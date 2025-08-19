#!/usr/bin/env python3
"""
BinX — Binary Analyzer Toolkit 
- Base address estimation (static + optional benign runtime sampling)
- Automatic buffer-overflow offset finder using cyclic crash analysis (pwntools)
- one_gadget offsets & constraints (if libc provided and one_gadget present)
- Libc helper offsets (system, execve, dup2, environ, __libc_start_main, '/bin/sh')
- Sections/Relocs/Deps (readelf + ldd) summaries
- Severity scorecard + clean Markdown report
- Optional JSON export for automation
- External offset_finder.py invocation + parsed result in report/JSON

This tool performs static analysis and benign runtime sampling only.
It does NOT craft or send exploits.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import textwrap
from datetime import datetime

try:
    from pwn import context, ELF as PwnELF, ROP, process, cyclic, cyclic_find, u64
except Exception as e:
    raise SystemExit("This tool requires 'pwntools'. Install with: pip install pwntools\nDetails: " + str(e))

# --------------------------- helpers ---------------------------

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out.strip()
    except Exception as e:
        return f"[cmd error] {e}"


def safe_file_output(path):
    return run_cmd(["file", "-b", path])


def safe_nm_output(path):
    return run_cmd(["nm", "-n", path])


def safe_readelf_S(path):
    return run_cmd(["readelf", "-S", path])


def safe_readelf_r(path):
    return run_cmd(["readelf", "-r", path])


def safe_ldd(path):
    return run_cmd(["ldd", path])


def human_readable_bytes(n):
    try:
        return f"{n} bytes"
    except Exception:
        return str(n)


# ---------------------- analysis primitives --------------------

def analyze_stack_frame_sizes(elf_obj, max_funcs=400):
    """Heuristic: find `sub rsp, imm` near function starts to estimate local buffer size."""
    res = []
    try:
        for idx, (name, addr) in enumerate(sorted(elf_obj.symbols.items(), key=lambda kv: kv[1])):
            if idx > max_funcs:
                break
            try:
                dis = elf_obj.disasm(addr, 64)
                for line in dis.splitlines():
                    line = line.strip()
                    if line.startswith("sub") and "rsp" in line and ("0x" in line or "," in line):
                        parts = line.replace(',', ' ').split()
                        imm = None
                        for tok in parts:
                            if tok.startswith("0x"):
                                try:
                                    imm = int(tok, 16)
                                    break
                                except Exception:
                                    pass
                        if imm and imm > 0:
                            res.append((name, hex(addr), imm))
                            raise StopIteration
            except StopIteration:
                continue
            except Exception:
                continue
    except Exception:
        pass
    return res


# ----------------- external offset_finder integration -----------

def run_offset_finder(binary):
    """
    Call external offset_finder.py and return:
      - raw_output (str)
      - parsed_offset (int or None)
    """
    try:
        raw = subprocess.check_output(
            ["python3", "offset_finder.py", "--binary", binary],
            text=True,
            stderr=subprocess.STDOUT
        ).strip()
    except FileNotFoundError:
        return "offset_finder.py not found in current directory.", None
    except subprocess.CalledProcessError as e:
        raw = f"[offset_finder error] {e.output.strip() if e.output else str(e)}"

    # Parse common patterns like "[+] Buffer Overflow Offset Found: 72"
    parsed = None
    try:
        m = re.search(r"(?:Offset\s*(?:Found)?|Buffer\s*Overflow\s*Offset(?:\s*Found)?)\D+(\d+)", raw, re.IGNORECASE)
        if m:
            parsed = int(m.group(1))
    except Exception:
        parsed = None

    return raw, parsed


def find_common_ctf_symbols(elf_obj, names=None):
    if names is None:
        names = [
            "win", "flag", "get_flag", "vuln", "vulnerable", "useful", "usefulfunction",
            "admin", "secret", "backdoor", "exploitme", "guest"
        ]
    found = {}
    for s, addr in elf_obj.symbols.items():
        for name in names:
            if s.lower() == name.lower() or name.lower() in s.lower():
                found[s] = hex(addr)
    return found


def estimate_buffer_overflow_offsets(stack_allocations):
    estimates = []
    for name, addr_hex, alloc in stack_allocations:
        est = alloc + 8  # saved rbp
        estimates.append((name, addr_hex, alloc, est))
    return estimates


def detect_unsafe_functions(elf_obj):
    unsafe = ["gets", "strcpy", "strncpy", "sprintf", "vsprintf", "scanf", "sscanf", "strcat", "stpcpy"]
    found = []
    try:
        for sym in elf_obj.got.keys():
            if sym in unsafe:
                found.append(sym + " (imported via GOT)")
    except Exception:
        pass
    try:
        for s in elf_obj.symbols.keys():
            if s in unsafe:
                found.append(s + " (internal)")
    except Exception:
        pass
    return sorted(set(found))


def detect_format_string_suspects(elf_obj):
    suspects = []
    if "printf" in getattr(elf_obj, 'plt', {}):
        suspects.append("printf@plt present")
    readers = ["fgets", "gets", "scanf", "fscanf", "read"]
    for r in readers:
        if r in getattr(elf_obj, 'plt', {}) or r in getattr(elf_obj, 'got', {}) or r in getattr(elf_obj, 'symbols', {}):
            suspects.append(f"{r} present (input-reader)")
    percent_found = False
    try:
        rodata = b""
        for sec in getattr(elf_obj, 'sections', []):
            if sec in (".rodata", ".data", ".rdata"):
                try:
                    rodata += elf_obj.section_bytes(sec)
                except Exception:
                    pass
        if b"%" in rodata:
            percent_found = True
    except Exception:
        percent_found = False
    if percent_found:
        suspects.append("Format-like strings ('%') present in rodata - manual audit recommended")
    return sorted(set(suspects))


# ---------------------- base address utils ---------------------

def estimate_base_address(elf_obj):
    if not elf_obj.pie:
        return {"mode": "static", "base": "0x400000", "note": "Non-PIE → fixed base on Linux amd64"}
    return {"mode": "dynamic", "base": None, "note": "PIE enabled → runtime randomized base"}


def runtime_base_address(binary_path):
    """Benign run → read /proc/<pid>/maps → first r-xp mapping for this binary."""
    try:
        p = subprocess.Popen([binary_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = p.pid
        maps = open(f"/proc/{pid}/maps", "r").read()
        # terminate quickly to avoid hanging programs
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=0.2)
        except Exception:
            p.kill()
        for line in maps.splitlines():
            if "r-xp" in line and os.path.basename(binary_path) in line:
                base = int(line.split("-")[0], 16)
                return hex(base)
        return None
    except Exception:
        return None


# --------------- libc helpers & one_gadget offsets --------------

def libc_helper_offsets(libc_path):
    if not libc_path or not os.path.exists(libc_path):
        return {}
    res = {"symbols": {}, "binsh_offset": None}
    nm = run_cmd(["nm", "-D", libc_path])
    if "[cmd error]" not in nm:
        for sym in ["system", "execve", "dup2", "environ", "__libc_start_main"]:
            m = re.search(rf"([0-9a-fA-F]+)\s+[A-Za-z]\s+{sym}$", nm, re.MULTILINE)
            if m:
                res["symbols"][sym] = int(m.group(1), 16)
    s = run_cmd(["strings", "-a", "-t", "x", libc_path])
    if "[cmd error]" not in s:
        m = re.search(r"^([0-9a-fA-F]+)\s+/bin/sh$", s, re.MULTILINE)
        if m:
            res["binsh_offset"] = int(m.group(1), 16)
    return res


def one_gadget_offsets(libc_path, topk=5):
    if not libc_path or not os.path.exists(libc_path):
        return {"available": False, "gadgets": [], "note": "libc not provided"}
    out = run_cmd(["one_gadget", libc_path])
    if out.startswith("[cmd error]"):
        return {"available": False, "gadgets": [], "note": "one_gadget not found in PATH (gem install one_gadget)"}
    gadgets = []
    for line in out.splitlines():
        m = re.match(r"\s*0x([0-9a-fA-F]+)\s+(.+)$", line)
        if m:
            off = int(m.group(1), 16)
            gadgets.append({"offset": off, "desc": m.group(2).strip(), "raw": line.strip()})
        elif line.strip().startswith("constraints:") and gadgets:
            gadgets[-1]["constraints"] = line.strip()
    gadgets = gadgets[:max(1, int(topk))]
    return {"available": True, "gadgets": gadgets, "note": None}


# ----------------- automatic offset finder (internal) -----------

def find_buffer_overflow_offset(binary):
    """Run target with a cyclic pattern, read crash bytes at RSP, and compute offset.
    Returns int offset, or None if undetermined.
    """
    try:
        elf = context.binary = PwnELF(binary)  # FIX: use PwnELF
        context.terminal = ["tmux", "splitw", "-h"]

        pattern = cyclic(300)

        p = process(binary)
        p.sendline(pattern)
        p.wait()  # wait for crash

        core = p.corefile
        crash_value = core.read(core.rsp, 8)
        crash_value = u64(crash_value)

        offset = cyclic_find(crash_value)
        print(f"[+] Buffer Overflow Offset Found: {offset}")
        return offset
    except Exception as e:
        return None  # keep it quiet; details go in external_raw if needed


# --------------------------- report ----------------------------

def severity_score(prot, unsafe_funcs, fmt_suspects, stack_allocs):
    score = 0
    if prot.get("PIE") == "Disabled":
        score += 1
    if prot.get("NX") == "Disabled":
        score += 3
    if prot.get("Canary") == "Absent":
        score += 2
    if "Partial" in str(prot.get("RELRO", "")) or "None" in str(prot.get("RELRO", "")):
        score += 1
    score += min(3, len(unsafe_funcs))
    if fmt_suspects:
        score += 1
    if any(alloc > 128 for _, _, alloc in stack_allocs):
        score += 1
    return min(10, score)


def render_report(args, elf_obj, prot, got, plt, syms, gadgets, binsh,
                  file_out, nm_out, ctf_symbols, stack_allocs, estimates,
                  unsafe_funcs, fmt_suspects, base_info, runtime_base,
                  secinfo, relocinfo, deps, libc_info, og_info,
                  bof_offset_internal, ext_raw, ext_offset_num):
    title = f"# Binx Report \n\n"
    meta = f"- Generated: {datetime.now().isoformat(timespec='seconds')}\n- Binary: `{args.binary}`\n- Libc: `{args.libc or 'Not provided'}`\n\n"

    sec = "## Protections\n" + "\n".join([f"- **{k}**: {v}" for k, v in prot.items()]) + "\n\n"

    score = severity_score(prot, unsafe_funcs, fmt_suspects, stack_allocs)
    badge = "🟢 Low" if score <= 3 else ("🟠 Medium" if score <= 6 else "🔴 High")
    scorecard = f"## Binary Security Scorecard\n- Severity: **{badge} ({score}/10)**\n\n"

    base_sec = "## Base Address Estimation\n"
    base_sec += f"- Mode: {base_info['mode']}\n"
    base_sec += f"- Static base hint: {base_info['base'] if base_info['base'] else 'N/A'}\n"
    base_sec += f"- Note: {base_info['note']}\n"
    if args.runtime_base and base_info['mode'] == 'dynamic':
        base_sec += f"- Benign runtime base (example): {runtime_base or 'Not determined'}\n\n"
    else:
        base_sec += "\n"

    # NEW: buffer overflow offset (internal + external)
    bof_sec = "## Buffer Overflow Offset (Cyclic Method)\n"
    if args.auto_offset:
        if bof_offset_internal is not None:
            bof_sec += f"- Internal method: **{bof_offset_internal}** bytes\n"
        else:
            bof_sec += "- Internal method: could not determine offset.\n"
        if ext_raw:
            if ext_offset_num is not None:
                bof_sec += f"- External offset_finder.py: **{ext_offset_num}** bytes\n"
            else:
                bof_sec += "- External offset_finder.py: **no numeric offset parsed** (raw output below)\n"
            bof_sec += f"\n<details><summary>External tool raw output</summary>\n\n```\n{ext_raw}\n```\n</details>\n\n"
        else:
            bof_sec += "- External offset_finder.py: not executed.\n\n"
    else:
        bof_sec += "- Auto-offset disabled (use `--auto-offset`).\n\n"

    secinfo_block = "## Sections & Segments (readelf -S)\n" + (f"```\n{secinfo}\n```\n\n" if secinfo else "- <none>\n\n")
    reloc_block = "## Relocations (readelf -r)\n" + (f"```\n{relocinfo}\n```\n\n" if relocinfo else "- <none>\n\n")
    deps_block = "## Dynamic Dependencies (ldd)\n" + (f"```\n{deps}\n```\n\n" if deps else "- <none>\n\n")

    syms_block = "## Symbols (sample)\n"
    if syms:
        syms_block += "\n".join([f"- `{k}` @ {v}" for k, v in syms]) + "\n\n"
    else:
        syms_block += "- <none>\n\n"

    got_block = "## GOT / PLT\n"
    if got:
        got_block += "### GOT\n" + "\n".join([f"- {k}: {v}" for k, v in got]) + "\n"
    else:
        got_block += "### GOT\n- <none>\n"
    if plt:
        got_block += "\n### PLT\n" + "\n".join([f"- {k}: {v}" for k, v in plt]) + "\n\n"
    else:
        got_block += "\n### PLT\n- <none>\n\n"

    gadgets_block = "## Candidate Gadgets (addresses if found)\n" + "\n".join([f"- {k}: {v}" for k, v in gadgets.items()]) + "\n\n"

    strings_block = "## Helpful Strings\n" + f"- `/bin/sh` in binary: {binsh if binsh else 'Not found'}\n\n"

    file_nm_block = "## System Command Outputs\n"
    file_nm_block += f"### file\n```\n{file_out}\n```\n"
    file_nm_block += f"### nm -n (symbols in address order, truncated)\n```\n{nm_out[:2000] + ('\\n...truncated...' if len(nm_out)>2000 else '')}\n```\n\n"

    ctf_block = "## Common CTF/Sensitive Symbols Found\n"
    if ctf_symbols:
        ctf_block += "\n".join([f"- `{k}` @ {v}" for k, v in ctf_symbols.items()]) + "\n\n"
    else:
        ctf_block += "- None of common CTF symbol names found (search space: win, flag, vuln, admin, secret, UsefulFunction, ...)\n\n"

    stack_block = "## Heuristic Stack Frame Allocations (sample)\n"
    if stack_allocs:
        stack_block += "\n".join([f"- {name} @ {addr}: alloc={human_readable_bytes(alloc)}" for name, addr, alloc in stack_allocs]) + "\n\n"
    else:
        stack_block += "- No obvious 'sub rsp, imm' patterns found in first functions scanned.\n\n"

    estimates_block = "## Estimated Buffer-Overflow Offsets (heuristic)\n"
    if estimates:
        estimates_block += "\n".join([f"- {name} @ {addr}: alloc={human_readable_bytes(alloc)} -> estimated offset to RIP ≈ {est} bytes (alloc + saved rbp(8))" for name, addr, alloc, est in estimates]) + "\n\n"
    else:
        estimates_block += "- No estimates available (no stack allocations found).\n\n"

    vuln_block = "## Vulnerability Checklist & Hints\n"
    vuln_block += "- Unsafe libc functions found: " + (", ".join(unsafe_funcs) if unsafe_funcs else "None detected") + "\n"
    vuln_block += "- Format-string suspects: " + (", ".join(fmt_suspects) if fmt_suspects else "None detected") + "\n"
    vuln_block += "- If you see `gets`, `strcpy`, or `scanf` without length checks, treat as high-priority manual review targets.\n\n"

    # libc helpers & one_gadget
    og_block = "## Exploit Building Helpers (Offsets Only)\n"
    if libc_info:
        if libc_info.get("symbols"):
            og_block += "### libc symbol offsets (from libc base)\n" + "\n".join(
                [f"- {k}: 0x{v:x}" for k, v in libc_info["symbols"].items()]
            ) + "\n"
        else:
            og_block += "- libc symbol offsets: <none>\n"
        og_block += f"- '/bin/sh' offset: {('0x%x' % libc_info['binsh_offset']) if libc_info.get('binsh_offset') else 'Not found'}\n\n"
    else:
        og_block += "- libc not provided → skip libc helpers\n\n"

    if og_info and og_info.get("available"):
        og_block += "### one_gadget offsets (from libc base)\n"
        for g in og_info["gadgets"]:
            og_block += f"- 0x{g['offset']:x}: {g.get('desc','')}\n"
            if g.get("constraints"):
                og_block += f"    - {g['constraints']}\n"
        og_block += "\n> Usage (PIE note): runtime_addr = libc_base + gadget_offset\n\n"
    else:
        og_block += f"- one_gadget: {og_info.get('note') if og_info else 'not attempted'}\n\n"

    quick_checks = "## Quick Checks & Tips\n" + textwrap.dedent("""
    - Offsets and heuristics must be validated in a controlled lab (cyclic patterns & core analysis) in an isolated environment.
    - Use the Scorecard to decide leak-first vs direct overwrite strategies based on PIE/Canary/NX.
    - For format-strings: look for printf-like calls where input flows directly into the format argument (manual review needed).
    - This tool intentionally avoids sending payloads or automating exploitation.
    """) + "\n"

    plan = textwrap.dedent("""
    ## Hypothetical Next Steps (Lab, Manual)
    1. Leak addresses (puts, __libc_start_main, stack pointer) to derive bases when PIE/ASLR are enabled.
    2. Compute runtime addresses using: runtime = base + offset (binary/ld/libc as applicable).
    3. Validate one_gadget constraints at runtime (e.g., rdx==0, rsp+offset writable, env==NULL).
    4. Confirm exact overflow offset via cyclic pattern & crash analysis.
    """)

    footer = textwrap.dedent("""
    ---
    **Ethical Use Only**: This report is for education and defensive research on intentionally vulnerable targets you own or have permission to test. It does **not** contain working exploit code and will not attempt to exploit a target.
    """)

    return (
        title + meta + scorecard + sec + base_sec + bof_sec + secinfo_block + reloc_block + deps_block +
        syms_block + got_block + gadgets_block + strings_block + file_nm_block + ctf_block +
        stack_block + estimates_block + vuln_block + og_block + quick_checks + plan + "\n" + footer
    )


# ----------------------------- main ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Binx analyzer toolkit.")
    parser.add_argument("--binary", required=True, help="Path to ELF binary")
    parser.add_argument("--libc", default=None, help="Optional path to matching libc for reference only")
    parser.add_argument("--report", default="./binx_report.md", help="Markdown report path (default: ./binx_report.md)")
    parser.add_argument("--json", default=None, help="Optional JSON export path")
    parser.add_argument("--runtime-base", action="store_true", help="Attempt benign run to sample runtime base address (PIE)")
    parser.add_argument("--one-gadget", type=int, default=5, help="Collect top-K one_gadget offsets if libc provided (default: 5)")
    parser.add_argument("--auto-offset", action="store_true", help="Attempt automatic buffer overflow offset detection via cyclic crash (internal + external)")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        raise SystemExit(f"Binary not found: {args.binary}")

    # pwntools ELF for analysis
    context.clear(arch="amd64")
    elf_obj = PwnELF(args.binary)

    prot = {
        "Arch": f"{elf_obj.arch} {elf_obj.bits}-bit",
        "Endianness": elf_obj.endian,
        "PIE": "Enabled" if elf_obj.pie else "Disabled",
        "NX": "Enabled" if elf_obj.nx else "Disabled",
        "RELRO": elf_obj.relro if isinstance(elf_obj.relro, str) else str(elf_obj.relro),
        "Canary": "Present" if elf_obj.canary else "Absent",
    }

    syms = [(k, hex(v)) for k, v in sorted(elf_obj.symbols.items(), key=lambda kv: kv[1])][:500]
    got = [(k, hex(v)) for k, v in getattr(elf_obj, 'got', {}).items()]
    plt = [(k, hex(v)) for k, v in getattr(elf_obj, 'plt', {}).items()]

    # ROP gadgets (basic)
    gadgets = {}
    try:
        rop = ROP(elf_obj)
        def hg(x):
            try:
                g = rop.find_gadget(x)
                return hex(g.address) if g else None
            except Exception:
                return None
        gadgets = {
            "ret": hg(['ret']),
            "pop_rdi_ret": hg(['pop rdi','ret']),
            "pop_rsi_ret": hg(['pop rsi','ret']),
            "pop_rdx_ret": hg(['pop rdx','ret']),
            "pop_rax_ret": hg(['pop rax','ret']),
            "syscall_ret": hg(['syscall','ret']),
            "leave_ret": hg(['leave','ret']),
            "jmp_rsp": hg(['jmp rsp'])
        }
    except Exception:
        pass

    # automatic buffer overflow offsets (internal + external)
    bof_offset_internal = find_buffer_overflow_offset(args.binary) if args.auto_offset else None
    ext_raw = None
    ext_offset_num = None
    if args.auto_offset:
        ext_raw, ext_offset_num = run_offset_finder(args.binary)

    # system tools
    file_out = safe_file_output(args.binary)
    nm_out = safe_nm_output(args.binary)
    secinfo = safe_readelf_S(args.binary)
    relocinfo = safe_readelf_r(args.binary)
    deps = safe_ldd(args.binary)

    # analyses
    ctf_symbols = find_common_ctf_symbols(elf_obj)
    stack_allocs = analyze_stack_frame_sizes(elf_obj, max_funcs=400)
    estimates = estimate_buffer_overflow_offsets(stack_allocs)
    unsafe_funcs = detect_unsafe_functions(elf_obj)
    fmt_suspects = detect_format_string_suspects(elf_obj)

    # strings
    try:
        binsh = hex(next(elf_obj.search(b"/bin/sh")))
    except Exception:
        binsh = None

    # base address info
    base_info = estimate_base_address(elf_obj)
    runtime_base = runtime_base_address(args.binary) if args.runtime_base and elf_obj.pie else None

    # libc helpers + one_gadget
    libc_info = libc_helper_offsets(args.libc) if args.libc else {}
    og_info = one_gadget_offsets(args.libc, topk=args.one_gadget) if args.libc else {"available": False, "gadgets": [], "note": "libc not provided"}

    # render
    report = render_report(
        args, elf_obj, prot, got, plt, syms, gadgets, binsh,
        file_out, nm_out, ctf_symbols, stack_allocs, estimates,
        unsafe_funcs, fmt_suspects, base_info, runtime_base,
        secinfo, relocinfo, deps, libc_info, og_info,
        bof_offset_internal, ext_raw, ext_offset_num
    )

    # write report
    os.makedirs(os.path.dirname(os.path.abspath(args.report)) or ".", exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report)

    # optional JSON export (automation)
    if args.json:
        payload = {
            "meta": {"generated": datetime.now().isoformat(timespec='seconds'), "binary": args.binary, "libc": args.libc},
            "protections": prot,
            "gadgets": gadgets,
            "symbols": syms,
            "got": got,
            "plt": plt,
            "ctf_symbols": ctf_symbols,
            "stack_allocs": stack_allocs,
            "overflow_estimates": estimates,
            "unsafe_funcs": unsafe_funcs,
            "fmt_suspects": fmt_suspects,
            "strings": {"binsh": binsh},
            "sections": secinfo,
            "relocs": relocinfo,
            "deps": deps,
            "base_info": base_info,
            "runtime_base": runtime_base,
            "libc_info": libc_info,
            "one_gadget": og_info,
            "bof_offset_internal": bof_offset_internal,
            "external_offset_finder": {
                "raw_output": ext_raw,
                "parsed_offset": ext_offset_num
            } if args.auto_offset else None,
        }
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(payload, jf, indent=2)

    # concise CLI line(s)
    if args.auto_offset:
        if bof_offset_internal is not None:
            print(f"[+] Buffer Overflow Offset (internal): {bof_offset_internal}")
        if ext_offset_num is not None:
            print(f"[+] Buffer Overflow Offset (external): {ext_offset_num}")
        if (bof_offset_internal is None) and (ext_offset_num is None):
            print("[-] No buffer overflow offset determined by internal or external methods.")

    print(f"Report written to: {os.path.abspath(args.report)}")
    if args.json:
        print(f"JSON written to: {os.path.abspath(args.json)}")


if __name__ == "__main__":
    main()
