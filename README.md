BinX —  Binary Analyzer Toolkit

BinX is a safe, static + benign runtime analysis tool for ELF binaries.
It is designed for educational and defensive research purposes only — it does not generate or send exploits.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()  

---

## ✨ Features
- 🛡 **Binary Protections Overview** → PIE, NX, RELRO, Canary, Arch
- 📏 **Buffer Overflow Analysis** → offset detection via cyclic patterns (pwntools)
- ⚙️ **Exploit Helper Data** → one_gadget offsets, libc symbols
- 📂 **Static Analysis** → sections, relocations, dependencies, unsafe funcs
- 🔎 **Heuristics** → format string suspects, stack frame size checks
- 📝 **Reporting** → Markdown + JSON export

---

## ⚙️ Installation

### Requirements
- Python **3.8+**
- [Pwntools](https://docs.pwntools.com/en/stable/) → `pip install pwntools`
- System tools: `file`, `nm`, `readelf`, `ldd`
- (Optional) [one_gadget](https://github.com/david942j/one_gadget) → `gem install one_gadget`

### Clone Repository
```bash
git clone https://github.com/Infin-Nine/BinX.git
cd BinX
python3 binx.py --binary ./vuln_binary [options]
```
OPTIONS
| Flag               | Description                            |
| ------------------ | -------------------------------------- |
| `--binary <path>`  | Path to ELF binary (required)          |
| `--libc <path>`    | Optional libc path                     |
| `--report <path>`  | Markdown output (default: `report.md`) |
| `--json <path>`    | JSON output                            |
| `--runtime-base`   | PIE base addr estimation               |
| `--one-gadget <N>` | Collect top-N one\_gadget offsets      |
| `--auto-offset`    | Auto buffer overflow offset detection  |

Example:-
 ~/tool/binx.py  --binary ret2csu --libc /lib/x86_64-linux-gnu/libc.so.6 --one-gadget 4 --auto-offset
 
<img width="1920" height="1080" alt="Screenshot_2025-08-19_01_57_02" src="https://github.com/user-attachments/assets/551771c1-7a0a-409c-a3a7-3fa903565a47" />

Report written to: /home/kali/binary/ctf/binx_report.md

<img width="1920" height="1080" alt="Screenshot_2025-08-19_01_59_42" src="https://github.com/user-attachments/assets/61e9cc7e-ef38-41cd-bf7f-8c4c382fed29" />

📄 report.md → Full Markdown analysis
📦 result.json → Machine-readable export




