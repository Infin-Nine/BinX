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
git clone https://github.com/your-username/BinX.git
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
