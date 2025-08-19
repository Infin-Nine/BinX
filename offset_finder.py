#!/usr/bin/env python3
from pwn import *
import argparse

def find_buffer_overflow_offset(binary):
    try:
        elf = context.binary = ELF(binary)
        context.terminal = ["tmux", "splitw", "-h"]

        pattern = cyclic(300)
        p = process(binary)
        p.sendline(pattern)
        p.wait()  # crash का wait

        core = p.corefile
        crash_value = core.read(core.rsp, 8)
        crash_value = u64(crash_value)

        offset = cyclic_find(crash_value)
        print(f"[+] Buffer Overflow Offset Found: {offset}")
        return offset
    except Exception as e:
        print(f"Could not determine offset ({str(e)})")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="Target binary")
    args = parser.parse_args()
    find_buffer_overflow_offset(args.binary)
