#!/usr/bin/env python3
"""Lista os pontos que chamam (bl/blx) um endereço, com a função dona.

Uso: python tools/callers.py hdbd 0x5a4e4
"""
from __future__ import annotations

import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile


def main(path, target_s):
    target = int(target_s, 0)
    data = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    syms = []
    sym = elf.get_section_by_name(".symtab")
    for s in sym.iter_symbols():
        if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
            syms.append((s["st_value"] & ~1, s.name))
    syms.sort()
    addrs = [a for a, _ in syms]
    name_of = dict(syms)

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD" or not (seg["p_flags"] & 0x1):
            continue
        code = data[seg["p_offset"]:seg["p_offset"] + seg["p_filesz"]]
        for ins in md.disasm(code, seg["p_vaddr"]):
            if ins.mnemonic not in ("bl", "blx") or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != ARM_OP_IMM or op.imm != target:
                continue
            fn = max((a for a in addrs if a <= ins.address), default=None)
            print(f"  chamada em {ins.address:#x}  em  {name_of.get(fn, hex(fn or 0))}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
