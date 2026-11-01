#!/usr/bin/env python3
"""Lista chamadas (bl/blx) a um endereço, varrendo instruções alinhadas.

A desmontagem linear desincroniza em binários grandes; aqui cada offset de 2
bytes é decodificado isoladamente, o que acha chamadas dentro de funções que a
linear perde.

Uso: python tools/callers.py hdbd 0x4e8c8 [0x50658 ...]
"""
from __future__ import annotations

import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile


def main(path, *targets):
    tgt = {int(t, 0): t for t in targets}
    data = open(path, "rb").read()
    elf = ELFFile(open(path, "rb"))
    syms = []
    for s in elf.get_section_by_name(".symtab").iter_symbols():
        if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
            syms.append((s["st_value"] & ~1, s.name))
    syms.sort()
    addrs = [a for a, _ in syms]
    names = dict(syms)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    seen = set()
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD" or not (seg["p_flags"] & 0x1):
            continue
        base, code = seg["p_vaddr"], data[seg["p_offset"]:seg["p_offset"] + seg["p_filesz"]]
        for off in range(0, len(code) - 4, 2):
            for ins in md.disasm(code[off:off + 4], base + off):
                if ins.mnemonic not in ("bl", "blx") or not ins.operands:
                    continue
                op = ins.operands[0]
                if op.type != ARM_OP_IMM or op.imm not in tgt:
                    continue
                key = (ins.address, op.imm)
                if key in seen:
                    continue
                seen.add(key)
                fn = max((a for a in addrs if a <= ins.address), default=None)
                print(f"  {tgt[op.imm]}: chamada em {ins.address:#x} em {names.get(fn, hex(fn or 0))}")
            # evita reprocessar o segundo halfword de uma instrução ja decodificada
            if code[off + 1] & 0xF8 in (0xF0, 0xF8):
                continue


if __name__ == "__main__":
    main(sys.argv[1], *sys.argv[2:])
