#!/usr/bin/env python3
"""Acha quem referencia uma string no binário (xref por literal pool / word).

Uso:  python tools/xref.py hdbd "HDB AUTHENTICPCIDENT"
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile


class Elf:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.f = open(self.path, "rb")
        self.elf = ELFFile(self.f)
        self.segs = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        self.data = self.path.read_bytes()

    def v2o(self, v):
        for s in self.segs:
            if s["p_vaddr"] <= v < s["p_vaddr"] + s["p_filesz"]:
                return s["p_offset"] + (v - s["p_vaddr"])
        return None

    def o2v(self, o):
        for s in self.segs:
            if s["p_offset"] <= o < s["p_offset"] + s["p_filesz"]:
                return s["p_vaddr"] + (o - s["p_offset"])
        return None

    def read(self, v, n):
        o = self.v2o(v)
        return self.data[o:o + n] if o is not None else b""

    def strings(self, needle):
        out = []
        start = 0
        while True:
            i = self.data.find(needle.encode(), start)
            if i < 0:
                break
            out.append((self.o2v(i), self.data[i:i + 80].split(b"\0")[0].decode(errors="replace")))
            start = i + 1
        return out

    def funcs(self):
        sym = self.elf.get_section_by_name(".symtab")
        return sorted(
            ((s["st_value"] & ~1, s.name) for s in sym.iter_symbols()
             if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]),
        )


def main(path, needle):
    elf = Elf(Path(path))
    funcs = elf.funcs()
    addrs = [a for a, _ in funcs]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False

    for vaddr, text in elf.strings(needle)[:4]:
        print(f'\n== "{text}" @ {vaddr:#x} ==')
        pat = struct.pack("<I", vaddr)
        idx = 0
        hits = 0
        while hits < 6:
            i = elf.data.find(pat, idx)
            if i < 0:
                break
            idx = i + 1
            pool = elf.o2v(i)
            if pool is None:
                continue
            # procura para trás uma instrução ldr rX,[pc,#d] que aponte para pool
            for back in range(2, 400, 2):
                cand = pool - back
                o = elf.v2o(cand)
                if o is None:
                    continue
                ins = next(md.disasm(elf.data[o:o + 4], cand), None)
                if ins and ins.mnemonic.startswith("ldr") and "[pc," in ins.op_str:
                    try:
                        disp = int(ins.op_str.split("#")[1].split("]")[0], 0)
                    except Exception:
                        continue
                    if ((cand + 4) & ~3) + disp == pool:
                        fn = max((a for a in addrs if a <= cand), default=None)
                        name = dict(funcs).get(fn, "?")
                        print(f"  ref em {cand:#x} (pool {pool:#x})  ->  {name}")
                        hits += 1
                        break


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
