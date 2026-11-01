#!/usr/bin/env python3
"""Desmonta funções do ``hdbd`` (ARM 32-bit, Thumb) anotando strings.

Uso:
    python tools/disasm.py hdbd _Z8hdb_authP7apacketP10atransport
    python tools/disasm.py hdbd --addr 0x47721

Requer ``capstone`` e ``pyelftools``. É a ferramenta usada para descobrir o
formato dos quadros ``HDB AUTHENTIC*`` (ver docs/PROTOCOL.md §3.1).
"""
from __future__ import annotations

import argparse
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile


class Elf:
    def __init__(self, path: str):
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.segments = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def offset_to_vaddr(self, off: int) -> int | None:
        for seg in self.segments:
            if seg["p_offset"] <= off < seg["p_offset"] + seg["p_filesz"]:
                return seg["p_vaddr"] + (off - seg["p_offset"])
        return None

    def read(self, vaddr: int, size: int) -> bytes:
        for seg in self.segments:
            if seg["p_vaddr"] <= vaddr < seg["p_vaddr"] + seg["p_filesz"]:
                start = seg["p_offset"] + (vaddr - seg["p_vaddr"])
                self.f.seek(start)
                return self.f.read(size)
        return b""

    def cstring(self, vaddr: int, limit: int = 120) -> str | None:
        raw = self.read(vaddr, limit)
        end = raw.find(b"\0")
        if end <= 0:
            return None
        try:
            text = raw[:end].decode()
        except UnicodeDecodeError:
            return None
        if all(32 <= ord(c) < 127 or c in "\n\t" for c in text):
            return text
        return None

    def symbols(self):
        symtab = self.elf.get_section_by_name(".symtab")
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]:
                yield sym.name, sym["st_value"]


def find_function(elf: Elf, needle: str):
    funcs = sorted(elf.symbols(), key=lambda kv: kv[1])
    starts = [addr for _, addr in funcs]
    for name, addr in funcs:
        if needle in name or f"{addr:#x}" == needle:
            idx = starts.index(addr)
            end = starts[idx + 1] if idx + 1 < len(starts) else addr + 0x400
            return name, addr & ~1, end & ~1
    return None


def annotate_literals(elf: Elf, insns) -> dict:
    """Mapeia a linha -> string lida do literal pool (ldr rX, [pc, #imm])."""
    notes = {}
    for ins in insns:
        if ins.mnemonic != "ldr" or len(ins.operands) != 2:
            continue
        mem = ins.operands[1]
        if mem.type != ARM_OP_MEM or mem.mem.base == 0:  # pc == 0? não; ver abaixo
            pass
        if mem.type != ARM_OP_MEM:
            continue
        # PC-relative: base é o registrador PC (ARM_REG_PC)
        if mem.mem.base != 15:  # ARM_REG_PC == 15
            continue
        target = (ins.address + 4) & ~3
        target += mem.mem.disp
        raw = elf.read(target, 4)
        if len(raw) < 4:
            continue
        ptr = struct.unpack("<I", raw)[0]
        text = elf.cstring(ptr)
        if text:
            notes[ins.address] = f'"{text[:70]}"'
    return notes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("symbol", nargs="?", help="nome (parcial) ou endereço 0x...")
    ap.add_argument("--addr", help="endereço alternativo")
    ap.add_argument("--count", type=int, default=400)
    args = ap.parse_args(argv)

    elf = Elf(args.binary)
    needle = args.addr or args.symbol
    if not needle:
        print("\n".join(f"{a:#010x} {n}" for n, a in sorted(elf.symbols(), key=lambda kv: kv[1])[:50]))
        return 1
    found = find_function(elf, needle)
    if not found:
        print(f"símbolo não encontrado: {needle}", file=sys.stderr)
        return 1
    name, start, end = found
    print(f"== {name} @ {start:#x}..{end:#x} ({(end-start)//2} instrs Thumb) ==")
    thumb = True  # símbolos ímpares já foram normalizados; hdbd é Thumb
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_ARM if not thumb else CS_MODE_THUMB)
    md.detail = True
    code = elf.read(start, end - start or 0x200)
    insns = list(md.disasm(code, start))
    notes = annotate_literals(elf, insns)
    for ins in insns[: args.count]:
        note = f"   ; {notes[ins.address]}" if ins.address in notes else ""
        print(f"  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
