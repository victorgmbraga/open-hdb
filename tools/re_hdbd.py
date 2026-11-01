#!/usr/bin/env python3
"""Engenharia reversa do hdbd: extrai strings, símbolos e caminhos de fonte.

Uso:
    python tools/re_hdbd.py /caminho/hdbd
    adb pull /system/bin/hdbd hdbd && python tools/re_hdbd.py hdbd

O binário do KOB2-W09 não é stripped, então os símbolos revelam a estrutura
(serviços, auth, transporte) sem precisar de desassemblador.
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

TOKENS = {
    "auth": r"auth|token|nonce|challenge|rsa",
    "transport": r"transport|usb|ffs|endpoint|bulk",
    "servicos": r"shell|sync|jdwp|services",
    "chaves": r"keys|hdb_keys|adb_keys",
    "install": r"pm install|hwhdb|install",
}


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def main(path: str) -> int:
    p = Path(path)
    if not p.exists():
        print(f"não encontrei {p}", file=sys.stderr)
        return 1
    print(f"== {p} ({p.stat().st_size} bytes) ==")
    print(sh("file", str(p)).strip())

    strings = sh("strings", "-n", "4", str(p)).splitlines()
    print(f"\n== {len(strings)} strings ==")
    for name, pattern in TOKENS.items():
        hits = sorted({s for s in strings if re.search(pattern, s, re.I)})
        print(f"\n-- {name} ({len(hits)}) --")
        for h in hits[:12]:
            print("   ", h[:110])

    src = sorted({s for s in strings if "hwusb/hdb/" in s})
    if src:
        print(f"\n== caminhos de fonte ({len(src)}) ==")
        for s in src:
            print("   ", s)

    syms = sh("nm", str(p))
    if syms:
        interesting = [l for l in syms.splitlines() if re.search(r"hdb_|_hdb|hdbd_", l)]
        print(f"\n== símbolos com 'hdb' ({len(interesting)}) ==")
        for l in interesting:
            print("   ", l)

    # distribuição de extensões/nomes ajuda a confirmar o fork do adb
    names = Counter(re.sub(r".*\.", "", l.split()[-1]) for l in syms.splitlines() if l.strip())
    print("\n== sufixos de símbolos mais comuns ==")
    for name, n in names.most_common(8):
        print(f"   {name:20s} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "hdbd"))
