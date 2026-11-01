#!/usr/bin/env python3
"""Compatibilidade: substitui o antigo fuzzer por um diagnóstico HDB conhecido.

As hipóteses de CRC32/prefixos e texto cru foram superadas. Não repetir essas
sondagens: podiam provocar erros USB/re-enumeração. Consulte docs/PROTOCOL.md.
Execute após `pip install -e .`.
"""
from check_hdb_independent import main

if __name__ == "__main__":
    raise SystemExit(main())
