"""CLI: python -m openhdb {probe,banner,shell,install}."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import client


def cmd_probe(args) -> int:
    from .usb import describe_devices

    lines = describe_devices()
    if not lines:
        print("nenhum dispositivo Huawei/MediaTek USB encontrado")
        return 1
    print("interfaces USB:")
    for line in lines:
        print("  " + line)
    print("\nsondando banner:")
    results = client.probe(timeout=args.timeout, verbose=args.verbose, force=args.force)
    if not results:
        print("  nenhuma interface ADB/HDB (ff/42/01) disponível")
        return 1
    for res in results:
        if res.banner:
            print(f"  {res.interface.label}: BANNER {res.banner!r}")
            print(f"      tipo={res.kind} features={res.features}")
        else:
            print(f"  {res.interface.label}: {res.error}")
    return 0


def cmd_shell(args) -> int:
    with client.connect(verbose=args.verbose) as conn:
        hdb = client.Hdb(conn)
        sys.stdout.write(hdb.shell(args.command).decode(errors="replace"))
    return 0


def cmd_banner(args) -> int:
    with client.connect(verbose=args.verbose) as conn:
        hdb = client.Hdb(conn)
        print("banner :", hdb.banner())
        print("tipo   :", conn.kind)
        print("versao :", hex(conn.version))
        print("payload:", conn.max_payload)
        print("feats  :", ", ".join(hdb.features()) or "(nenhuma)")
    return 0


def cmd_install(args) -> int:
    with client.connect(verbose=args.verbose) as conn:
        hdb = client.Hdb(conn)
        print(hdb.install(Path(args.apk)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="openhdb", description="cliente HDB aberto")
    ap.add_argument("-v", "--verbose", action="store_true", help="mostra o tráfego de pacotes")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="lista interfaces e lê o banner")
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--force", action="store_true", help="escreve CNXN também na interface HDB (pode resetar o USB)")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("banner", help="mostra banner/versão/features")
    p.set_defaults(func=cmd_banner)

    p = sub.add_parser("shell", help="executa um comando no dispositivo")
    p.add_argument("command")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("install", help="instala um APK pelo caminho do HDB")
    p.add_argument("apk")
    p.set_defaults(func=cmd_install)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
