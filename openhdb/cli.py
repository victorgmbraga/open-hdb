"""CLI USB independente: python -m openhdb --help."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import usb.core

from . import auth, client
from .usb import TransportError


def cmd_probe(args):
    from .usb import describe_devices
    for line in describe_devices():
        print(line)
    results = client.probe(timeout=args.auth_timeout, verbose=args.verbose,
                           force=args.force, kind=args.kind, serial=args.serial,
                           key_path=args.key)
    for res in results:
        print(f"{res.interface.label}: {res.banner or res.error}")
    return 0 if results and not (args.force and all(r.banner is None for r in results)) else 1


def _connect(args):
    return client.connect(verbose=args.verbose, serial=args.serial, kind=args.kind,
                          key_path=args.key, auth_timeout=args.auth_timeout)


def cmd_device(args):
    with _connect(args) as conn:
        hdb = client.Hdb(conn)
        if args.cmd == "banner":
            print("canal  :", conn.transport_kind.upper())
            print("banner :", hdb.banner())
            print("tipo   :", conn.kind)
            print("versao :", hex(conn.version))
            print("payload:", conn.max_payload)
            print("feats  :", ", ".join(hdb.features()) or "(nenhuma)")
        elif args.cmd == "shell":
            sys.stdout.buffer.write(hdb.shell(args.command, timeout=args.timeout))
        elif args.cmd == "push":
            hdb.push(Path(args.local), args.remote, timeout=args.timeout)
        elif args.cmd == "pull":
            hdb.pull(args.remote, Path(args.local), timeout=args.timeout)
        elif args.cmd == "install":
            print(hdb.install(Path(args.apk), timeout=args.timeout))
        elif args.cmd == "auth-info":
            # É um pedido de controle documentado no daemon, não um bypass.
            response = conn.hdb_auth_exchange(b"HDB AUTHENTICREQUSET", timeout=args.timeout)
            prefix = b"HDB AUTHENTICRES3000"
            if not response.startswith(prefix):
                raise TransportError(f"resposta de controle inesperada: {response[:80]!r}")
            ciphertext = bytes.fromhex(response[len(prefix):].decode())
            if len(ciphertext) != 256:
                raise TransportError("desafio RSA não tem 256 bytes")
            print("Autorização USB HDB: aceita")
            print("Controle de serviços: HDB AUTHENTICRES3000")
            print("Desafio RSA: 256 bytes (cifrado; não é o TOKEN USB)")
            print("A segunda autenticação Huawei ainda não está implementada.")
    return 0


def main(argv=None):
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("-s", "--serial", default=argparse.SUPPRESS,
                        help="seleciona o serial USB do tablet")
    common.add_argument("--kind", choices=("hdb", "adb", "auto"), default=argparse.SUPPRESS,
                        help="canal USB (padrão: hdb; ADB somente se solicitado)")
    common.add_argument("--key", type=Path, default=argparse.SUPPRESS,
                        help="chave RSA privada do host para autorização USB")
    common.add_argument("--auth-timeout", type=float, default=argparse.SUPPRESS,
                        help="prazo para aprovação manual (padrão: 60 segundos)")
    common.add_argument("--no-approve", action="store_true", default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)
    common.add_argument("--auto-approve", action="store_true", default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)
    ap = argparse.ArgumentParser(prog="openhdb", parents=[common],
                                 description="cliente USB HDB/ADB sem executável adb")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe", parents=[common], help="lista descritores (sem handshake)")
    p.add_argument("--force", action="store_true", help="também inicia CNXN/AUTH")
    p.set_defaults(func=cmd_probe)
    for name in ("banner", "shell", "push", "pull", "install", "auth-info"):
        p = sub.add_parser(name, parents=[common])
        p.add_argument("--timeout", type=float, default=120.0 if name in ("push", "pull", "install") else 20.0)
        p.set_defaults(func=cmd_device)
        if name == "shell":
            p.add_argument("command")
        elif name == "push":
            p.add_argument("local")
            p.add_argument("remote")
        elif name == "pull":
            p.add_argument("remote")
            p.add_argument("local")
        elif name == "install":
            p.add_argument("apk")
    args = ap.parse_args(argv)
    for attr, value in (("verbose", False), ("serial", None), ("kind", "hdb"),
                        ("key", None), ("auth_timeout", 60.0), ("auto_approve", False)):
        if not hasattr(args, attr):
            setattr(args, attr, value)
    if args.auto_approve:
        ap.error("--auto-approve removido: aprove manualmente; este cliente não chama ADB")
    if args.cmd == "auth-info" and args.kind != "hdb":
        ap.error("auth-info requer --kind hdb")
    if args.auth_timeout <= 0 or getattr(args, "timeout", 1) <= 0:
        ap.error("timeouts precisam ser positivos")
    try:
        return args.func(args)
    except (TransportError, auth.AuthError, usb.core.USBError, OSError, ValueError) as exc:
        print(f"openhdb: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
