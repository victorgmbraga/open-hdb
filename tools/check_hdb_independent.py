#!/usr/bin/env python3
"""Teste opt-in no tablet: ff/48 exclusivamente, sem adb disponível.

Uso após `pip install -e .`: python tools/check_hdb_independent.py
Aprovação da chave é manual. Envia apenas `shell:id` e o pedido de desafio HDB;
não instala APKs, apaga chaves, troca configurações nem acessa a interface ADB.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from openhdb import client
from openhdb.transport import ServiceAuthRequired
from openhdb.usb import HDB_SUBCLASS


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--serial")
    ap.add_argument("--auth-timeout", type=float, default=60.0)
    args = ap.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        ap.error("OpenSSL não encontrado")
    real_run = subprocess.run
    old_path = os.environ.get("PATH")
    calls = []

    def openssl_only(cmd, *a, **kw):
        if not isinstance(cmd, list) or cmd[0] != "openssl" or kw.get("shell"):
            raise RuntimeError("este teste permite somente subprocessos OpenSSL")
        calls.append(cmd[0])
        return real_run(cmd, *a, **kw)

    try:
        with tempfile.TemporaryDirectory(prefix="openhdb-no-adb-") as directory:
            Path(directory, "openssl").symlink_to(openssl)
            os.environ["PATH"] = directory
            subprocess.run = openssl_only
            assert shutil.which("adb") is None
            print("adb ausente do PATH; somente OpenSSL permitido como subprocesso")
            for attempt in range(2):
                print(f"Sessão HDB {attempt + 1}", flush=True)
                with client.connect(kind="hdb", serial=args.serial, verbose=True,
                                    auth_timeout=args.auth_timeout) as conn:
                    assert conn.transport.interface.intf.bInterfaceSubClass == HDB_SUBCLASS
                    print("Banner:", conn.banner)
                    if attempt == 0:
                        try:
                            print("Shell:", client.Hdb(conn).shell("id", timeout=5))
                        except ServiceAuthRequired as exc:
                            print("Shell ainda bloqueado:", exc)
                    reply = conn.hdb_auth_exchange(b"HDB AUTHENTICREQUSET")
                    prefix = b"HDB AUTHENTICRES3000"
                    if not reply.startswith(prefix) or len(bytes.fromhex(reply[20:].decode())) != 256:
                        raise RuntimeError("desafio HDB inesperado")
                    print("RES3000: desafio RSA cifrado de 256 bytes recebido")
                time.sleep(2)
            print("Subprocessos:", calls)
            print("Duas autorizações USB HDB confirmadas; não equivale a autenticação dos serviços.")
    finally:
        subprocess.run = real_run
        if old_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = old_path
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
