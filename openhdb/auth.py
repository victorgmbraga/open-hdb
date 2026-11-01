"""Autenticação HDB (derivada do adb, ver docs/PROTOCOL.md §4).

O dispositivo envia um ``A_AUTH``/``TOKEN`` com 20 bytes de nonce; respondemos
com ``A_AUTH``/``SIGNATURE`` contendo a assinatura PKCS#1 v1.5 + SHA-1 desse
nonce. Se a assinatura não for aceita, o dispositivo pede ``RSAPUBLICKEY`` e
grava a chave em ``/data/misc/adb/hdb_keys`` (store separado do adb_keys).

A chave privada é gerada/gerenciada pelo ``openssl`` (sem dependências Python).
"""

from __future__ import annotations

import base64
import os
import re
import socket
import struct
import subprocess
from pathlib import Path

DEFAULT_KEY = Path.home() / ".config" / "open-hdb" / "hdbkey.pem"

#: prefixo do DigestInfo de SHA-1 (PKCS#1 v1.5), usado só para documentação:
#: o openssl já aplica o prefixo em ``dgst -sha1 -sign``.
_SHA1_DIGESTINFO = bytes.fromhex("3021300906052b0e03021a05000414")


class AuthError(RuntimeError):
    pass


def _run(cmd: list[str], data: bytes | None = None) -> bytes:
    proc = subprocess.run(cmd, input=data, capture_output=True)
    if proc.returncode != 0:
        raise AuthError(f"{' '.join(cmd)} falhou: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def ensure_key(path: Path = DEFAULT_KEY, bits: int = 2048) -> Path:
    """Cria a chave privada RSA se ainda não existir."""
    path = Path(path)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    _run(["openssl", "genrsa", "-out", str(path), str(bits)])
    path.chmod(0o600)
    return path


def modulus_and_exponent(path: Path) -> tuple[int, int]:
    """Lê módulo e expoente público da chave."""
    mod_hex = _run(["openssl", "rsa", "-in", str(path), "-noout", "-modulus"])
    match = re.search(rb"Modulus=([0-9A-Fa-f]+)", mod_hex)
    if not match:
        raise AuthError("não consegui ler o módulo da chave")
    modulus = int(match.group(1), 16)
    text = _run(["openssl", "rsa", "-in", str(path), "-noout", "-text"])
    exp = re.search(rb"publicExponent:\s*(\d+)", text)
    if not exp:
        raise AuthError("não consegui ler o expoente da chave")
    return modulus, int(exp.group(1))


def sign_token(path: Path, token: bytes) -> bytes:
    """Assina o nonce com PKCS#1 v1.5/SHA-1 (256 bytes para chave de 2048 bits)."""
    return _run(["openssl", "dgst", "-sha1", "-sign", str(path)], data=token)


def android_public_key(path: Path) -> bytes:
    """Monta o blob ``RSAPublicKey`` que o adbd/hdbd espera.

    Layout (adb/crypto/rsa_2048.h)::

        uint32 len;       // palavras de 32 bits do módulo (64 para 2048 bits)
        uint32 n0inv;     // -1 / n[0]  mod 2^32
        uint32 n[64];     // módulo em palavras little-endian
        uint32 rr[64];    // R^2 mod n, R = 2^2048
        uint32 exponent;

    Total: 524 bytes.
    """
    modulus, exponent = modulus_and_exponent(path)
    words = (modulus.bit_length() + 31) // 32
    if words != 64:
        raise AuthError(f"chave precisa ser de 2048 bits (módulo tem {words} palavras)")
    n0inv = (-pow(modulus & 0xFFFFFFFF, -1, 1 << 32)) & 0xFFFFFFFF
    rr = pow(1 << (2 * 2048), 1, modulus)
    blob = struct.pack("<II", words, n0inv)
    blob += struct.pack("<64I", *[(modulus >> (32 * i)) & 0xFFFFFFFF for i in range(64)])
    blob += struct.pack("<64I", *[(rr >> (32 * i)) & 0xFFFFFFFF for i in range(64)])
    blob += struct.pack("<I", exponent)
    assert len(blob) == 4 + 4 + 256 + 256 + 4
    return blob


def encoded_public_key(path: Path, identity: str | None = None) -> bytes:
    """Formato que o dispositivo grava em ``hdb_keys``: ``base64 blob user@host``.

    ``identity=""`` devolve só o base64 (o hdbd aceita; o framework então grava
    uma linha sem identidade, que parece ser o formato que ele consegue reler).
    """
    blob = base64.b64encode(android_public_key(path))
    if identity == "":
        return blob
    identity = identity or f"open-hdb@{socket.gethostname()}"
    return blob + b" " + identity.encode()
