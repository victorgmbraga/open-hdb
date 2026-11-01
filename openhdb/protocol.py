"""Wire format do HDB.

O ``hdbd`` é um fork do ``adbd`` (ver docs/PROTOCOL.md), portanto o framing é o
mesmo do ADB: um cabeçalho de 24 bytes little-endian seguido dos dados.

Este módulo não tem dependências externas.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

# --- comandos (mesmos valores do adb; ver docs/PROTOCOL.md §2) ---------------
# Os valores são o ASCII lido como uint32 little-endian:
#   "SYNC" -> 53 59 4E 43 -> 0x434E5953
A_SYNC = 0x434E5953
A_CNXN = 0x4E584E43
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_AUTH = 0x48545541
A_STLS = 0x534C5453

COMMAND_NAMES = {
    A_SYNC: "SYNC",
    A_CNXN: "CNXN",
    A_OPEN: "OPEN",
    A_OKAY: "OKAY",
    A_CLSE: "CLSE",
    A_WRTE: "WRTE",
    A_AUTH: "AUTH",
    A_STLS: "STLS",
}

# --- versões do protocolo ---------------------------------------------------
A_VERSION_MIN = 0x01000000
A_VERSION_SKIP_CHECKSUM = 0x01000001
A_VERSION = 0x01000001

# --- autenticação -----------------------------------------------------------
AUTH_TOKEN = 1
AUTH_SIGNATURE = 2
AUTH_RSAPUBLICKEY = 3

AUTH_NAMES = {
    AUTH_TOKEN: "TOKEN",
    AUTH_SIGNATURE: "SIGNATURE",
    AUTH_RSAPUBLICKEY: "RSAPUBLICKEY",
}

#: payload máximo que anunciamos/aceitamos (o adbd clássico usa 4096)
MAX_PAYLOAD = 4096 * 64

#: cabeçalho: command, arg0, arg1, data_length, data_crc32, magic
HEADER = struct.Struct("<6I")
HEADER_SIZE = HEADER.size  # 24


@dataclass
class Message:
    """Um pacote HDB/ADB (cabeçalho + dados)."""

    command: int
    arg0: int = 0
    arg1: int = 0
    data: bytes = b""

    @property
    def name(self) -> str:
        return COMMAND_NAMES.get(self.command, f"0x{self.command:08X}")

    def encode(self) -> tuple[bytes, bytes]:
        """Retorna (cabeçalho, dados) prontos para escrita no transporte."""
        crc = zlib.crc32(self.data) & 0xFFFFFFFF if self.data else 0
        header = HEADER.pack(
            self.command,
            self.arg0,
            self.arg1,
            len(self.data),
            crc,
            self.command ^ 0xFFFFFFFF,
        )
        return header, self.data

    def __repr__(self) -> str:  # pragma: no cover - conveniência de debug
        detail = ""
        if self.command == A_AUTH:
            detail = f" {AUTH_NAMES.get(self.arg0, self.arg0)}"
        return f"<{self.name}{detail} arg0={self.arg0} arg1={self.arg1} len={len(self.data)}>"


def decode_header(header: bytes) -> tuple[int, int, int, int, int, int]:
    """Decodifica e valida um cabeçalho; levanta ValueError se o magic não casar."""
    if len(header) != HEADER_SIZE:
        raise ValueError(f"cabeçalho incompleto: {len(header)} de {HEADER_SIZE} bytes")
    command, arg0, arg1, length, crc, magic = HEADER.unpack(header)
    if magic != (command ^ 0xFFFFFFFF):
        raise ValueError(
            f"magic inválido para {COMMAND_NAMES.get(command, hex(command))}: "
            f"{magic:#010x} != {command ^ 0xFFFFFFFF:#010x}"
        )
    return command, arg0, arg1, length, crc, magic


def parse_banner(banner: str) -> tuple[str, list[str]]:
    """Divide um banner ``<tipo>::<feature>,<feature>,...`` (ver docs §3).

    >>> parse_banner("hdb::shell_v2,cmd,stat_v2")
    ('hdb', ['shell_v2', 'cmd', 'stat_v2'])
    """
    kind, _, rest = banner.partition("::")
    features = [f for f in rest.split(",") if f]
    return kind, features


def make_banner(kind: str, features: list[str]) -> str:
    return f"{kind}::" + ",".join(features)
