"""Cabeçalho de 36 bytes do HDB (descoberto por desmontagem do hdbd).

Layout reconstruído de ``check_header``/``send_packet``/``handle_packet``
(ver docs/PROTOCOL.md §2.1)::

    offset  tamanho  campo
    0x00    4        prefixo de quadro (lido/escrito separadamente pelo hdbd) — semântica aberta
    0x04    4        desconhecido
    0x08    4        desconhecido
    0x0c    4        command
    0x10    4        arg0
    0x14    4        arg1
    0x18    4        data_length
    0x1c    4        data_check  (soma dos bytes; ver calculate_apacket_checksum)
    0x20    4        magic       (= ~command; check_header valida)
    0x24    ...      data

Evidência no binário (Thumb, ``hdbd`` do KOB2-W09):

    check_header:   ldr r0,[r6,#0xc]      ; command
                    ldr r1,[r6,#0x20]     ; magic
                    mvns r0,r0 ; cmp r1,r0
                    ldr r0,[r5,#0xa0]     ; transport->max_payload
                    ldr r1,[r6,#0x18]     ; data_length
    send_packet:    ldr r0,[r5,#0xc] ; mvns r0,r0 ; str r0,[r5,#0x20]
                    bl calculate_apacket_checksum ; str r0,[r5,#0x1c]
    handle_packet:  ldr r1,[r4,#0xc] ; movw/movt 0x4854_5541 (A_AUTH) / 0x4e45_504f (A_OPEN)
                    payload em r4+0x24

O prefixo de 4 bytes é lido/escrito antes do resto por ``read_packet``/``write_packet``;
o valor correto ainda não foi identificado (ver docs/PROTOCOL.md §8).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HDR_SIZE = 0x24  # 36 bytes
PREFIX_SIZE = 4

_CMD = 0x0C
_ARG0 = 0x10
_ARG1 = 0x14
_LEN = 0x18
_CHECK = 0x1C
_MAGIC = 0x20


@dataclass
class HdbMessage:
    command: int
    arg0: int = 0
    arg1: int = 0
    data: bytes = b""
    prefix: int = 0

    def checksum(self) -> int:
        """``calculate_apacket_checksum``: soma dos bytes (não CRC32!)."""
        return sum(self.data) & 0xFFFFFFFF

    def encode(self) -> bytes:
        header = bytearray(HDR_SIZE)
        struct.pack_into("<I", header, _CMD, self.command)
        struct.pack_into("<I", header, _ARG0, self.arg0)
        struct.pack_into("<I", header, _ARG1, self.arg1)
        struct.pack_into("<I", header, _LEN, len(self.data))
        struct.pack_into("<I", header, _CHECK, self.checksum())
        struct.pack_into("<I", header, _MAGIC, (~self.command) & 0xFFFFFFFF)
        return struct.pack("<I", self.prefix) + bytes(header) + self.data


def decode(raw: bytes) -> tuple[HdbMessage, int]:
    """Decodifica ``prefixo + cabeçalho [+ dados]``. Retorna (mensagem, consumido)."""
    if len(raw) < PREFIX_SIZE + HDR_SIZE:
        raise ValueError(f"quadro curto: {len(raw)} bytes")
    (prefix,) = struct.unpack_from("<I", raw, 0)
    base = PREFIX_SIZE
    (command,) = struct.unpack_from("<I", raw, base + _CMD)
    (arg0,) = struct.unpack_from("<I", raw, base + _ARG0)
    (arg1,) = struct.unpack_from("<I", raw, base + _ARG1)
    (length,) = struct.unpack_from("<I", raw, base + _LEN)
    (check,) = struct.unpack_from("<I", raw, base + _CHECK)
    (magic,) = struct.unpack_from("<I", raw, base + _MAGIC)
    if magic != (~command) & 0xFFFFFFFF:
        raise ValueError(f"magic inválido: {magic:#010x} != {~command & 0xFFFFFFFF:#010x}")
    data = raw[base + HDR_SIZE : base + HDR_SIZE + length]
    if len(data) != length:
        raise ValueError(f"dados incompletos: {len(data)} de {length}")
    if data and (sum(data) & 0xFFFFFFFF) != check:
        raise ValueError("checksum inválido")
    return HdbMessage(command, arg0, arg1, data, prefix), base + HDR_SIZE + length
