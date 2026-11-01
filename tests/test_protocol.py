"""Testes do framing e do banner (rodam sem dispositivo)."""
import struct
import zlib

import pytest

from openhdb import protocol as P


def test_header_roundtrip():
    msg = P.Message(P.A_OPEN, 7, 0, b"shell:id\0")
    header, data = msg.encode()
    assert len(header) == 24 and data == b"shell:id\0"
    cmd, a0, a1, ln, crc, magic = P.decode_header(header)
    assert (cmd, a0, a1, ln) == (P.A_OPEN, 7, 0, 9)
    assert crc == zlib.crc32(data) & 0xFFFFFFFF
    assert magic == P.A_OPEN ^ 0xFFFFFFFF


def test_magic_invalido():
    header = struct.pack("<6I", P.A_CNXN, 1, 1, 0, 0, 0)
    with pytest.raises(ValueError):
        P.decode_header(header)


def test_constantes_sao_ascii_le():
    # "CNXN" etc. lidos como little-endian
    assert P.A_CNXN.to_bytes(4, "little") == b"CNXN"
    assert P.A_AUTH.to_bytes(4, "little") == b"AUTH"
    assert P.A_WRTE.to_bytes(4, "little") == b"WRTE"
    assert P.A_OKAY.to_bytes(4, "little") == b"OKAY"


def test_banner():
    assert P.parse_banner("hdb::shell_v2,cmd,stat_v2") == ("hdb", ["shell_v2", "cmd", "stat_v2"])
    assert P.parse_banner("device::") == ("device", [])
    assert P.make_banner("host", ["a", "b"]) == "host::a,b"
