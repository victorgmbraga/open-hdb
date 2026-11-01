"""Framing real de 24 bytes, sem hardware."""
import struct

import pytest

from openhdb import protocol as P, protocol_hdb as H


def test_header_roundtrip():
    msg = P.Message(P.A_OPEN, 7, 0, b"shell:id\0")
    header, data = msg.encode()
    assert len(header) == 24
    assert P.decode_header(header) == (P.A_OPEN, 7, 0, 9, sum(data), P.A_OPEN ^ 0xFFFFFFFF)
    decoded, used = H.decode(header + data)
    assert decoded == msg
    assert used == len(header + data)


def test_checksum_is_sum_for_both_protocols():
    for payload in (b"", b"abc", bytes(range(256)) * 20):
        header, _ = P.Message(P.A_WRTE, data=payload).encode()
        assert P.decode_header(header)[4] == sum(payload) & 0xFFFFFFFF


def test_skip_checksum_and_reject_crc32():
    assert P.decode_header(P.Message(P.A_WRTE, data=b"abc").encode("none")[0])[4] == 0
    with pytest.raises(ValueError):
        P.Message(P.A_WRTE).encode("crc32")


def test_invalid_magic():
    with pytest.raises(ValueError):
        P.decode_header(struct.pack("<6I", P.A_CNXN, 1, 1, 0, 0, 0))


@pytest.mark.parametrize("raw", [b"", b"x" * 23, b"x" * 25])
def test_invalid_header_size(raw):
    with pytest.raises(ValueError):
        P.decode_header(raw)


def test_invalid_checksum_and_truncated_payload():
    header, data = P.Message(P.A_WRTE, data=b"abc").encode()
    for raw in (header + b"abd", header + data[:2]):
        with pytest.raises(ValueError):
            H.decode(raw)


def test_constants_are_ascii_le():
    for command, text in ((P.A_CNXN, b"CNXN"), (P.A_AUTH, b"AUTH"), (P.A_OPEN, b"OPEN")):
        assert command.to_bytes(4, "little") == text


def test_banner_properties():
    banner = "device::ro.product.name=KOB2-W09;features=stat_v2,cmd,shell_v2;\0"
    assert P.parse_banner(banner) == ("device", ["stat_v2", "cmd", "shell_v2"])
    assert P.parse_banner("device::ro.product.model=X;") == ("device", [])
    assert P.make_banner("host", ["a", "b"]) == "host::features=a,b;\0"
    assert P.parse_banner(P.make_banner("host", ["a", "b"])) == ("host", ["a", "b"])
