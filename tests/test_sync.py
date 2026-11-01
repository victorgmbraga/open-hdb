from collections import deque

import pytest

from openhdb.sync import HEADER, MAX_DATA, Sync
from openhdb.usb import TransportError


class Stream:
    def __init__(self, raw):
        self.chunks = deque(raw[i:i + 3] for i in range(0, len(raw), 3))
        self.sent = bytearray()

    def write(self, data, timeout):
        self.sent.extend(data)

    def read(self, timeout):
        return self.chunks.popleft() if self.chunks else None


@pytest.mark.parametrize("data", [b"", b"\0\xffhello\r\n", bytes(range(256)) * 300])
def test_binary_push(tmp_path, data):
    local = tmp_path / "file"
    local.write_bytes(data)
    stream = Stream(HEADER.pack(b"OKAY", 0))
    Sync(stream).push(local, "/data/local/tmp/a b;'file")
    raw = bytes(stream.sent)
    path = b"/data/local/tmp/a b;'file,33206"
    assert raw.startswith(HEADER.pack(b"SEND", len(path)) + path)
    pos = 8 + len(path)
    recovered = bytearray()
    while True:
        command, size = HEADER.unpack(raw[pos:pos + 8])
        pos += 8
        if command == b"DONE":
            break
        assert command == b"DATA" and size <= MAX_DATA
        recovered.extend(raw[pos:pos + size])
        pos += size
    assert recovered == data and pos == len(raw)


@pytest.mark.parametrize("data", [b"", b"\xff\0\r\nhello"])
def test_pull_including_empty_files(tmp_path, data):
    raw = HEADER.pack(b"DATA", len(data)) + data + HEADER.pack(b"DONE", 0)
    stream = Stream(raw)
    local = tmp_path / "download"
    Sync(stream).pull("/tmp/a", local)
    assert local.read_bytes() == data
    assert bytes(stream.sent) == HEADER.pack(b"RECV", 6) + b"/tmp/a"


def test_failed_pull_preserves_destination(tmp_path):
    target = tmp_path / "keep"
    target.write_bytes(b"old")
    stream = Stream(HEADER.pack(b"FAIL", 6) + b"denied")
    with pytest.raises(TransportError, match="denied"):
        Sync(stream).pull("/private", target)
    assert target.read_bytes() == b"old"
    assert list(tmp_path.iterdir()) == [target]


def test_truncated_pull_does_not_create_file(tmp_path):
    target = tmp_path / "file"
    with pytest.raises(TransportError):
        Sync(Stream(HEADER.pack(b"DATA", 10) + b"xx")).pull("/x", target)
    assert not target.exists()


@pytest.mark.parametrize("remote", ["", "x\0y", "x" * 1025])
def test_invalid_path(remote):
    with pytest.raises(ValueError):
        Sync._path(remote)
