from collections import deque
from types import SimpleNamespace

import pytest
import usb.core

from openhdb import protocol as P
from openhdb.usb import TransportError, TransportTimeout, UsbTransport


class Endpoint:
    wMaxPacketSize = 64

    def __init__(self, chunks):
        self.chunks = deque(chunks)

    def read(self, size, timeout):
        assert size % self.wMaxPacketSize == 0
        chunk = self.chunks.popleft()
        if isinstance(chunk, Exception):
            raise chunk
        return chunk


def make_transport(chunks):
    transport = UsbTransport(SimpleNamespace(device=None))
    transport._ep_in = Endpoint(chunks)
    return transport


def raw_message(data=b"abc"):
    h, d = P.Message(P.A_WRTE, 7, 1, data).encode()
    return h + d


def test_partial_header_and_payload_survive_timeout():
    raw = raw_message()
    transport = make_transport([raw[:10], usb.core.USBTimeoutError("timeout"), raw[10:25],
                                usb.core.USBTimeoutError("timeout"), raw[25:]])
    for _ in range(2):
        with pytest.raises(TransportTimeout):
            transport.recv()
    assert transport.recv() == P.Message(P.A_WRTE, 7, 1, b"abc")


def test_combined_frames_and_zlp():
    transport = make_transport([b"", raw_message() + raw_message(b"xyz")])
    assert transport.recv().data == b"abc"
    assert transport.recv().data == b"xyz"


def test_invalid_checksum():
    raw = raw_message()
    with pytest.raises(TransportError, match="checksum"):
        make_transport([raw[:-1] + b"z"]).recv()


def test_max_length_checked_before_allocation():
    h = P.HEADER.pack(P.A_WRTE, 1, 2, P.MAX_PAYLOAD + 1, 0, P.A_WRTE ^ 0xFFFFFFFF)
    with pytest.raises(TransportError, match="limite"):
        make_transport([h]).recv()


def test_disconnect_not_a_timeout():
    with pytest.raises(TransportError, match="falha") as exc:
        make_transport([usb.core.USBError("disconnected")]).recv()
    assert not isinstance(exc.value, TransportTimeout)
