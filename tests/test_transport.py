from collections import deque
from pathlib import Path

import pytest

from openhdb import auth, protocol as P
from openhdb.transport import HdbConnection, ServiceAuthRequired, ServiceRejected, ConnectionError_
from openhdb.usb import TransportError, TransportTimeout


class FakeUsb:
    def __init__(self, messages):
        self.messages = deque(messages)
        self.sent = []
        self.closed = False

    def send_raw(self, header, data):
        command, a0, a1, length, checksum, magic = P.decode_header(header)
        assert checksum == sum(data) & 0xFFFFFFFF
        self.sent.append(P.Message(command, a0, a1, data))

    def recv(self, timeout):
        if not self.messages:
            raise TransportTimeout("fake idle")
        msg = self.messages.popleft()
        if isinstance(msg, Exception):
            raise msg
        return msg

    def close(self):
        self.closed = True


@pytest.fixture
def connection(monkeypatch):
    monkeypatch.setattr(auth, "ensure_key", lambda path: Path("fake.pem"))
    monkeypatch.setattr(auth, "sign_token", lambda path, token: b"S" * 256)
    monkeypatch.setattr(auth, "encoded_public_key", lambda path: b"base64 test@host")
    monkeypatch.setattr(auth, "fingerprint", lambda path: "AA:BB")
    def make(messages, **kwargs):
        return HdbConnection(FakeUsb(messages), **kwargs)
    return make


def banner():
    return P.Message(P.A_CNXN, P.A_VERSION_MIN, 4096, b"device::features=cmd;\0")


def token():
    return P.Message(P.A_AUTH, P.AUTH_TOKEN, 0, b"T" * 20)


def test_known_key_and_no_settle_or_resend(connection):
    conn = connection([token(), banner()])
    assert conn.connect() == "device::features=cmd;"
    assert [m.command for m in conn.transport.sent] == [P.A_CNXN, P.A_AUTH]
    assert conn.online and conn.features == ["cmd"]
    assert conn.transport.sent[1].arg0 == P.AUTH_SIGNATURE


def test_unknown_key_public_key_null_and_callback(connection):
    approvals = []
    conn = connection([token(), token(), banner()], approve=approvals.append)
    conn.connect()
    key = conn.transport.sent[-1]
    assert key.arg0 == P.AUTH_RSAPUBLICKEY
    assert key.data == b"base64 test@host\0"
    assert approvals == ["AA:BB"]


def test_auth_restart_not_an_infinite_signature_loop(connection):
    conn = connection([token(), token(), token()])
    with pytest.raises(ConnectionError_, match="recusada"):
        conn.connect()
    assert len(conn.transport.sent) == 3


def test_disconnect_not_swallowed_as_timeout(connection):
    conn = connection([TransportError("unplugged")])
    with pytest.raises(TransportError, match="unplugged"):
        conn.connect()


def test_timeout_can_be_retried(connection):
    conn = connection([TransportTimeout("idle"), banner()])
    conn.connect()
    assert conn.online


def test_hdb_service_rejection_not_timeout(connection):
    conn = connection([banner(), P.Message(P.A_OPEN, 1, 0, b"HDB AUTHENTICEXABORT\0")])
    conn.connect()
    with pytest.raises(ServiceAuthRequired, match="AUTHENTICEXABORT"):
        conn.open("shell:id")
    assert not conn._streams
    assert len([m for m in conn.transport.sent if m.command == P.A_OPEN]) == 1


def test_hdb_control_exchange(connection):
    payload = b"HDB AUTHENTICRES3000" + b"AA" * 256
    conn = connection([banner(), P.Message(P.A_OPEN, 1, 0, payload + b"\0")])
    conn.connect()
    assert conn.hdb_auth_exchange(b"HDB AUTHENTICREQUSET") == payload
    assert conn.transport.sent[-1].data == b"HDB AUTHENTICREQUSET\0"


def test_rejected_stream_cleanup(connection):
    conn = connection([banner(), P.Message(P.A_CLSE, 0, 1)])
    conn.connect()
    with pytest.raises(ServiceRejected):
        conn.open("invalid:")
    assert not conn._streams


def test_stream_read_ack_and_close(connection):
    conn = connection([banner(), P.Message(P.A_OKAY, 7, 1),
                       P.Message(P.A_WRTE, 7, 1, b"hello\0\xff"), P.Message(P.A_CLSE, 7, 1)])
    with conn:
        conn.connect()
        with conn.open("shell:id") as stream:
            assert stream.read() == b"hello\0\xff"
            assert stream.read() is None
        assert conn.transport.sent[-2:] == [P.Message(P.A_OKAY, 1, 7), P.Message(P.A_CLSE, 1, 7)]
    assert conn.transport.closed and not conn.online and not conn._streams


def test_write_uses_negotiated_payload(connection):
    conn = connection([banner(), P.Message(P.A_OKAY, 7, 1)] + [P.Message(P.A_OKAY, 7, 1)] * 3)
    conn.connect()
    stream = conn.open("sync:")
    stream.write(b"x" * 9000)
    assert [len(m.data) for m in conn.transport.sent if m.command == P.A_WRTE] == [4096, 4096, 808]


def test_open_send_failure_cleanup(connection, monkeypatch):
    conn = connection([banner()])
    conn.connect()
    def fail(msg):
        raise TransportError("USB write failed")
    monkeypatch.setattr(conn, "send", fail)
    with pytest.raises(TransportError, match="write failed"):
        conn.open("shell:id")
    assert not conn._streams


def test_write_closed_before_ack_is_error(connection):
    conn = connection([banner(), P.Message(P.A_OKAY, 7, 1), P.Message(P.A_CLSE, 7, 1)])
    conn.connect()
    stream = conn.open("sync:")
    with pytest.raises(ServiceRejected):
        stream.write(b"data")


def test_invalid_negotiated_payload(connection):
    conn = connection([P.Message(P.A_CNXN, P.A_VERSION_MIN, 0, b"device::")])
    with pytest.raises(ConnectionError_, match="max_payload"):
        conn.connect()
    large = connection([P.Message(P.A_CNXN, P.A_VERSION_MIN, 1024 * 1024, b"device::")])
    large.connect()
    assert large.max_payload == P.MAX_PAYLOAD


def test_timeout_cleanup(connection):
    conn = connection([banner()])
    conn.connect()
    with pytest.raises(TransportTimeout):
        conn.open("shell:id", timeout=0.002)
    assert not conn._streams
