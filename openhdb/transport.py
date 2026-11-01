"""Camada de conexão: ``A_CNXN`` + autenticação + streams."""

from __future__ import annotations

import time
from pathlib import Path

from . import auth, protocol
from .protocol import Message
from .usb import TransportError, UsbTransport

HOST_FEATURES = ["shell_v2", "cmd", "stat_v2", "ls_v2", "libusb"]


class ConnectionError_(RuntimeError):
    pass


class Stream:
    """Um stream aberto (equivale a um socket do adb)."""

    def __init__(self, conn: "HdbConnection", local_id: int):
        self.conn = conn
        self.local_id = local_id
        self.remote_id: int | None = None
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        if self.remote_id is None:
            raise ConnectionError_("stream não confirmado (A_OKAY não recebido)")
        for off in range(0, len(data), protocol.MAX_PAYLOAD):
            chunk = data[off : off + protocol.MAX_PAYLOAD]
            self.conn.send(Message(protocol.A_WRTE, self.local_id, self.remote_id, chunk))
            self.conn.wait_ack(self)

    def read(self, timeout: float = 5.0) -> bytes | None:
        """Lê o que houver; ``None`` quando o stream fecha."""
        if self.buffer:
            data, self.buffer = bytes(self.buffer), bytearray()
            return data
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.closed:
                return None
            remaining = max(0.05, deadline - time.monotonic())
            try:
                msg = self.conn.recv(timeout=min(remaining, 0.5))
            except TransportError:
                continue
            if self.conn.dispatch(msg):
                if self.buffer:
                    data, self.buffer = bytes(self.buffer), bytearray()
                    return data
                if self.closed:
                    return None
        return b""

    def close(self) -> None:
        if self.remote_id is not None and not self.closed:
            self.conn.send(Message(protocol.A_CLSE, self.local_id, self.remote_id))
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class HdbConnection:
    """Conecta, autentica e multiplexa streams sobre um transporte USB."""

    def __init__(self, transport: UsbTransport, key_path: Path | None = None, verbose: bool = False):
        self.transport = transport
        self.key_path = auth.ensure_key(key_path or auth.DEFAULT_KEY)
        self.verbose = verbose
        self.banner: str | None = None
        self.features: list[str] = []
        self.version: int = 0
        self.max_payload: int = protocol.MAX_PAYLOAD
        self.online = False
        self.kind: str | None = None
        self._next_id = 1
        self._streams: dict[int, Stream] = {}
        self._log: list[Message] = []

    # -- utilitários --------------------------------------------------------
    def _trace(self, direction: str, msg: Message) -> None:
        self._log.append(msg)
        if self.verbose:
            print(f"  {direction} {msg}")

    def send(self, msg: Message) -> None:
        self._trace(">>", msg)
        self.transport.send(msg)

    def recv(self, timeout: float = 2.0) -> Message:
        msg = self.transport.recv(int(timeout * 1000))
        self._trace("<<", msg)
        return msg

    # -- handshake ----------------------------------------------------------
    def connect(self, timeout: float = 15.0) -> str:
        """Executa CNXN + AUTH. Retorna o banner do dispositivo."""
        self.send(
            Message(
                protocol.A_CNXN,
                protocol.A_VERSION,
                protocol.MAX_PAYLOAD,
                protocol.make_banner("host", HOST_FEATURES).encode(),
            )
        )
        deadline = time.monotonic() + timeout
        sent_key = False
        while time.monotonic() < deadline:
            msg = self.recv(timeout=min(3.0, max(0.2, deadline - time.monotonic())))
            if msg.command == protocol.A_CNXN:
                self.banner = msg.data.decode(errors="replace")
                self.kind, self.features = protocol.parse_banner(self.banner)
                self.version, self.max_payload = msg.arg0, msg.arg1 or protocol.MAX_PAYLOAD
                self.online = True
                return self.banner
            if msg.command == protocol.A_AUTH:
                self._handle_auth(msg, sent_key)
                sent_key = sent_key or msg.arg0 == protocol.AUTH_RSAPUBLICKEY
                continue
            if msg.command == protocol.A_STLS:
                raise ConnectionError_("dispositivo exigiu TLS (A_STLS), não suportado")
        raise ConnectionError_("timeout esperando A_CNXN do dispositivo")

    def _handle_auth(self, msg: Message, already_sent_key: bool) -> None:
        if msg.arg0 == protocol.AUTH_TOKEN:
            signature = auth.sign_token(self.key_path, msg.data[:20])
            self.send(Message(protocol.A_AUTH, protocol.AUTH_SIGNATURE, 0, signature))
            return
        if msg.arg0 == protocol.AUTH_RSAPUBLICKEY:
            if already_sent_key:
                raise ConnectionError_(
                    "chave recusada duas vezes: remova a autorização antiga no tablet "
                    "ou desligue a depuração USB/HDB e repita"
                )
            key = auth.encoded_public_key(self.key_path)
            self.send(Message(protocol.A_AUTH, protocol.AUTH_RSAPUBLICKEY, 0, key + b"\0"))
            return
        raise ConnectionError_(f"A_AUTH desconhecido: arg0={msg.arg0}")

    # -- streams ------------------------------------------------------------
    def open(self, service: str, timeout: float = 5.0) -> Stream:
        local_id = self._next_id
        self._next_id += 1
        stream = Stream(self, local_id)
        self._streams[local_id] = stream
        self.send(Message(protocol.A_OPEN, local_id, 0, service.encode() + b"\0"))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if stream.remote_id is not None:
                return stream
            msg = self.recv(timeout=min(1.0, max(0.1, deadline - time.monotonic())))
            self.dispatch(msg)
        raise ConnectionError_(f"timeout abrindo stream {service!r}")

    def dispatch(self, msg: Message) -> bool:
        """Roteia a mensagem para o stream certo. Retorna True se era de um stream."""
        if msg.command == protocol.A_OKAY:
            stream = self._streams.get(msg.arg1)
            if stream is not None:
                stream.remote_id = msg.arg0
                return True
        elif msg.command == protocol.A_WRTE:
            stream = self._streams.get(msg.arg1)
            if stream is not None:
                stream.buffer.extend(msg.data)
                self.send(Message(protocol.A_OKAY, msg.arg1, msg.arg0))
                return True
        elif msg.command == protocol.A_CLSE:
            stream = self._streams.get(msg.arg1)
            if stream is not None:
                stream.closed = True
                stream.remote_id = msg.arg0
                self.send(Message(protocol.A_CLSE, msg.arg1, msg.arg0))
                self._streams.pop(msg.arg1, None)
                return True
        return False

    def wait_ack(self, stream: Stream, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.recv(timeout=0.5)
            if self.dispatch(msg):
                if msg.command == protocol.A_OKAY and msg.arg1 == stream.local_id:
                    return
            if stream.closed:
                return
        raise ConnectionError_("timeout esperando A_OKAY de escrita")

    def close(self) -> None:
        for stream in list(self._streams.values()):
            try:
                stream.close()
            except Exception:
                pass
        self.transport.close()
