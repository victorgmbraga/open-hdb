"""CNXN/AUTH e streams no framing compartilhado por ADB e HDB."""
from __future__ import annotations

import time
from pathlib import Path

from . import auth, protocol
from .protocol import Message
from .usb import TransportError, TransportTimeout, UsbTransport

# Não anunciar serviços/protocolos que este cliente ainda não implementa.
HOST_FEATURES: list[str] = []


class ConnectionError_(TransportError):
    pass


class ServiceAuthRequired(ConnectionError_):
    """A autorização USB funcionou, mas falta a autenticação Huawei de serviços."""


class ServiceRejected(ConnectionError_):
    pass


class Stream:
    def __init__(self, conn: "HdbConnection", local_id: int):
        self.conn = conn
        self.local_id = local_id
        self.remote_id: int | None = None
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes, timeout: float = 5.0) -> None:
        if self.remote_id is None or self.closed:
            raise ConnectionError_("stream não está aberto")
        deadline = time.monotonic() + timeout
        for off in range(0, len(data), self.conn.max_payload):
            chunk = data[off:off + self.conn.max_payload]
            self.conn.send(Message(protocol.A_WRTE, self.local_id, self.remote_id, chunk))
            self.conn.wait_ack(self, max(0.0, deadline - time.monotonic()))

    def read(self, timeout: float = 5.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            if self.buffer:
                data, self.buffer = bytes(self.buffer), bytearray()
                return data
            if self.closed:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("timeout lendo stream")
            try:
                self.conn.dispatch(self.conn.recv(timeout=min(remaining, 0.5)))
            except TransportTimeout:
                continue

    def close(self) -> None:
        try:
            if self.remote_id is not None and not self.closed:
                self.conn.send(Message(protocol.A_CLSE, self.local_id, self.remote_id))
        finally:
            self.closed = True
            self.conn._streams.pop(self.local_id, None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class HdbConnection:
    def __init__(self, transport: UsbTransport, key_path: Path | None = None,
                 verbose: bool = False, checksum: str = "sum", approve=None,
                 transport_kind: str = "hdb"):
        self.transport = transport
        self.checksum = checksum
        self.approve = approve  # callback opcional; nunca chama ADB por conta própria
        self.transport_kind = transport_kind
        self.is_hdb = transport_kind == "hdb"
        self.key_path = auth.ensure_key(key_path or auth.DEFAULT_KEY)
        self.verbose = verbose
        self.banner: str | None = None
        self.features: list[str] = []
        self.version = 0
        self.max_payload = protocol.MAX_PAYLOAD
        self.online = False
        self.kind: str | None = None
        self._tokens = 0
        self._key_sent = False
        self._next_id = 1
        self._streams: dict[int, Stream] = {}

    def _trace(self, direction: str, msg: Message) -> None:
        if self.verbose:
            import sys
            detail = f" {msg.data[:80]!r}" if msg.data.startswith(b"HDB ") else ""
            print(f"  {direction} {msg}{detail}", file=sys.stderr)

    def send(self, msg: Message) -> None:
        self._trace(">>", msg)
        header, data = msg.encode(checksum=self.checksum)
        self.transport.send_raw(header, data)

    def recv(self, timeout: float = 2.0) -> Message:
        msg = self.transport.recv(max(1, int(timeout * 1000)))
        self._trace("<<", msg)
        return msg

    def connect(self, timeout: float = 60.0) -> str:
        offered_version = protocol.A_VERSION_MIN if self.is_hdb else protocol.A_VERSION
        self.transport.skip_checksum = offered_version >= protocol.A_VERSION_SKIP_CHECKSUM
        self.send(Message(protocol.A_CNXN, offered_version, protocol.MAX_PAYLOAD,
                          protocol.make_banner("host", HOST_FEATURES).encode()))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                msg = self.recv(timeout=min(1.0, deadline - time.monotonic()))
            except TransportTimeout:
                continue
            if msg.command == protocol.A_CNXN:
                if not protocol.A_VERSION_MIN <= msg.arg0 <= protocol.A_VERSION:
                    raise ConnectionError_(f"versão não suportada: {msg.arg0:#x}")
                if msg.arg1 == 0:
                    raise ConnectionError_(f"max_payload inválido: {msg.arg1}")
                self.banner = msg.data.rstrip(b"\0").decode(errors="replace")
                self.kind, self.features = protocol.parse_banner(self.banner)
                self.version = msg.arg0
                self.max_payload = min(msg.arg1, protocol.MAX_PAYLOAD)
                self.transport.skip_checksum = msg.arg0 >= protocol.A_VERSION_SKIP_CHECKSUM
                self.online = True
                return self.banner
            if msg.command == protocol.A_AUTH:
                self._handle_auth(msg)
            elif msg.command == protocol.A_STLS:
                raise ConnectionError_("dispositivo exigiu TLS (A_STLS), não suportado")
            else:
                raise ConnectionError_(f"pacote inesperado durante autenticação: {msg}")
        raise ConnectionError_("timeout na autorização USB; desbloqueie o tablet e aprove a chave")

    def _handle_auth(self, msg: Message) -> None:
        if msg.arg0 != protocol.AUTH_TOKEN:
            raise ConnectionError_(f"AUTH inesperado do dispositivo: arg0={msg.arg0}")
        if len(msg.data) != 20:
            raise ConnectionError_(f"TOKEN inválido: {len(msg.data)} bytes")
        self._tokens += 1
        if self._tokens == 1:
            signature = auth.sign_token(self.key_path, msg.data)
            self.send(Message(protocol.A_AUTH, protocol.AUTH_SIGNATURE, 0, signature))
        elif not self._key_sent:
            key = auth.encoded_public_key(self.key_path) + b"\0"
            self.send(Message(protocol.A_AUTH, protocol.AUTH_RSAPUBLICKEY, 0, key))
            self._key_sent = True
            if self.approve:
                self.approve(auth.fingerprint(self.key_path))
        else:
            raise ConnectionError_("autorização USB recusada ou reiniciada após envio da chave")

    def _allocate_id(self) -> int:
        local_id = self._next_id
        self._next_id += 1
        return local_id

    def hdb_auth_exchange(self, payload: bytes, timeout: float = 5.0) -> bytes:
        """Troca de controle HDB via A_OPEN (não é um serviço de shell).

        Helper de pesquisa: não implementa a resposta RSA da Huawei nem usa ADB.
        """
        if not self.online or not self.is_hdb or not payload.startswith(b"HDB "):
            raise ConnectionError_("troca de controle requer conexão HDB e payload 'HDB '")
        local_id = self._allocate_id()
        self.send(Message(protocol.A_OPEN, local_id, 0, payload.rstrip(b"\0") + b"\0"))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                msg = self.recv(min(0.5, deadline - time.monotonic()))
            except TransportTimeout:
                continue
            if msg.command == protocol.A_OPEN and msg.arg0 == local_id and msg.data.startswith(b"HDB "):
                return msg.data.rstrip(b"\0")
            self.dispatch(msg)
        raise TransportTimeout("timeout na troca de controle HDB")

    def open(self, service: str, timeout: float = 5.0) -> Stream:
        if not self.online:
            raise ConnectionError_("conexão não autenticada")
        local_id = self._allocate_id()
        stream = Stream(self, local_id)
        self._streams[local_id] = stream
        deadline = time.monotonic() + timeout
        try:
            self.send(Message(protocol.A_OPEN, local_id, 0, service.encode() + b"\0"))
            while time.monotonic() < deadline:
                if stream.closed:
                    raise ServiceRejected(f"serviço recusado: {service!r}")
                if stream.remote_id is not None:
                    return stream
                try:
                    self.dispatch(self.recv(min(0.5, deadline - time.monotonic())))
                except TransportTimeout:
                    continue
            raise TransportTimeout(f"timeout abrindo serviço {service!r}")
        except Exception:
            stream.close()
            raise

    def dispatch(self, msg: Message) -> bool:
        if self.is_hdb and msg.command == protocol.A_OPEN and msg.data.startswith(b"HDB "):
            reply = msg.data.rstrip(b"\0").decode(errors="replace")
            raise ServiceAuthRequired(
                f"hdbd respondeu {reply!r}: autorização USB não basta; "
                "a autenticação Huawei de serviços ainda não foi implementada")
        if msg.command == protocol.A_AUTH:
            self.online = False
            raise ConnectionError_("dispositivo reiniciou a autorização USB após CNXN")
        if msg.command == protocol.A_OKAY:
            stream = self._streams.get(msg.arg1)
            if stream is not None and msg.arg0:
                if stream.remote_id not in (None, msg.arg0):
                    raise ConnectionError_("ID remoto inesperado em OKAY")
                stream.remote_id = msg.arg0
                return True
        elif msg.command == protocol.A_WRTE:
            stream = self._streams.get(msg.arg1)
            if stream is not None and stream.remote_id == msg.arg0:
                stream.buffer.extend(msg.data)
                self.send(Message(protocol.A_OKAY, msg.arg1, msg.arg0))
                return True
        elif msg.command == protocol.A_CLSE:
            stream = self._streams.get(msg.arg1)
            if stream is not None:
                if not stream.closed and stream.remote_id is not None:
                    self.send(Message(protocol.A_CLSE, msg.arg1, msg.arg0))
                stream.closed = True
                self._streams.pop(msg.arg1, None)
                return True
        return False

    def wait_ack(self, stream: Stream, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                msg = self.recv(min(0.5, deadline - time.monotonic()))
            except TransportTimeout:
                continue
            self.dispatch(msg)
            if stream.closed:
                raise ServiceRejected("stream fechado antes de confirmar escrita")
            if msg.command == protocol.A_OKAY and msg.arg1 == stream.local_id:
                return
        raise TransportTimeout("timeout esperando OKAY de escrita")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        try:
            for stream in list(self._streams.values()):
                try:
                    stream.close()
                except TransportError:
                    pass
        finally:
            self.online = False
            self.transport.close()
