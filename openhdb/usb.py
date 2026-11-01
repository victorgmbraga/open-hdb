"""Transporte USB para HDB.

O ``hdbd`` usa FunctionFS: ff/48/01 é HDB; ff/42/01 é ADB.
A seleção da interface é explícita; não há chamadas ao executável ``adb``.

Requer ``pyusb`` e acesso ao nó do dispositivo (udev/ACL).

Um ``adb server`` pode ocupar ff/42 (EBUSY no modo ADB explícito).
O canal HDB ff/48 é separado: não é necessário iniciar/parar esse servidor.
"""

from __future__ import annotations

import time

import usb.core
import usb.util

from .protocol import HEADER_SIZE, Message, decode_header

#: VID/PIDs conhecidos que carregam HDB
KNOWN_VIDS = (0x12D1, 0x0E8D)  # Huawei, MediaTek

#: interfaces de depuração
DEBUG_CLASS = 0xFF
PROTOCOL = 0x01
ADB_SUBCLASS = 0x42   # adbd  -> "ADB Interface"
HDB_SUBCLASS = 0x48   # hdbd  -> "HDB Interface"  (verificado no KOB2-W09)
DEBUG_SUBCLASSES = {ADB_SUBCLASS: "adb", HDB_SUBCLASS: "hdb"}


class TransportError(RuntimeError):
    pass


class TransportTimeout(TransportError):
    """Espera expirou, sem confundir com desconexão ou falha de protocolo."""


class Interface:
    """Uma interface candidata HDB (ff/48/01) ou ADB (ff/42/01)."""

    def __init__(self, device, config, intf):
        self.device = device
        self.config = config
        self.intf = intf
        self.number = intf.bInterfaceNumber

    @property
    def label(self) -> str:
        return (
            f"{self.device.idVendor:04x}:{self.device.idProduct:04x} "
            f"bus {self.device.bus} addr {self.device.address} itf {self.number}"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Interface {self.label}>"


class UsbTransport:
    """Envia e recebe :class:`Message` por uma interface USB."""

    def __init__(self, interface: Interface, timeout_ms: int = 2000):
        self.interface = interface
        self.timeout_ms = timeout_ms
        self.dev = interface.device
        self._ep_in = None
        self._ep_out = None
        self._claimed = False
        self._detached = False
        self._rx = bytearray()
        self.skip_checksum = False

    # -- ciclo de vida ------------------------------------------------------
    def open(self) -> "UsbTransport":
        dev = self.dev
        try:
            if dev.is_kernel_driver_active(self.interface.number):
                dev.detach_kernel_driver(self.interface.number)
                self._detached = True
        except NotImplementedError:
            pass
        try:
            usb.util.claim_interface(dev, self.interface.number)
        except usb.core.USBError as exc:
            self.close()
            raise TransportError(f"claim falhou na interface {self.interface.number}: {exc}") from exc
        self._claimed = True
        for ep in self.interface.intf:
            if usb.util.endpoint_type(ep.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                continue
            if ep.bEndpointAddress & 0x80:
                self._ep_in = ep
            else:
                self._ep_out = ep
        if self._ep_in is None or self._ep_out is None:
            self.close()
            raise TransportError("interface sem endpoints bulk IN/OUT")
        return self

    def close(self) -> None:
        try:
            if self._claimed:
                usb.util.release_interface(self.dev, self.interface.number)
        finally:
            self._claimed = False
            if self._detached:
                self.dev.attach_kernel_driver(self.interface.number)
                self._detached = False
            usb.util.dispose_resources(self.dev)

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    # -- I/O ----------------------------------------------------------------
    def send(self, msg: Message) -> None:
        header, data = msg.encode()
        self.send_raw(header, data)

    def send_raw(self, header: bytes, data: bytes = b"") -> None:
        """Escreve cabeçalho e dados (transferências separadas, como o adbd)."""
        try:
            for part in (header, data):
                if part and self._ep_out.write(part, timeout=self.timeout_ms) != len(part):
                    raise TransportError("escrita USB incompleta")
        except usb.core.USBError as exc:
            raise TransportError(f"falha na escrita USB: {exc}") from exc

    def recv(self, timeout_ms: int | None = None) -> Message:
        """Lê um pacote completo (cabeçalho + dados)."""
        timeout = timeout_ms if timeout_ms is not None else self.timeout_ms
        deadline = time.monotonic() + timeout / 1000.0
        self._fill(HEADER_SIZE, deadline)
        command, arg0, arg1, length, check, _magic = decode_header(bytes(self._rx[:HEADER_SIZE]))
        from . import protocol
        if length > protocol.MAX_PAYLOAD:
            raise TransportError(f"payload USB excede o limite: {length}")
        self._fill(HEADER_SIZE + length, deadline)
        data = bytes(self._rx[HEADER_SIZE:HEADER_SIZE + length])
        del self._rx[:HEADER_SIZE + length]
        if not self.skip_checksum and (sum(data) & 0xFFFFFFFF) != check:
            raise TransportError("checksum USB inválido")
        return Message(command, arg0, arg1, data)

    def _fill(self, size: int, deadline: float) -> None:
        # Preserva cabeçalho/payload parcial entre timeouts e lê múltiplos do
        # tamanho de pacote USB, sem perder bytes caso venham juntos.
        while len(self._rx) < size:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise TransportTimeout("timeout USB")
            packet = self._ep_in.wMaxPacketSize
            request = ((size - len(self._rx) + packet - 1) // packet) * packet
            try:
                chunk = self._ep_in.read(request, timeout=remaining)
            except usb.core.USBTimeoutError as exc:
                raise TransportTimeout("timeout USB") from exc
            except usb.core.USBError as exc:
                raise TransportError(f"falha na leitura USB: {exc}") from exc
            # ZLP é possível no USB bulk e não equivale a EOF.
            self._rx.extend(bytes(chunk))


def find_interfaces(vids=KNOWN_VIDS) -> list[Interface]:
    """Lista as interfaces ff/42/01 e ff/48/01 dos dispositivos conectados."""
    found: list[Interface] = []
    for dev in usb.core.find(find_all=True, custom_match=lambda d: d.idVendor in vids):
        try:
            cfg = dev.get_active_configuration()
        except usb.core.USBError:
            continue
        for intf in cfg:
            if (
                intf.bInterfaceClass == DEBUG_CLASS
                and intf.bInterfaceSubClass in DEBUG_SUBCLASSES
                and intf.bInterfaceProtocol == PROTOCOL
            ):
                found.append(Interface(dev, cfg, intf))
    return found


def describe_devices(vids=KNOWN_VIDS) -> list[str]:
    """Descrição legível de todas as interfaces USB (para o comando ``probe``)."""
    lines = []
    for dev in usb.core.find(find_all=True, custom_match=lambda d: d.idVendor in vids):
        try:
            cfg = dev.get_active_configuration()
        except usb.core.USBError as exc:
            lines.append(f"{dev.idVendor:04x}:{dev.idProduct:04x} erro: {exc}")
            continue
        for intf in cfg:
            try:
                name = usb.util.get_string(dev, intf.iInterface) or ""
            except Exception:
                name = ""
            kind = DEBUG_SUBCLASSES.get(intf.bInterfaceSubClass) if intf.bInterfaceClass == DEBUG_CLASS else None
            marker = f"  <-- {kind.upper()}" if kind and intf.bInterfaceProtocol == PROTOCOL else ""
            lines.append(
                f"{dev.idVendor:04x}:{dev.idProduct:04x} itf{intf.bInterfaceNumber} "
                f"{intf.bInterfaceClass:02x}/{intf.bInterfaceSubClass:02x}/"
                f"{intf.bInterfaceProtocol:02x} {name!r}{marker}"
            )
    return lines
