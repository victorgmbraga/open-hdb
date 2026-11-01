"""Transporte USB para HDB.

O ``hdbd`` usa FunctionFS, como o ``adbd``, então a interface se anuncia como
``class=0xff, subclass=0x42, protocol=0x01``. Numa configuração composta da
Huawei (``12d1:107f``) existem várias dessas — este módulo lista todas e deixa o
chamador escolher qual responde com o banner do HDB.

Requer ``pyusb`` e acesso ao nó do dispositivo (udev/ACL).

Atenção: se o ``adb server`` estiver rodando, ele toma a interface e o claim
falha com EBUSY. Rode ``adb kill-server`` antes.
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


class Interface:
    """Uma interface candidata (ff/42/01) de um dispositivo USB."""

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

    # -- ciclo de vida ------------------------------------------------------
    def open(self) -> "UsbTransport":
        dev = self.dev
        cfg = self.interface.config
        usb.util.claim_interface(dev, self.interface.number)
        self._claimed = True
        for ep in self.interface.intf:
            if ep.bEndpointAddress & 0x80:
                self._ep_in = ep
            else:
                self._ep_out = ep
        if self._ep_in is None or self._ep_out is None:
            raise TransportError("interface sem endpoints bulk IN/OUT")
        return self

    def close(self) -> None:
        try:
            if self._claimed:
                usb.util.release_interface(self.dev, self.interface.number)
        finally:
            self._claimed = False

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
        self._ep_out.write(header, timeout=self.timeout_ms)
        if data:
            self._ep_out.write(data, timeout=self.timeout_ms)

    def recv(self, timeout_ms: int | None = None) -> Message:
        """Lê um pacote completo (cabeçalho + dados)."""
        timeout = timeout_ms if timeout_ms is not None else self.timeout_ms
        deadline = time.monotonic() + timeout / 1000.0
        header = self._read_exact(HEADER_SIZE, deadline)
        command, arg0, arg1, length, _crc, _magic = decode_header(header)
        data = self._read_exact(length, deadline) if length else b""
        return Message(command, arg0, arg1, data)

    def _read_exact(self, size: int, deadline: float) -> bytes:
        buf = bytearray()
        while len(buf) < size:
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                raise TransportError(f"timeout lendo {size} bytes (faltam {size - len(buf)})")
            try:
                chunk = self._ep_in.read(size - len(buf), timeout=remaining)
            except usb.core.USBTimeoutError as exc:
                raise TransportError("timeout USB") from exc
            if not chunk:
                raise TransportError("dispositivo fechou a conexão")
            buf.extend(bytes(chunk))
        return bytes(buf)


def find_interfaces(vids=KNOWN_VIDS) -> list[Interface]:
    """Lista todas as interfaces ff/42/01 dos dispositivos conectados."""
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
