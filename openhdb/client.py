"""API USB independente: HDB por padrão, ADB apenas quando solicitado."""
from __future__ import annotations

import shlex
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import usb.core

from . import protocol
from .transport import HdbConnection
from .usb import (ADB_SUBCLASS, HDB_SUBCLASS, Interface, TransportError,
                  TransportTimeout, UsbTransport, find_interfaces)


@dataclass
class ProbeResult:
    interface: Interface
    banner: str | None = None
    error: str | None = None

    @property
    def kind(self) -> str | None:
        return protocol.parse_banner(self.banner)[0] if self.banner else None

    @property
    def features(self) -> list[str]:
        return protocol.parse_banner(self.banner)[1] if self.banner else []


def _candidates(interface=None, kind="hdb", serial=None):
    if kind not in ("hdb", "adb", "auto"):
        raise ValueError(f"transporte inválido: {kind!r}")
    candidates = [interface] if interface is not None else find_interfaces()
    if kind != "auto":
        subclass = HDB_SUBCLASS if kind == "hdb" else ADB_SUBCLASS
        candidates = [i for i in candidates if i.intf.bInterfaceSubClass == subclass]
    if serial:
        candidates = [i for i in candidates if i.device.serial_number == serial]
    return sorted(candidates, key=lambda i: i.intf.bInterfaceSubClass != HDB_SUBCLASS)


def connect(interface: Interface | None = None, key_path: Path | None = None,
            verbose: bool = False, auth_timeout: float = 60.0,
            approve: bool = False, serial: str | None = None,
            kind: str = "hdb") -> HdbConnection:
    """Conecta à interface escolhida; nunca executa ``adb`` ou toca a tela.

    Não troca silenciosamente de protocolo/dispositivo quando a autenticação
    falha. ``kind='auto'`` só é apropriado para descoberta explícita.
    """
    if approve:
        raise ValueError("aprovação por ADB foi removida; aprove manualmente no tablet")
    candidates = _candidates(interface, kind, serial)
    if not candidates:
        raise TransportError(f"nenhuma interface {kind.upper()} encontrada; verifique cabo e configuração USB")
    devices = {(i.device.bus, i.device.address) for i in candidates}
    if len(devices) > 1:
        raise TransportError("mais de um dispositivo; selecione com --serial")
    intf = candidates[0]
    actual_kind = "hdb" if intf.intf.bInterfaceSubClass == HDB_SUBCLASS else "adb"
    transport = UsbTransport(intf)
    try:
        transport.open()
        conn = HdbConnection(transport, key_path=key_path, verbose=verbose,
                             transport_kind=actual_kind)
        conn.connect(timeout=auth_timeout)
        return conn
    except Exception:
        transport.close()
        raise


def probe(timeout: float = 3.0, verbose: bool = False, force: bool = False,
          kind: str = "hdb", serial: str | None = None,
          key_path: Path | None = None) -> list[ProbeResult]:
    """Sem ``force``, apenas lista descritores: não consome pacotes de sessões."""
    results = []
    for intf in _candidates(kind=kind, serial=serial):
        result = ProbeResult(intf)
        if force:
            try:
                with connect(intf, key_path, verbose, timeout, serial=serial, kind=kind) as conn:
                    result.banner = conn.banner
            except (TransportError, usb.core.USBError, ValueError) as exc:
                result.error = str(exc)
        else:
            result.error = "descritores apenas; --force inicia CNXN/AUTH"
        results.append(result)
    return results


class Hdb:
    def __init__(self, conn: HdbConnection):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.conn.close()

    def shell(self, command: str, timeout: float = 20.0) -> bytes:
        """Retorna stdout+stderr do shell legado (sem status de saída remoto)."""
        deadline = time.monotonic() + timeout
        with self.conn.open(f"shell:{command}", timeout=timeout) as stream:
            chunks = []
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportTimeout("comando não terminou dentro do prazo")
                data = stream.read(timeout=remaining)
                if data is None:
                    return b"".join(chunks)
                chunks.append(data)

    def push(self, local: Path, remote: str, timeout: float = 120.0) -> None:
        from .sync import Sync
        with self.conn.open("sync:", timeout=timeout) as stream:
            Sync(stream, timeout).push(Path(local), remote)

    def pull(self, remote: str, local: Path, timeout: float = 120.0) -> Path:
        from .sync import Sync
        with self.conn.open("sync:", timeout=timeout) as stream:
            Sync(stream, timeout).pull(remote, Path(local))
        return Path(local)

    def install(self, apk: Path, timeout: float = 120.0) -> str:
        """Envia por sync e chama pm; o hdbd pode reescrever a instalação.

        Não fabrica ``--hwhdb <tamanho>``: a análise do daemon mostra um hash,
        associado a uma chave de instalação enviada ao framework, não tamanho.
        """
        apk = Path(apk)
        remote = f"/data/local/tmp/openhdb-{uuid.uuid4().hex}.apk"
        self.push(apk, remote, timeout=timeout)
        try:
            out = self.shell(f"pm install -r {shlex.quote(remote)}", timeout=timeout)
            result = out.decode(errors="replace").strip()
            if result != "Success":
                raise TransportError(f"instalação não confirmada: {result}")
            return result
        finally:
            # Não esconder falha original se o transporte cair durante a limpeza.
            try:
                self.shell(f"rm -f {shlex.quote(remote)}", timeout=10)
            except TransportError:
                pass

    def features(self) -> list[str]:
        return self.conn.features

    def banner(self) -> str:
        return self.conn.banner or ""
