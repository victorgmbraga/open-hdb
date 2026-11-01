"""API de alto nível: probe, banner, shell e install."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import protocol
from .transport import HdbConnection
from .usb import Interface, TransportError, UsbTransport, find_interfaces


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


def probe(timeout: float = 3.0, verbose: bool = False) -> list[ProbeResult]:
    """Abre cada interface candidata e tenta ler o banner de conexão."""
    results: list[ProbeResult] = []
    for intf in find_interfaces():
        result = ProbeResult(intf)
        try:
            transport = UsbTransport(intf, timeout_ms=int(timeout * 1000)).open()
        except Exception as exc:  # EBUSY, permissão, etc.
            result.error = f"claim falhou: {exc}"
            results.append(result)
            continue
        try:
            from .usb import HDB_SUBCLASS

            if intf.intf.bInterfaceSubClass == HDB_SUBCLASS and not force:
                transport._ep_in.read(transport._ep_in.wMaxPacketSize * 4, timeout=int(timeout * 1000))
                result.banner = None
                result.error = "leitura passiva: nada enviado (HDB exige handshake próprio)"
            else:
                conn = HdbConnection(transport, verbose=verbose)
                result.banner = conn.connect(timeout=timeout)
        except Exception as exc:
            result.error = str(exc)
        finally:
            try:
                transport.close()
            except Exception:
                pass
        results.append(result)
    return results


def connect(interface: Interface | None = None, key_path: Path | None = None,
            verbose: bool = False, auth_timeout: float = 20.0) -> HdbConnection:
    """Conecta e autentica na primeira interface que responder, ou na indicada."""
    candidates = [interface] if interface else find_interfaces()
    if not candidates:
        raise TransportError("nenhuma interface ADB/HDB encontrada (cabo? settings system hdb_enabled?)")
    last: Exception | None = None
    for intf in candidates:
        try:
            transport = UsbTransport(intf).open()
        except Exception as exc:
            last = exc
            continue
        from .usb import HDB_SUBCLASS
        mode = "sum" if intf.intf.bInterfaceSubClass == HDB_SUBCLASS else "crc32"
        conn = HdbConnection(transport, key_path=key_path, verbose=verbose, checksum=mode)
        try:
            conn.connect(timeout=auth_timeout)
            return conn
        except Exception as exc:
            last = exc
            conn.transport.close()
    raise TransportError(f"não consegui conectar: {last}")


class Hdb:
    """Operações sobre uma conexão estabelecida."""

    def __init__(self, conn: HdbConnection):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.conn.close()

    def shell(self, command: str, timeout: float = 20.0) -> bytes:
        """Executa um comando e devolve stdout+stderr."""
        with self.conn.open(f"shell:{command}") as stream:
            chunks: list[bytes] = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data = stream.read(timeout=min(2.0, max(0.2, deadline - time.monotonic())))
                if data is None:
                    break
                chunks.append(data)
            return b"".join(chunks)

    def push(self, local: Path, remote: str, timeout: float = 120.0) -> None:
        """Envia um arquivo por um stream de shell (``cat > destino``)."""
        data = Path(local).read_bytes()
        with self.conn.open(f"shell:cat > {remote}") as stream:
            stream.write(data)
        size = int(self.shell(f"stat -c %s {remote}").strip() or 0)
        if size != len(data):
            raise TransportError(f"upload incompleto: {size} de {len(data)} bytes")

    def install(self, apk: Path) -> str:
        """Instala um APK pelo caminho do HDB.

        O ``hdbd`` executa ``pm install --hwhdb <tamanho> <caminho>``; o
        PackageManager valida o APK e devolve ``INSTALL_HDB_VERIFY_FAILED``
        para pacotes sem a assinatura exigida (ver docs/PROTOCOL.md §5).
        """
        apk = Path(apk)
        remote = f"/data/local/tmp/{apk.name}"
        self.push(apk, remote)
        out = self.shell(f"pm install --hwhdb {apk.stat().st_size} {remote}")
        self.shell(f"rm -f {remote}")
        return out.decode(errors="replace").strip()

    def features(self) -> list[str]:
        return self.conn.features

    def banner(self) -> str:
        return self.conn.banner or ""
