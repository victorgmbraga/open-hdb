"""API de alto nível: probe, banner, shell e install."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import subprocess

from . import auth, protocol
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


def _adb(serial: str | None, *args: str) -> subprocess.CompletedProcess:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, timeout=20)


def adb_approve_dialog(serial: str | None = None, timeout: float = 8.0) -> bool:
    """Aceita o diálogo "Permitir conexão via HDB?" tocando em OK via uiautomator.

    É o caminho que funciona de fato: o ``service call`` não entrega o argumento
    (marshal do AIDL), então automatizamos o toque.
    """
    import tempfile
    import time as _t
    import xml.etree.ElementTree as ET

    end = _t.monotonic() + timeout
    while _t.monotonic() < end:
        _adb(serial, "shell", "uiautomator", "dump", "/sdcard/openhdb_ui.xml")
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            path = tmp.name
        _adb(serial, "pull", "/sdcard/openhdb_ui.xml", path)
        try:
            root = ET.parse(path).getroot()
        except Exception:
            _t.sleep(0.8)
            continue
        ok = None
        for node in root.iter("node"):
            text = (node.get("text") or "").strip().upper()
            if text in ("OK", "PERMITIR", "ALLOW") and node.get("clickable") == "true":
                ok = node.get("bounds")
                break
        if ok:
            x1, y1, x2, y2 = (int(v) for v in ok.replace("][", ",").strip("[]").split(","))
            _adb(serial, "shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
            _adb(serial, "shell", "rm", "-f", "/sdcard/openhdb_ui.xml")
            return True
        _t.sleep(0.8)
    # fallback: coordenadas proporcionais do diálogo HwUsbDebuggingActivity
    size = _adb(serial, "shell", "wm", "size").stdout.decode(errors="replace")
    try:
        w, h = (int(v) for v in size.split(":")[-1].strip().split("x"))
    except Exception:
        return False
    _adb(serial, "shell", "input", "tap", str(w // 2), str(int(h * 0.60)))   # "Sempre permita"
    _adb(serial, "shell", "input", "tap", str(int(w * 0.65)), str(int(h * 0.67)))  # OK
    return True


def adb_approve(fingerprint: str, serial: str | None = None) -> None:
    """Aprova a chave pendente sem tocar na tela (``hwUsbExService.allowUsbHDB``).

    É o que o HiSuite faz depois que o usuário aceita o diálogo; aqui chamamos
    o serviço Binder direto pelo ADB, usando o fingerprint da chave.
    """
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", "service", "call", "hwUsbExService", "1", "s16", fingerprint]
    subprocess.run(cmd, capture_output=True, timeout=15)
    # fallback: toca o diálogo (o service call não faz o marshal da string)
    adb_approve_dialog(serial)


def clear_keys(serial: str | None = None) -> None:
    """Apaga o store de chaves do HDB (``hwUsbExService.clearUsbHDBKeys``)."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", "service", "call", "hwUsbExService", "3", "s16", "x"]
    subprocess.run(cmd, capture_output=True, timeout=15)


def connect(interface: Interface | None = None, key_path: Path | None = None,
            verbose: bool = False, auth_timeout: float = 20.0,
            approve: bool = False, serial: str | None = None,
            kind: str = "auto") -> HdbConnection:
    """Conecta e autentica na primeira interface que responder, ou na indicada."""
    candidates = [interface] if interface else find_interfaces()
    if kind == "adb":
        candidates = [i for i in candidates if i.intf.bInterfaceSubClass == 0x42]
    elif kind == "hdb":
        candidates = [i for i in candidates if i.intf.bInterfaceSubClass == 0x48]
    else:  # auto: ADB primeiro (é o canal que funciona de ponta a ponta)
        candidates.sort(key=lambda i: 0 if i.intf.bInterfaceSubClass == 0x42 else 1)
    if not candidates:
        raise TransportError("nenhuma interface ADB/HDB encontrada (cabo? settings system hdb_enabled?)")
    last: Exception | None = None
    for tentativa in range(3):
        for intf in candidates:
            try:
                transport = UsbTransport(intf).open()
            except Exception as exc:
                last = exc
                continue
            from .usb import HDB_SUBCLASS
            mode = "sum" if intf.intf.bInterfaceSubClass == HDB_SUBCLASS else "crc32"
            approver = (lambda fp: adb_approve(fp, serial)) if approve else None
            conn = HdbConnection(transport, key_path=key_path, verbose=verbose, checksum=mode,
                                 approve=approver)
            try:
                conn.connect(timeout=auth_timeout)
                return conn
            except Exception as exc:
                last = exc
                conn.transport.close()
        import time as _t

        _t.sleep(1.5)  # dá tempo do adbd liberar o transporte anterior
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

    def pull(self, remote: str, local: Path, timeout: float = 120.0) -> Path:
        """Baixa um arquivo usando ``base64`` no shell (sem o serviço sync)."""
        import base64 as _b64

        out = self.shell(f"base64 {remote}", timeout=timeout)
        if not out.strip():
            raise TransportError(f"arquivo vazio ou inexistente: {remote}")
        data = _b64.b64decode(b"".join(out.split()))
        Path(local).write_bytes(data)
        return Path(local)

    def install(self, apk: Path) -> str:
        """Instala um APK pelo caminho do HDB.

        O ``hdbd`` executa ``pm install --hwhdb <tamanho> <caminho>``; o
        PackageManager valida o APK e devolve ``INSTALL_HDB_VERIFY_FAILED``
        para pacotes sem a assinatura exigida (ver docs/PROTOCOL.md §5).
        """
        apk = Path(apk)
        remote = f"/data/local/tmp/{apk.name}"
        self.push(apk, remote)
        if self.conn.is_hdb:
            # caminho do hdbd: exige verificação Huawei (INSTALL_HDB_VERIFY_FAILED)
            out = self.shell(f"pm install --hwhdb {apk.stat().st_size} {remote}")
        else:
            out = self.shell(f"pm install -r {remote}")
        self.shell(f"rm -f {remote}")
        return out.decode(errors="replace").strip()

    def features(self) -> list[str]:
        return self.conn.features

    def banner(self) -> str:
        return self.conn.banner or ""
