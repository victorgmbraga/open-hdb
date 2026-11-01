"""File sync v1 (SEND/RECV), compartilhado por ADB e o fork HDB.

Não usa shell, base64, comandos externos ou arquivos inteiros em memória.
"""
from __future__ import annotations

import os
import struct
import tempfile
import time
from pathlib import Path

from .usb import TransportError, TransportTimeout

HEADER = struct.Struct("<4sI")
MAX_DATA = 64 * 1024


class Sync:
    def __init__(self, stream, timeout: float = 120.0):
        self.stream = stream
        self.deadline = time.monotonic() + timeout
        self.buffer = bytearray()

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TransportTimeout("timeout de file sync")
        return remaining

    def _read(self, size):
        while len(self.buffer) < size:
            chunk = self.stream.read(timeout=self._remaining())
            if chunk is None:
                raise TransportError("stream sync fechado antes de terminar")
            self.buffer.extend(chunk)
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def _send(self, command, data=b"", value=None):
        self.stream.write(HEADER.pack(command, len(data) if value is None else value) + data,
                          timeout=self._remaining())

    def _header(self):
        command, size = HEADER.unpack(self._read(HEADER.size))
        if command == b"FAIL":
            if size > MAX_DATA:
                raise TransportError("FAIL sync excede o limite")
            raise TransportError(self._read(size).decode(errors="replace"))
        return command, size

    @staticmethod
    def _path(remote):
        raw = remote.encode()
        if not raw or b"\0" in raw or len(raw) > 1024:
            raise ValueError("caminho sync vazio, longo ou contendo NUL")
        return raw

    def push(self, local: Path, remote: str):
        target = self._path(remote) + b",33206"  # S_IFREG | 0666
        if len(target) > 1024:
            raise ValueError("caminho SEND excede 1024 bytes")
        with local.open("rb") as source:
            self._send(b"SEND", target)
            while chunk := source.read(MAX_DATA):
                self._send(b"DATA", chunk)
            mtime = int(os.fstat(source.fileno()).st_mtime) & 0xFFFFFFFF
            self._send(b"DONE", value=mtime)
        if self._header() != (b"OKAY", 0):
            raise TransportError("resposta SEND inesperada")

    def pull(self, remote: str, local: Path):
        self._send(b"RECV", self._path(remote))
        # Substitui o destino só depois de DONE; preserva arquivo anterior em falha.
        name = None
        try:
            with tempfile.NamedTemporaryFile(dir=local.parent, delete=False) as output:
                name = output.name
                while True:
                    command, size = self._header()
                    if command == b"DONE":
                        if size != 0:
                            raise TransportError("DONE RECV inválido")
                        break
                    if command != b"DATA" or size > MAX_DATA:
                        raise TransportError("resposta RECV inválida ou grande demais")
                    output.write(self._read(size))
            os.replace(name, local)
        finally:
            if name and os.path.exists(name):
                os.unlink(name)
