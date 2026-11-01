"""Compatibilidade: HDB usa o mesmo amessage de 24 bytes que ADB.

A antiga hipótese de prefixo + struct de 36 bytes não descrevia o fio USB.
Não deve ser usada nem para testes do protocolo real.
"""
from .protocol import HEADER_SIZE, MAX_PAYLOAD, Message, decode_header

HDR_SIZE = HEADER_SIZE
HdbMessage = Message


def decode(raw: bytes) -> tuple[Message, int]:
    command, arg0, arg1, length, check, _magic = decode_header(raw[:HEADER_SIZE])
    if length > MAX_PAYLOAD:
        raise ValueError("payload excede o limite")
    total = HEADER_SIZE + length
    if len(raw) < total:
        raise ValueError("payload incompleto")
    data = raw[HEADER_SIZE:total]
    if (sum(data) & 0xFFFFFFFF) != check:
        raise ValueError("checksum inválido")
    return Message(command, arg0, arg1, data), total
