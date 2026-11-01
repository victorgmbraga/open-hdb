#!/usr/bin/env python3
"""Testa variantes de handshake na interface HDB, recuperando o USB entre elas.

Cada tentativa pode derrubar a porta (o hdbd re-enumera); o script espera o
dispositivo voltar antes de seguir. Uso:
    python tools/try_handshake.py itf3
"""
from __future__ import annotations

import struct
import sys
import time
import zlib

import usb.core
import usb.util

VID, PID = 0x12D1, 0x107F
A_AUTH, A_CNXN, A_OPEN = 0x48545541, 0x4E584E43, 0x4E45504F


def packet(cmd, a0, a1, data=b""):
    return struct.pack("<6I", cmd, a0, a1, len(data), zlib.crc32(data) & 0xFFFFFFFF,
                       cmd ^ 0xFFFFFFFF) + data


def wait_device(timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        d = usb.core.find(idVendor=VID, idProduct=PID)
        if d is not None:
            try:
                d.get_active_configuration()
                return d
            except usb.core.USBError:
                pass
        time.sleep(0.2)
    return None


def attempt(dev, itf_no, label, frames):
    cfg = dev.get_active_configuration()
    intf = [i for i in cfg if i.bInterfaceNumber == itf_no][0]
    try:
        usb.util.claim_interface(dev, itf_no)
    except Exception as e:
        print(f"  [{label}] claim falhou: {e}")
        return "claim"
    epi = [e for e in intf if e.bEndpointAddress & 0x80][0]
    epo = [e for e in intf if not (e.bEndpointAddress & 0x80)][0]
    try:
        for kind, payload in frames:
            if kind == "raw":
                epo.write(payload, timeout=1500)
            else:
                epo.write(packet(*payload), timeout=1500)
            try:
                r = bytes(epi.read(epi.wMaxPacketSize * 8, timeout=1500))
                print(f"  [{label}] <- {len(r)}B {r[:64]!r}")
                return r
            except usb.core.USBError as e:
                print(f"  [{label}] read errno={e.errno}")
        return "sem-resposta"
    except usb.core.USBError as e:
        print(f"  [{label}] write errno={e.errno} (dispositivo resetou?)")
        return "reset"
    finally:
        try:
            usb.util.release_interface(dev, itf_no)
        except Exception:
            pass


VARIANTS = {
    "texto-pcident\\n": [("raw", b"HDB AUTHENTICPCIDENT\n")],
    "texto-pcident\\0": [("raw", b"HDB AUTHENTICPCIDENT\0")],
    "auth0-pcident": [("pkt", (A_AUTH, 0, 0, b"HDB AUTHENTICPCIDENT"))],
    "auth0-pcident\\0": [("pkt", (A_AUTH, 0, 0, b"HDB AUTHENTICPCIDENT\0"))],
    "auth3-nome": [("pkt", (A_AUTH, 3, 0, b"HDB AUTHENTICPCIDENT"))],
    "cnxn-hdb": [("pkt", (A_CNXN, 0x01000001, 256 * 1024, b"hdb::"))],
    "open-pcident": [("pkt", (A_OPEN, 1, 0, b"HDB AUTHENTICPCIDENT\0"))],
}


def main():
    itf = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    names = sys.argv[2:] or list(VARIANTS)
    for name in names:
        dev = wait_device()
        if dev is None:
            print(f"[{name}] dispositivo ausente, abortando")
            return 1
        print(f"[{name}]")
        attempt(dev, itf, name, VARIANTS[name])
        time.sleep(2.5)
    print("fim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
