# open-hdb

A dependency-light Python client that talks to Android/Huawei devices **directly over USB**,
without `adb`, without `adb server` and without HiSuite.

It implements two transports:

| transport | USB interface | status |
|---|---|---|
| **ADB** (Android Debug Bridge) | `ff/42/01` "ADB Interface" | **works end-to-end**: banner, shell, push, pull, install |
| **HDB** (Huawei Debug Bridge) | `ff/48/01` "HDB Interface" | protocol implemented/documented; auth + banner work |

```console
$ python -m openhdb shell "id -un; getprop ro.product.model"
shell
KOB2-W09

$ python -m openhdb install hello.apk
Success

$ python -m openhdb pull /data/local/tmp/x ./x
$ python -m openhdb --kind hdb banner
banner : device::ro.product.name=KOB2-W09;...features=stat_v2,cmd,shell_v2
```

## Why

HDB is the proprietary protocol HiSuite uses to back up app data, install packages and
repair firmware. It has **no open-source client** (GitHub search returns one repository,
containing only Windows binaries). The device-side daemon `hdbd` turns out to be a *fork
of `adbd`*, so an open client is feasible — and while reverse engineering it we ended up
with a complete, independent ADB implementation as well.

## Install

```bash
git clone https://github.com/<user>/open-hdb
cd open-hdb
python3 -m venv .venv
.venv/bin/pip install pyusb
.venv/bin/python -m openhdb probe
```

Requires Python ≥ 3.10 and `pyusb`. Linux/macOS need udev/ACL access to the USB node.
If the `adb server` is running it holds the ADB interface — stop it (`adb kill-server`)
or use `--kind hdb`.

On the first connection the device shows its authorization dialog
(*"Allow USB debugging?"* / *"Allow HDB connection?"*). Approve it manually; the key is
stored on the device and reused afterwards.

## Usage

```
python -m openhdb probe [--force]        # list interfaces, read banner
python -m openhdb banner                 # banner, protocol version, features
python -m openhdb shell "<command>"      # run a command, print its output
python -m openhdb install <apk>          # push + pm install
python -m openhdb pull <remote> <local>  # download a file
```

Global options: `--kind auto|adb|hdb`, `-s/--serial`, `-v/--verbose` (packet trace),
`--auto-approve` (accept the on-device dialog through ADB instead of tapping it).

## How it works

`openhdb/protocol.py` implements the ADB packet format: a 24-byte little-endian header
(`command, arg0, arg1, data_length, data_check, magic`) followed by the payload, with
`magic = ~command`. Authentication follows the ADB flow: the device sends an
`A_AUTH/TOKEN` nonce, the client answers with a PKCS#1 v1.5 / SHA-1 signature, and if the
key is unknown the device asks for `A_AUTH/RSAPUBLICKEY` (an `RSAPublicKey` blob encoded
in base64, NUL-terminated), then prompts the user.

`openhdb/usb.py` is a small pyusb transport; `openhdb/transport.py` multiplexes streams
(`A_OPEN`/`A_OKAY`/`A_WRTE`/`A_CLSE`) and `openhdb/client.py` exposes the high-level API.

### HDB specifics

The Huawei fork differs from ADB in three ways (all verified on a MatePad T8 /
KOB2-W09, Android 10, and by disassembling the stock `hdbd`):

1. **Interface**: `ff/48/01` ("HDB Interface", bulk endpoints `0x04`/`0x85`) — ADB uses
   subclass `0x42`. Both can be present at the same time.
2. **Checksum**: `calculate_apacket_checksum` sums the payload bytes instead of using
   CRC32. The in-memory packet struct is 36 bytes, but only the classic **24-byte header
   travels on the wire** (proved in `remote_read`: it reads `0x18` bytes into
   `packet + 0x0c`).
3. **Key store**: authorized keys live in `/data/misc/adb/hdb_keys`, written by the
   framework (`HwUsbHDBManager`), not by `adbd`.

`docs/PROTOCOL.md` documents the packet layout, the authentication sequence, the
`hwUsbExService` binder service (`allowUsbHDB`, `denyUsbHDB`, `clearUsbHDBKeys`,
`setHdbEnabled`) and the known firmware bug that prevents persistent HDB authorization.

## Known limitations

* HDB streams do not open on the tested firmware: `hdbd` reloads `hdb_keys` on every
  `A_AUTH`, finds an invalid line written by the framework and restarts authentication,
  so `A_OPEN` is ignored. Clearing the file requires root. Details in
  `docs/PROTOCOL.md §2.2`.
* Even with a working stream, HDB package installation runs
  `pm install --hwhdb <size> <path>`, which enforces Huawei signature verification:
  self-signed APKs fail with `INSTALL_HDB_VERIFY_FAILED`. Install through the ADB
  transport instead.
* Tested on one device (Huawei KOB2-W09). Other Huawei/MediaTek devices should work but
  are untested.

## Repository layout

```
openhdb/protocol.py      ADB packet format, commands, banner parsing
openhdb/protocol_hdb.py  HDB (36-byte) packet layout, byte-sum checksum
openhdb/usb.py           pyusb transport + interface discovery
openhdb/auth.py          RSA keys, token signing, Android public-key blob
openhdb/transport.py     CNXN + authentication + stream multiplexing
openhdb/client.py        probe / banner / shell / push / pull / install
openhdb/cli.py           command line entry point
tools/                   disassembly / cross-reference helpers used for the RE
docs/PROTOCOL.md         everything discovered about HDB
tests/                   unit tests for the packet formats
```

`tools/disasm.py`, `tools/xref.py` and `tools/re_hdbd.py` are the scripts used to
disassemble `hdbd` (ARM/Thumb, via capstone) and to map strings to code — they are kept
in the repository because they document *how* the protocol facts were obtained.

## License

Apache-2.0. No Huawei code is included; all protocol details were derived by analysing
the binary shipped on a device the author owns.
