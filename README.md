# open-hdb

Experimental Python client for Huawei Debug Bridge (**HDB**) and Android Debug
Bridge (**ADB**) over USB. It does not invoke `adb`, start an ADB server, use
HiSuite, or automate taps on the device.

**Important:** HDB is not yet a working replacement for HiSuite. USB key
authorization and the Huawei service-authentication challenge work on the tested
tablet; shell, file transfer and installation over HDB remain blocked by an
additional authentication layer that is not implemented yet.

## Current status

| Capability | HDB (`ff/48/01`, default) | ADB (`ff/42/01`, opt-in) |
|---|---|---|
| Interface discovery | Verified | Verified |
| USB RSA authorization / banner | Verified, including reconnection | Previously verified |
| Huawei service-authentication request | Verified: 256-byte encrypted RSA challenge | Not applicable |
| Shell | Rejected with `HDB AUTHENTICEXABORT` | Previously verified |
| Push / pull | Cannot open `sync:` until service auth is implemented | Sync v1 implemented and unit-tested; earlier shell-based transfer was device-tested |
| APK installation | Not validated over HDB | Previously verified using `pm install -r` |

The latest HDB test selected only `ff/48`, with no `adb` executable available in
the process's `PATH`. The tablet exposed both interfaces, but no ADB connection
was used. See [the device-session transcript](docs/HDB_SESSION.md).

Tested hardware: Huawei MatePad T8 KOB2-W09, Android 10,
`10.1.0.212(C605E2R1P2)`. Other devices/firmware are untested.

## Why this exists

The goal is an independent, inspectable HDB client. The device-side `hdbd` is
derived from `adbd`, but sharing the USB packet format does **not** make their
authentication requirements identical. This repository records the protocol
analysis, working USB transport, tests and remaining gaps. It does not claim to
be the only open client or to implement all HiSuite services.

## Install

Requires **Python 3.10+**, **OpenSSL** (the `openssl` executable), **PyUSB** and a
working **libusb** backend. Development/device testing was done on Linux.

```bash
git clone https://github.com/victorgmbraga/open-hdb.git
cd open-hdb
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m openhdb probe
```

Your user needs permission to access the tablet's USB node (udev/ACL on Linux).
Enable HDB in the tablet's settings, unlock its screen and approve the USB key
manually when prompted. This client does **not** require Android's USB debugging
(ADB) setting for the HDB path.

The host's USB authorization key is stored at
`~/.config/open-hdb/hdbkey.pem`. Keep it private and out of version control.
Use `--key PATH` to select another key.

## Usage

```bash
# Descriptors only: no packets sent, no USB interface claimed.
.venv/bin/python -m openhdb probe

# Real HDB USB connection; may require approval on the tablet.
.venv/bin/python -m openhdb banner

# HDB service-authentication diagnostic; requests but does not solve the challenge.
.venv/bin/python -m openhdb auth-info -v

# Currently reports HDB AUTHENTICEXABORT, not a successful shell.
.venv/bin/python -m openhdb shell 'id'

# Explicitly opt into the separate ADB USB protocol, still without the adb program.
.venv/bin/python -m openhdb --kind adb shell 'id'
.venv/bin/python -m openhdb --kind adb push ./file /data/local/tmp/file
.venv/bin/python -m openhdb --kind adb pull /data/local/tmp/file ./download
.venv/bin/python -m openhdb --kind adb install ./app.apk
```

The default is **`--kind hdb`**. `--kind adb` selects ADB; `--kind auto` explicitly
allows either, preferring HDB. A failed connection does not silently fall back to
the other protocol. Use `-s SERIAL` if multiple devices are connected.

Options work before or after the subcommand. `--auth-timeout 120` allows more
time for manual USB approval; `--timeout` controls service/operation timeouts.
`probe --force` actively connects instead of just reading descriptors.

If an ADB server already holds `ff/42`, the explicit ADB mode can fail with
`Resource busy`. The HDB path uses its own interface and does not need to stop or
start that server.

### Migration from the initial prototype

- `--kind hdb` is now the default (the old prototype preferred ADB).
- ADB-based `--auto-approve`, Binder calls and blind coordinate taps were removed.
- CRC32 was incorrect: classic ADB **and HDB** use a byte sum; newer ADB versions
  can negotiate skipping checksum validation.
- The obsolete prefix + 36-byte wire codec was replaced by the real 24-byte codec.
- File transfer now uses binary **sync v1**, rather than `cat`/`base64` shell hacks.
- The documented `push` and `pull` commands actually exist in the CLI now.

## What was discovered

1. **USB:** HDB is `ff/48/01`; ADB is `ff/42/01`. Endpoint addresses/interface
   numbers depend on the active USB configuration, so discovery uses descriptors.
2. **Wire format:** a 24-byte little-endian `amessage` header followed by payload.
   The daemon's 36-byte in-memory structure is not the USB frame.
3. **USB authorization:** Android-style RSA key authorization, with a separate
   `/data/misc/adb/hdb_keys` store. The 20-byte TOKEN is signed as a prehashed
   SHA-1 digest using PKCS#1 v1.5, **not** SHA1(TOKEN). Public keys are Android's
   524-byte blob in base64, with identity and a terminating NUL.
4. **Additional service authentication:** `A_OPEN` messages beginning with
   `HDB ` enter a Huawei control path. `HDB AUTHENTICREQUSET` receives
   `HDB AUTHENTICRES3000` plus 512 hexadecimal characters encoding an encrypted
   RSA challenge. Plain `shell:id` receives `HDB AUTHENTICEXABORT`.
5. **Install verification:** `pm_auth_install` generates an install key, passes it
   to the framework and builds a SHA-256 hash for `--hwhdb`. The earlier test
   `--hwhdb 3901 ...` supplied an invalid hash; its failure does not establish a
   Huawei-only APK-signing requirement.

Earlier revisions incorrectly attributed the service failure to a firmware bug
and claimed root was necessary to repair it. The latest session authenticates
with the existing USB key repeatedly; it exposes the missing second layer.
**No root requirement or firmware defect has been established for this task.**

Detailed evidence, addresses and remaining hypotheses:
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Next steps

- Complete the Huawei service-authentication exchange and command authentication.
  The daemon uses an embedded RSA public key; the corresponding host-side
  cryptographic operation/key source still needs to be understood. An arbitrary
  newly generated USB authorization key is not a demonstrated substitute.
- Compare with a legitimate HiSuite session/host implementation, without assuming
  that USB authorization alone grants access to services.
- Validate shell, sync and installation end-to-end **on HDB**, before claiming
  those capabilities work.

No private/vendor key, proprietary daemon binary, firmware or APK is included.

## Development

```bash
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

The tests run without a tablet. They cover packet checksums/banners, RSA token
signatures, authorization state, HDB control replies, stream lifecycle/timeouts,
partial USB reads, interface selection, CLI parsing and binary sync transfers.
Mocks do not prove that the remaining Huawei authentication works on hardware.

Optional reverse-engineering tools:

```bash
.venv/bin/pip install -e '.[re]'
.venv/bin/python tools/disasm.py /path/to/hdbd hdb_auth_do
```

## Layout

- `openhdb/auth.py`: host RSA keys, prehashed token signature, Android public-key blob.
- `openhdb/protocol.py`: shared 24-byte framing and banner parsing.
- `openhdb/protocol_hdb.py`: compatibility alias/decoder for the same wire format.
- `openhdb/usb.py`: descriptor discovery, claiming, bounded/buffered bulk I/O.
- `openhdb/transport.py`: USB authorization, streams and HDB control exchange.
- `openhdb/sync.py`: binary file sync v1.
- `openhdb/client.py`, `openhdb/cli.py`: API and CLI, with no calls to ADB.
- `tools/`: static-analysis helpers; require a separately supplied device binary.
- `docs/`: protocol analysis and actual HDB-session evidence.
- `tests/`: offline unit tests.

## License

Apache-2.0. No Huawei source code is included. Protocol observations were obtained
from a device owned by the user; third-party binaries used for analysis are not
redistributed here.
