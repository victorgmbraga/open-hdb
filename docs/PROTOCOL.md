# HDB protocol — evidence and open questions

Target: Huawei MatePad T8 KOB2-W09, Android 10,
`10.1.0.212(C605E2R1P2)`. Addresses below refer to the stock ARM32/Thumb `hdbd`
analysed locally; that proprietary binary is **not** in this repository.
Thumb symbol values include bit 0; instruction addresses below clear it.
Binary SHA-256: `832d7cc1e8bfb2bd79d35dd4538af353f988aca86b69adf98365c61bd455c031`.

This replaces the initial, contradictory research notes. Claims are separated
into **device-tested**, **static analysis**, and **not yet verified**.

## 1. USB and framing — device-tested and statically confirmed

HDB is a separate FunctionFS function from ADB:

| Interface class/subclass/protocol | Description | Daemon |
|---|---|---|
| `ff/48/01` | HDB Interface | `hdbd` |
| `ff/42/01` | ADB Interface | `adbd` |

Observed composite VID/PID: `12d1:107f`. With both protocols enabled, HDB was
interface 3, OUT `0x04` / IN `0x85`; with only HDB, it was interface 2. Do not
hardcode the interface number or endpoints. Use descriptor discovery.

HDB's FunctionFS paths in the daemon are `/dev/usb-ffs/hdb/ep0`, `ep1`, `ep2`.
The daemon includes paths under
`vendor/huawei/chipset_common/modules/hwusb/hdb/` and is derived from ADB.

The wire header is **24 bytes**, not 36 or 40:

```c
struct amessage {
    uint32_t command;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_check;
    uint32_t magic;       // command ^ 0xffffffff
};
// followed by data_length bytes
```

All fields are little-endian. Commands are ASCII packed as little-endian words:
`CNXN`, `AUTH`, `OPEN`, `OKAY`, `WRTE`, `CLSE`.

The daemon's `apacket` has 12 bytes of internal metadata before `amessage`, with
payload at internal offset `0x24`. In `remote_read` at `0x5b4c4`,
`movs r2,#0x18; add r1,r4,#0xc; bl usb_read` reads only the 24-byte message
header. `get_apacket` at `0x4fa74` allocates the larger internal structure.

`calculate_apacket_checksum` at `0x4fa58` **sums payload bytes** modulo 2^32.
Classic ADB also uses a sum, despite the historical field name `data_crc32`.
ADB protocol version `0x01000001` can skip checksum checking; the HDB device
advertises `0x01000000`, so this client uses sums throughout HDB sessions.

Malformed CRC32/36-byte/40-byte probes in the initial research sometimes caused
USB errors/re-enumeration. They do not establish a different protocol prefix,
missing preamble, daemon crash or need for root. The obsolete codec was removed.

## 2. First layer: USB key authorization — device-tested

A known host key now authenticates with this sequence:

```text
host   -> device  CNXN(version=0x01000000, max_payload=262144)
                  "host::features=;\0"
device -> host    AUTH(TOKEN=1), 20 bytes
host   -> device  AUTH(SIGNATURE=2), 256 bytes
device -> host    CNXN(version=0x01000000, max_payload=262144), banner
```

The 20-byte TOKEN is passed directly to RSA PKCS#1 v1.5 / SHA-1 signing as a
**prehashed digest**, matching the daemon's
`RSA_verify(NID_sha1, token, 20, signature, ..., key)` call in
`adbd_auth_verify` (`0x5b7ec`, call at `0x5baca`).

The initial client incorrectly used `openssl dgst -sha1 -sign`, signing
SHA1(TOKEN) instead. The corrected command is:

```text
openssl pkeyutl -sign -inkey host.pem \
    -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt digest:sha1
```

For an unknown key, another TOKEN after the first signature makes the host send
`AUTH(RSAPUBLICKEY=3)`. A device-originated AUTH type 3 is **not** required by
this flow. The public-key payload is:

```text
base64(Android RSAPublicKey blob) + " user@host" + NUL
```

The blob is 524 bytes: `uint32 len=64`, `n0inv`, 256-byte little-endian modulus,
256-byte little-endian R² mod n, `uint32 exponent`. Without NUL, the daemon was
observed logging `Key must be a null-terminated string`.

Manual approval uses `com.android.systemui/.usb.HwUsbDebuggingActivity`.
Authorized HDB keys are separate from ADB keys:
`/data/misc/adb/hdb_keys`, versus `/data/misc/adb/adb_keys`.

Older experiments logged `Invalid base64 key` while reading the HDB key file.
Its cause was **not established**: empty/trailing lines, malformed experimental
Binder approvals and the old client are all relevant possibilities. A log of an
invalid line does not show that all keys are unusable. The new client reconnects
successfully with the existing key, without clearing or modifying that store.

There is no demonstrated requirement for root, rewriting `hdb_keys`, `_settle_auth`
or repeated CNXN/OPEN retries. The current client returns after CNXN and surfaces
a later AUTH restart as an error, rather than swallowing it.

### Banner

Observed (without trailing NUL):

```text
device::ro.product.name=KOB2-W09;ro.product.model=KOB2-W09;ro.product.device=HWKOB2;features=stat_v2,cmd,shell_v2
```

Parse semicolon-separated properties, then the comma-separated `features=`
value. Product properties are not feature names. The banner type is `device`,
not `hdb`. Features advertised by the daemon do not mean that the host has passed
the second authentication layer.

### Binder observations — historical only, not a client dependency

Earlier device experiments identified `hwUsbExService`, interface
`huawei.android.hardware.usb.IHwUsbManagerEx`:

| Transaction | Interpreted method | Confidence |
|---|---|---|
| 1 | `allowUsbHDB` | Method/log mapping; argument marshalling not established |
| 2 | `denyUsbHDB` | Preliminary mapping |
| 3 | `clearUsbHDBKeys` | Key-file deletion observed in logs |
| 4 | `setHdbEnabled` | Preliminary mapping |

The previous `service call ... 1 s16 <fingerprint>` did **not** demonstrate a
correct approval call. No full AIDL signature is claimed here. Those calls and
ADB/uiautomator approval fallbacks were removed from the client. User approval
is manual; the client neither deletes keys nor changes USB settings.

## 3. Second layer: Huawei service authentication

### 3.1 Newly device-tested behavior

After a successful USB authorization/banner, plain service opening fails:

```text
host   -> device  OPEN(local_id=1, remote_id=0), "shell:id\0"
device -> host    OPEN(arg0=1, arg1=0), "HDB AUTHENTICEXABORT\0"
```

This is **not** an `OKAY`/`CLSE` stream reply. The old client ignored it and
reported a timeout, leading to an incorrect diagnosis.

Control requests beginning with `HDB ` use `A_OPEN` directly:

```text
host   -> device  OPEN(local_id=2, remote_id=0), "HDB AUTHENTICREQUSET\0"
device -> host    OPEN(arg0=2, arg1=0),
                  "HDB AUTHENTICRES3000" + 512 hex characters
```

The misspelling `REQUSET` is present in the daemon. Each text prefix above is
20 bytes, excluding NUL. The response contains 256 bytes of RSA ciphertext,
not the first layer's 20-byte TOKEN. Its reported data_length was 532, excluding
the NUL that the daemon writes after its payload.

`python -m openhdb auth-info` performs only this verified diagnostic. It does
not claim to authenticate services. See [HDB_SESSION.md](HDB_SESSION.md).

### 3.2 Static control flow

In `handle_packet` (`0x50658`):

- `0x506b6`: ordinary OPEN requires the transport's online flag.
- `0x506e8..0x506f2`: compares the first four payload bytes with `"HDB "`.
- `0x50a9c..0x50aa0`: HDB control payloads enter `hdb_auth` (`0x478e4`).
- `0x50700`: other OPEN payloads enter `hdb_auth_do` (`0x47720`).
- Only a successful check reaches `create_local_service_socket` (`0x5070e`).

Thus a successful USB key exchange does not by itself authorize `shell:` or
`sync:`.

Relevant functions:

| Function | Address | Evidence |
|---|---|---|
| `send_auth_respone` [sic] | `0x473d8` | generates 20 random bytes; calls RSA_public_encrypt with PKCS#1 padding; hex-encodes 256 output bytes after RES3000 |
| `hdb_auth` | `0x478e4` | dispatches REQUSET/PCIDENT; RSA_public_decrypt and SHA-256 validation; builds CONFIRM/EXABORT replies |
| `hdb_auth_do` | `0x47720` | checks a session slot, counter/replay state and a SHA-256 command authenticator |
| `send_hdbauth_failure` | `0x47624` | replaces payload with AUTHENTICEXABORT, sends the packet back |

The daemon contains an Android-format RSA public key in `rsa_pub` (`0x111000`),
and a runtime RSA pointer `g_RSA_PubKey` (`0x11992c`). `init()` (`0x47070`)
reads `rsa_pub`, decodes the 524-byte blob and passes `&g_RSA_PubKey` to
`android_pubkey_decode` at `0x470b6`. This confirms that the additional crypto
uses the embedded key, separate from the user-approved host USB key. No matching
private key has been established or included in the project.

### 3.3 Partial reconstruction — not validated end-to-end

The following describes static analysis, **not a completed implementation**:

1. REQUSET produces an RSA-encrypted 20-byte device nonce.
2. PCIDENT includes a 40-hex-character client nonce at payload offset 20, then
   a 512-hex-character RSA block at payload offset 61.
3. `RSA_public_decrypt(..., RSA_PKCS1_PADDING)` recovers data whose first 20 bytes
   are used with the device nonce in a SHA-256 calculation. The digest is compared
   with recovered bytes at offset 20. Success produces CONFIRM and session state.
4. CONFIRM includes a space and a session-slot character. Session state contains
   nonce-derived SHA-256 material and replay/counter bookkeeping.
5. `hdb_auth_do` rejects short unauthenticated commands and expects a suffix with
   slot information, a 64-hex-character SHA-256 value and an 8-character counter.
   The digest includes a bounded command prefix, counter and session secret.

The exact encoding, key provenance, host-side private operation, session lifecycle
and signed-command construction still require corroboration with a legitimate
host implementation/session. Generating an arbitrary RSA key is not evidence that
this fixed-key exchange can be completed. No claim of a bypass is made.

## 4. Installation: previous assumption corrected

In `service_to_fd` (`0x48b90`), a `shell` request beginning with `:pm install`
is routed through `pm_auth_install` (`0x47198`, call at `0x4914a`).

Static flow in `pm_auth_install`:

- `0x471f6`: generates a 32-byte random install key.
- `0x47202..0x47222`: encodes it as 64 hexadecimal characters.
- `0x47236`: sends that key to the framework through `hdbd_send_install_key`.
- `0x47250`: formats a string containing original install arguments and the key.
- `0x4725e..0x47276`: SHA-256 of that string.
- `0x4727c..0x47296`: hex-encodes the digest.
- `0x472b0`: builds `:pm install --hwhdb %s %s`, where the first substitution is
  the **hexadecimal digest**, not the APK size.

The earlier command:

```text
pm install --hwhdb 3901 /data/local/tmp/hello-hdb.apk
```

failed with `INSTALL_HDB_VERIFY_FAILED`, but `3901` was not a valid authentication
hash. This experiment cannot determine which APK signatures are accepted, nor
prove that a self-signed Hello World is impossible to install by HDB. Correct
installation still needs service authentication plus the daemon/framework flow.

The current client no longer invents `--hwhdb <file_size>`. It uploads via sync
and issues an ordinary `pm install -r ...`; the daemon's own rewriting path, if
reached, must be evaluated on hardware. That operation is **not HDB-validated**.
Previous successful Hello World installations used the **ADB USB interface**.

## 5. Implementation scope and next work

Implemented without the ADB executable or ADB USB channel:

- strict HDB descriptor selection (default), serial filtering and safe claiming;
- byte-sum framing, bounded/buffered reads preserving data across timeouts;
- correct prehashed USB RSA authorization and manual key approval;
- explicit error for Huawei control responses instead of retrying/ignoring them;
- diagnostic REQUSET/RES3000 exchange;
- shared stream and binary sync v1 code, tested offline but still gated on HDB.

Open work:

- identify the legitimate host-side cryptographic material/operation for PCIDENT;
- validate CONFIRM and command suffixes rather than guessing keys or padding;
- validate HDB shell, sync push/pull and `pm_auth_install` end-to-end;
- map the real Binder AIDL only if needed for documentation, not as an ADB crutch;
- expand coverage across devices/firmware, USB permissions and disconnect cases.

Root, bootloader unlocking, key-file editing and APK-signing restrictions are
**not established prerequisites** for finishing this client.
