# Verified HDB-only USB sessions

Device: KOB2-W09, Android 10, build `10.1.0.212(C605E2R1P2)`.

## Conditions

- The tablet exposed HDB (`ff/48/01`) and ADB (`ff/42/01`).
- Only HDB was selected and claimed; no request was sent to the ADB interface.
- `adb` was absent from the test process's PATH. It contained only a temporary
  symlink to OpenSSL, for the host RSA operation.
- A guard on `subprocess.run` rejected every command except `openssl`.
- The existing USB key was reused. No key deletion, Binder calls, UI automation,
  USB-setting changes, root or bootloader operations were performed.

This proves use of HDB without relying on ADB in that test. It does **not** claim
that the tablet's ADB function was disabled during these particular sessions.

## First session (trace)

```text
>> CNXN arg0=16777216 arg1=262144 len=17
<< AUTH TOKEN arg0=1 arg1=0 len=20
>> AUTH SIGNATURE arg0=2 arg1=0 len=256
<< CNXN arg0=16777216 arg1=262144 len=113

banner:
device::ro.product.name=KOB2-W09;ro.product.model=KOB2-W09;ro.product.device=HWKOB2;features=stat_v2,cmd,shell_v2

>> OPEN arg0=1 arg1=0 len=24       # shell:id; echo HDB-ONLY + NUL
<< OPEN arg0=1 arg1=0 len=20       # HDB AUTHENTICEXABORT

ServiceAuthRequired: autorização USB não basta; a autenticação Huawei de
serviços ainda não foi implementada

>> OPEN arg0=2 arg1=0 len=21       # HDB AUTHENTICREQUSET + NUL
<< OPEN arg0=2 arg1=0 len=532      # HDB AUTHENTICRES3000 + 512 hex characters

Decoded challenge length: 256 RSA-encrypted bytes
```

The random ciphertext is omitted: only its validated encoding and length are
relevant here. It is not a plaintext nonce or reusable host credential.

## Reconnection

After closing the USB handle and waiting two seconds, another session completed:

```text
>> CNXN
<< AUTH TOKEN                    # new 20-byte token
>> AUTH SIGNATURE
<< CNXN                          # same device banner
>> OPEN HDB AUTHENTICREQUSET
<< OPEN HDB AUTHENTICRES3000...   # fresh 256-byte encrypted challenge
```

Across these two sessions, the external-call guard recorded exactly:

```text
['openssl', 'openssl']
```

Both private-key operations authenticated the first USB layer. No ADB process was
used. The known key did not require another user approval.

## Reproduce

After installing the project (`pip install -e .`), with the tablet connected:

```bash
python tools/check_hdb_independent.py
```

Or inspect just the newly supported control exchange:

```console
$ python -m openhdb auth-info -v
Autorização USB HDB: aceita
Controle de serviços: HDB AUTHENTICRES3000
Desafio RSA: 256 bytes (cifrado; não é o TOKEN USB)
A segunda autenticação Huawei ainda não está implementada.
```

`auth-info` success means a valid challenge was received, **not** that shell or
installation works. `python -m openhdb shell id` currently exits nonzero with an
explicit `HDB AUTHENTICEXABORT` diagnostic.

## Conclusions and limits

- **Verified:** persistent USB key authorization, real HDB banner and Huawei
  challenge request, independent of ADB executable/channel.
- **Identified:** a distinct service-authentication gate in `hdb_auth_do`.
- **Not completed:** PCIDENT/CONFIRM exchange, authenticated service commands,
  HDB shell, HDB file transfer or HDB APK installation.
- The earlier assertion that root/key-file repair would free shell access is
  unsupported and is superseded by this result.
