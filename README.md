# open-hdb

Cliente **HDB** (Huawei/HiSuite Debug Bridge) livre, em Python, feito a partir de
engenharia reversa do `hdbd` do dispositivo — sem HiSuite, sem Windows.

> Status: **alpha**.
> - ✅ framing de pacotes (validado contra o `adbd` real: recebemos `A_AUTH/TOKEN`)
> - ✅ transporte USB, descoberta de interfaces, `probe`/`banner`/`shell`
> - ✅ descoberta da interface HDB (`ff/48/01`, ep `04`/`85`)
> - ⚠️ handshake do HDB: pendente — `A_CNXN` faz o dispositivo re-enumerar;
>   o HDB usa o vocabulário `HDB AUTHENTIC*` (ver docs/PROTOCOL.md §3.1)
> - ✅ **cabeçalho real do HDB decodificado: 36 bytes** (`openhdb/protocol_hdb.py`)
> - ⏳ `install` pelo caminho `pm install --hwhdb`
>
> Evidências em [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Por que isso existe

O HDB é o protocolo proprietário que o HiSuite usa para backup/restore, instalar
apps e reparar firmware. Não existe cliente aberto (busca no GitHub: 1 repositório,
apenas binários do Windows). O `hdbd` é um **fork do `adbd`**, então um cliente
aberto é viável — e a única capacidade que ele oferece além do ADB é o
backup/restore de dados de aplicativo.

## O que já sabemos (com evidência)

| fato | evidência |
|---|---|
| `hdbd` é fork do adbd | símbolos `adb.cpp`, `services.cpp`, `shell_service.cpp`, `file_sync_service.cpp` e caminho `vendor/huawei/chipset_common/modules/hwusb/hdb/` no binário |
| banner é `<tipo>::<features>` | strings `%s::%s`, `features=%s`, `parse_banner: %s`, `Connection banner is too long` |
| autenticação própria | `hdb_auth.cpp`, `hdb_auth_do`, `send_hdbauth_failure`, chaves em `/data/misc/adb/hdb_keys` |
| instalação exige verificação Huawei | `pm install --hwhdb <tamanho> <caminho>` → `INSTALL_HDB_VERIFY_FAILED` para APK auto-assinado |
| transporte USB | função FunctionFS separada (`sys.usb.ffs_hdb.ready`), interface `ff/42/01` |

## Uso

```bash
python3 -m venv .venv && .venv/bin/pip install pyusb
adb kill-server                  # o servidor do adb disputa a interface USB
sudo .venv/bin/python -m openhdb probe      # lista interfaces e lê o banner
.venv/bin/python -m openhdb shell 'getprop ro.product.model'
```

## Estrutura

```
openhdb/protocol.py   structs (apacket), constantes A_*, crc32, banner/features
openhdb/usb.py        transporte USB (pyusb), claim/detach, leitura/escrita de pacotes
openhdb/auth.py       chaves RSA, assinatura de token, formato de chave pública
openhdb/transport.py  camada de mensagens sobre o transporte (connect/auth)
openhdb/client.py     máquina de estados (CNXN/AUTH/OPEN/OKAY/WRTE/CLSE)
openhdb/cli.py        probe | banner | shell | install
tools/               scripts de engenharia reversa do hdbd
```

## Licença

Apache-2.0. O projeto não contém código da Huawei; todas as constantes e
formatos documentados aqui foram derivados por análise do binário do próprio
dispositivo.
