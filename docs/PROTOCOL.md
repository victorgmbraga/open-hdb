# Protocolo HDB — notas de engenharia reversa

Este documento registra o que foi **verificado** no `hdbd` (KOB2-W09,
`10.1.0.212(C605E2R1P2)`, Android 10) e o que ainda é hipótese.

## 1. Parentesco com o ADB

`hdbd` é um fork do `adbd`. Evidências diretas no binário:

```
vendor/huawei/chipset_common/modules/hwusb/hdb/adb.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/adb_io.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/adb_trace.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/adb_utils.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/daemon/main.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/daemon/usb.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/fdevent.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/file_sync_service.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/hdb_auth.cpp      <- exclusivo
vendor/huawei/chipset_common/modules/hwusb/hdb/jdwp_service.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/services.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/shell_service.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/sockets.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/transport.cpp
vendor/huawei/chipset_common/modules/hwusb/hdb/transport_usb.cpp
```

Consequência: o framing de pacotes, os serviços (`shell:`, `sync:`, `jdwp`) e a
semântica de streams são os do ADB. O que muda é autenticação, banner e o
"install" via `pm`.

## 2. Framing de pacote (APACKET)

24 bytes de cabeçalho, little-endian, seguidos de `data_length` bytes de dados:

```c
struct amessage {
    uint32_t command;      /* A_* */
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_crc32;   /* crc32 dos dados (0 para A_CNXN/A_AUTH) */
    uint32_t magic;        /* command ^ 0xffffffff */
};
```

Constantes (valores do ADB, herdados pelo fork):

| nome | valor | uso |
|---|---|---|
| `A_SYNC`  | `0x434e5953` | ressincronização de stream |
| `A_CNXN`  | `0x4e584e43` | connect + banner/versão |
| `A_OPEN`  | `0x4e45504f` | abre stream (`"shell:..."`, `"sync:"`) |
| `A_OKAY`  | `0x59414b4f` | confirma stream |
| `A_CLSE`  | `0x45534c43` | fecha stream |
| `A_WRTE`  | `0x45545257` | dados do stream |
| `A_AUTH`  | `0x48545541` | autenticação |

(Os valores são o ASCII — `"CNXN"`, `"OPEN"`... — lido como `uint32` little-endian.)

## 2.1 Cabeçalho real do HDB: 36 bytes (não 24)

Desmontando `hdbd` (Thumb, símbolos não removidos) o layout do `apacket` do HDB
é **maior** que o do adb:

```
offset  tamanho  campo
0x00    4        prefixo de quadro (read_packet/write_packet tratam separado)
0x04    4        desconhecido
0x08    4        desconhecido
0x0c    4        command
0x10    4        arg0
0x14    4        arg1
0x18    4        data_length
0x1c    4        data_check   (calculate_apacket_checksum)
0x20    4        magic        (= ~command)
0x24    ...      data
```

Evidências (endereços no binário do KOB2-W09):

| função | instruções |
|---|---|
| `check_header` @0x59445 | `ldr r0,[r6,#0xc]` / `ldr r1,[r6,#0x20]` / `mvns r0,r0; cmp r1,r0` / `ldr r0,[r5,#0xa0]` (max_payload) / `ldr r1,[r6,#0x18]` |
| `send_packet` @0x57fd1 | `ldr r0,[r5,#0xc]; mvns r0,r0; str r0,[r5,#0x20]` e `str r0,[r5,#0x1c]` (checksum) |
| `handle_packet` @0x50659 | lê comando de `[r4,#0xc]`, compara com `0x48545541` (A_AUTH) e `0x4e45504f` (A_OPEN), payload em `r4+0x24` |
| `check_data` @0x59575 | compara `calculate_apacket_checksum` com `[r4,#0x1c]` |
| `calculate_apacket_checksum` @0x4fa59 | **soma de bytes** (`ldrb; add; bne`), não CRC32 |
| `get_apacket` @0x4fa75 | `malloc(36 + 0x80000)`, zera 0x00–0x2f → payload máx. **512 KB** |
| `send_connect` @0x4fe35 | `get_apacket`; `str cmd,[r5,#0xc]`; arg0 `[r5,#0x10]`; arg1 `[r5,#0x14]`; banner em `r5+0x24`; `str len,[r5,#0x18]` — **nada em 0x00–0x0b** |

Caminhos usados pela função USB (FunctionFS):

```
/dev/usb-ffs/hdb/ep0   (controle)
/dev/usb-ffs/hdb/ep1   (bulk)
/dev/usb-ffs/hdb/ep2   (bulk)
```

Implementação: `openhdb/protocol_hdb.py` (`HdbMessage`), com testes em
`tests/test_protocol.py`.

### Resultado empírico das tentativas de handshake

| tentativa na interface `ff/48/01` | resultado |
|---|---|
| leitura passiva (sem escrever) | timeout (dispositivo não fala primeiro) |
| texto puro `HDB AUTHENTICPCIDENT\n` | aceito, sem resposta |
| APACKET de 24 bytes (`A_CNXN`, `A_AUTH`…) | **EIO** + re-enumeração do USB |
| prefixo 4B + cabeçalho 36B (`A_CNXN`, `A_AUTH`+texto), prefixo ∈ {0,1,0x24,'HDBS','HDSH'} | **EIO** + re-enumeração |
| prefixo = tamanho total do quadro | EIO + re-enumeração |
| quadro completo de 512 bytes (padding) | EIO + re-enumeração |
| escrita em 2 partes (4B, depois 36B) | EIO + re-enumeração |
| **ler a interface nova após a re-enumeração** | timeout — não há resposta pendente |

Detalhe importante: o `write` é **aceito** e o erro aparece na `read`
(`EIO`/`ENODEV`) — o USB re-enumera, mas o `hdbd` **não crasha** (pid estável).
A interface nova não traz dados, então a sessão não continua. Falta descobrir o
que o `hdbd` espera antes do primeiro quadro (tamanho de leitura? passo de
inicialização?) — próximo passo dinâmico: *usbmon* de uma sessão real.

Conclusão: o `hdbd` rejeita o quadro antes de qualquer autenticação — falta
descobrir a semântica do prefixo de 4 bytes (ou um passo de inicialização
anterior a ele).

## 3. Banner

Formato confirmado pelas strings `%s::%s`, `features=%s`, `parse_banner: %s`:

```
<tipo>::<feature>,<feature>,...
```

O binário contém as strings `adb` e `hdb` separadas, e a propriedade
`adb_device_banner` / `device_banner`. **Hipótese a confirmar**: o tipo do banner
é `hdb` (contra `device` no adbd puro). A ferramenta `openhdb probe` imprime o
banner bruto para resolver isso empiricamente.

## 3.1 Autenticação do HDB: vocabulário verificado

O HDB **não** usa o par `AUTH/TOKEN` + `AUTH/SIGNATURE` do adb. O binário contém
um conjunto próprio de mensagens nomeadas:

```
HDB AUTHENTICPCIDENT     (o PC se identifica)
HDB AUTHENTICREQUSET     (o dispositivo envia o desafio)   [sic: typo da Huawei]
HDB AUTHENTICCONFIRM     (confirmação)
HDB AUTHENTICEXABORT     (aborto)
HDB AUTHENTICRES3000     (código de resultado)
HDB RSA_public_encrypt failure
HDB%s
```

Funções correspondentes: `hdb_auth`, `hdb_auth_do`, `send_auth_request`,
`send_auth_respone` [sic], `send_hdbauth_failure`, `pm_auth_install`,
`adbd_auth_verify`, `adbd_auth_verified`, `adbd_auth_init`.

**Hipótese de fluxo** (a confirmar com `openhdb probe --force -v`):

```
host -> device : HDB AUTHENTICPCIDENT <id/base64 da chave>
device -> host : HDB AUTHENTICREQUSET <challenge>
host -> device : <resposta RSA>            (RSA_public_encrypt no lado do device)
device -> host : HDB AUTHENTICCONFIRM
```

Diferença importante em relação ao adb: o dispositivo usa
`RSA_public_encrypt`/`RSA_verify` (as strings `RSA_verify success`/`failure`
aparecem no binário), então pode haver validação contra **chave fixa da Huawei**,
não apenas TOFU.

## 3.2 Interfaces USB (verificado no KOB2-W09, modo `12d1:107f`)

| itf | classe | iInterface | endpoints | protocolo |
|---|---|---|---|---|
| 0 | `ff/ff/00` | MTP | — | MTP |
| 1 | `08/06/50` | Mass Storage | — | BOT |
| 2 | `ff/42/01` | ADB Interface | OUT `0x03` / IN `0x84` | **adbd** (adb clássico) |
| 3 | `ff/48/01` | HDB Interface | OUT `0x04` / IN `0x85` | **hdbd** (handshake próprio) |

Comportamento observado:

- Interface ADB: nosso `A_CNXN` é aceito e o dispositivo responde
  `A_AUTH arg0=TOKEN(1)` com 20 bytes de nonce — **o codificador de pacotes do
  open-hdb foi validado contra o `adbd` real**.
- Interface HDB: um `A_CNXN` faz o endpoint devolver `EIO` e o dispositivo
  **re-enumerar no USB** (`hdbd` reinicia). Ou seja: o HDB rejeita o framing do
  adb logo no primeiro pacote. É por isso que `openhdb probe` só faz leitura
  passiva na interface HDB, a menos que se use `--force`.

## 4. Autenticação (hdb_auth)

Símbolos presentes: `_Z8hdb_authP7apacketP10atransport` (`hdb_auth`),
`_Z11hdb_auth_doP7apacketP10atransporti` (`hdb_auth_do`),
`_Z20send_hdbauth_failureP7apacketP10atransport`,
`hdb_auth.cpp`, `auth_required`, `rsa_pub`, `/hdb_keys`,
`/data/misc/adb/hdb_keys`, `getHdbKey`, `sHdbKey`.

Fluxo derivado do ADB, com desvios marcados:

1. Dispositivo → host: `A_CNXN` com banner.
2. Host → dispositivo: `A_CNXN` (`A_VERSION`, `max_payload`).
3. Se `auth_required`, o dispositivo envia `A_AUTH` `arg0=TOKEN(1)` + 20 bytes de nonce.
4. Host responde `A_AUTH` `arg0=SIGNATURE(2)` com a assinatura PKCS#1 v1.5/SHA-1 do nonce.
5. Se a assinatura não confere, o dispositivo responde `A_AUTH` `arg0=RSAPUBLICKEY(3)`
   e grava a chave em `/data/misc/adb/hdb_keys` (store **separado** do `/data/misc/adb/adb_keys`).

Pontos a confirmar no binário: se `hdb_auth_do` usa `RSA_verify` com um
certificado fixo da Huawei (as strings `RSA_verify success` / `RSA_verify failure`
aparecem no binário) antes de aceitar o token, o que tornaria o passo 4 diferente
do ADB.

## 5. Instalação

O `hdbd` executa, ao receber um pedido de instalação:

```
pm install --hwhdb <tamanho> <caminho>
```

(extraído da string `:pm install --hwhdb %s %s`.)

Verificado no dispositivo:

```
$ pm install --hwhdb 3901 /data/local/tmp/hello-hdb.apk
Failure [INSTALL_FAILED_INTERNAL_ERROR: Failure [INSTALL_HDB_VERIFY_FAILED]]
```

Ou seja: o caminho de instalação do HDB **valida o APK** (assinatura/verificação
Huawei) antes de instalar. Um APK auto-assinado é recusado — o HDB é mais
restritivo que o ADB, não menos.

## 6. USB

O HDB é uma função FunctionFS própria, com estado exposto pelo sistema:

```
sys.usb.ffs_hdb.ready = 1
persist.service.hdb.enable = true
settings system hdb_enabled = 1
init.svc.hdbd = running
```

Na configuração composta (`12d1:107f`) as interfaces observadas foram:

| # | classe | descrição |
|---|---|---|
| 0 | `ff/42/01` | MTP |
| 1 | `08/06/50` | Mass Storage |
| 2 | `ff/42/01` | **ADB Interface** (iInterface=8) |

Interface do HDB **a identificar** — o `probe` reporta todas as interfaces com
`class=0xff, subclass=0x42, protocol=0x01` e o banner lido de cada uma.

## 7. Aberto

- [x] qual interface USB pertence ao `hdbd` (itf ff/48/01, ep 04/85)
- [ ] semântica do prefixo de 4 bytes do quadro HDB
- [ ] **capturar uma sessão real do HiSuite com usbmon** (caminho decisivo)
- [ ] formato das mensagens `HDB AUTHENTIC*` (texto puro? A_AUTH com payload?)
- [ ] se o handshake do HDB começa com um magic/hello diferente de A_CNXN
- [ ] valor do tipo no banner (`hdb` vs `device`) e lista de features (o HDB não aceita CNXN, logo o banner vem por outro caminho)
- [ ] se `hdb_auth` valida uma chave fixa da Huawei ou apenas TOFU como o ADB
- [ ] formato exato do serviço de backup/restore (`backup:` / `restore:`)
- [ ] pacote de instalação (`pm install --hwhdb`) — quem fornece o fd
