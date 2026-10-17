# Engenharia Reversa — `proftpd` (squashfs-root/sbin)

**Amostra:** `squashfs-root/sbin/proftpd`  •  1.244.528 bytes  •  ELF 32-bit **MIPS32 big-endian**, uClibc, **stripped**
**Firmware:** `_3FE46322BGBB25-AAA.extracted` (Alcatel IAD/router, ProFTPD 1.3.5d)
**Ferramentas:** readelf, objdump, strings, Ghidra 12.1 (headless, MIPS:BE:32, 1590 funções descompiladas)
**Foco desta análise:** reconhecimento de **device USB** e **pontos de login FTP**, do ponto de vista de um **usuário comum de FTP** (sem SSH/root). Falhas que exigem acesso prévio ao sistema são marcadas como fora de escopo.

---

## 0. Ponto de partida: o que um usuário comum de FTP enxerga

Interface de acesso: **usuário comum ao FTP** (não `useradmin`, não `sftpadmin`, sem SSH/root).

- `proftpd.conf` define `DefaultRoot  ~  !useradmin  !useradmin-Read` → **todo usuário comum é chrootado no seu home**.
- Só `useradmin` e `useradmin-Read` escapam do chroot (conseguem ver `/`, `/mnt`, `/var`, ...).
- A autenticação é feita por módulo: `mod_auth_unix` contra `/etc/passwd` + `/etc/shadow`, e `mod_auth_file`.
- Contas FTP gerenciadas pelo `cfgmgr`/datamodel: `ftpadmin` (FTP) e `sftpadmin` (SFTP). O template estático usa `useradmin`/`useradmin-Read`; o `cfgmgr` reescreve apenas as linhas `AllowUser`/`Port` em runtime e **não toca** no `DefaultRoot`/`DenyUser`.

> **Correção decisiva (cfgmgr decompilado, `cfgUtladdSysUser`):** a conta `ftpadmin` é criada com
> **home `/mnt`** — `adduser -D -H -h /mnt -s /sbin/nologin -u <uid> ftpadmin`
> (`DAT_00655030 = "/mnt"`). Como a `ftpadmin` **não** está na lista de exceção do chroot
> (`!useradmin !useradmin-Read`), ela é **chrootada em `/mnt`** — exatamente o diretório de
> mounts dos pendrives. Por isso, na prática, a `ftpadmin` "só enxerga o pendrive": o chroot
> dela é `/mnt`, onde ficam `/mnt/usb1_1`, `/mnt/usb1_2`, ... Dentro do chroot, os pendrives
> aparecem como `/usb1_1`, `/usb1_2`, ... (o `/mnt` real vira `/`).
>
> **Consequências práticas da `ftpadmin` (chroot `/mnt`):**
> - **Alcança e escreve no pendrive**: não é `useradmin-Read`, então `STOR`/`DELE`/`RMD`/`RNFR`/
>   `RNTO`/`XRMD` em `/mnt/*` **são permitidos** (`<Directory /mnt/*>` só nega a `useradmin-Read`).
> - **Não alcança** `/var`, `/configs`, `/tmp`, `/proc` — todos fora do chroot `/mnt`.
> - **Não pode** escrever em `/tmp/var/e8client/upload` (`DenyUser !useradmin`) e **não alcança**
>   `/var/e8client/download` (`DenyAll` + fora do chroot). Todos os pontos de execução de comando
>   (e8client) estão fora do alcance dela.

---

## 0.1 RCE? — veredito

**Da conta `ftpadmin` (chrootada em `/mnt`, sem SSH/root): NÃO há RCE.**

A `ftpadmin` está **chrootada em `/mnt`** (home `/mnt`, não exceção do chroot). Isso significa
que ela só vê o pendrive montado e **não alcança** nenhum diretório onde o firmware executa
comandos (`/var/e8client/...`, `/configs`, `/tmp`). Todos os pontos de execução de comando no
binário e libs vendor foram mapeados e **nenhum é alcançável e explorável** pela `ftpadmin`:

| Ponto de execução | Argumento | Injetável? | Alcançável pela `ftpadmin`? |
|---|---|---|---|
| `system("rm -f /var/proftpd.useradmin_logined")` (proftpd) | **fixo** | ❌ | ❌ (fora do chroot `/mnt`; só sessão `useradmin`) |
| `system("dos2unix /var/e8client/upload/e8DigConfig.txt")` (`processE8DigConfig`) | **fixo** | ❌ | ❌ (fora do chroot; requer `useradmin`) |
| `system("echo %d > /var/e8client/download/e8DigConfigResult.txt")` (`FUN_00010ac0`) | **fixo** (`%d` int) | ❌ | ❌ (fora do chroot; disparo interno) |
| `system("rm -rf %s")` (`extract_e8digstatus_info`) | nome de arquivo **filtrado por sed** | ❌ | ❌ (fora do chroot; dir `DenyAll`) |
| `execv(argv[0], argv)` (proftpd relaunch) | argv fixo | ❌ | ❌ (restart interno) |
| `system("for f in /mnt/*;...")` (`usbRestoreCfg` @ cfgmgr) | `$f` = dirs do `/mnt`; nome do `.cfg` do `/configs/usb_rtscfg_tmp` | ❌ (nomes não controláveis pela FTP) | só via disparo TR-069/gerência, **não via FTP** |
| `system("echo %s %s > /configs/usb_rtscfg_tmp")` (`rts_CtUsbRestoreObject` @ cfgmgr) | campo do request TR-069 | ⚠️ **sim** (metacaracteres shell) | ❌ (exige interface TR-069, **não a conta FTP**) |

O único ponto *potencialmente* injetável — `echo %s %s > /configs/usb_rtscfg_tmp` em
`rts_CtUsbRestoreObject` — está na **interface de gerenciamento TR-069/ACS** e não é
alcançável pela conta `ftpadmin` (nem por qualquer conta FTP). É um achado válido para outro
escopo (gerência remota), não para a superfície FTP. (Detalhado na seção 7.6.)

O único vetor que *parecia* RCE — `sprintf("rm -rf %s", nome) → system()` em
`extract_e8digstatus_info` — é **neutralizado pelo filtro `sed`** que precede o `rm`:

```
popen("ls -l /var/e8client/download/ | sed -n 's/\\(.*\\)\\(e8DigStatus[0-9]\\{10\\}.txt\\)/\\2/p'")
```

O `sed` só devolve o token que casa `e8DigStatus` + exatamente 10 dígitos + `.txt`. Um nome
com metacaracteres de shell (`;`, `&`, `|`, `$`, backtick, espaço) **não casa** e é
descartado — o `%s` que vai ao `rm -rf` é sempre um nome limpo `e8DigStatus##########.txt`.
Além disso, para plantar tal arquivo em `/var/e8client/download/` seria preciso burlar o
`DenyAll` do `proftpd.conf` (acesso privilegiado). Logo, **não é um RCE** — no máximo um
`rm` de um arquivo específico já existente, e não por usuário comum.

Os **stack overflows** documentados na seção 7 (`FUN_00012cf8` e o `strcpy` em
`processE8DigConfig`) poderiam, em tese, virar RCE — mas **ambos exigem a conta `useradmin`**
(única com `STOR` liberado em `/tmp/var/e8client/upload/`), o que está fora do escopo do
usuário comum. Mesmo assim, o layout de stack exato não foi confirmado (limitação desta
análise), então não há um exploit demonstrado.

> **Conclusão prática (conta `ftpadmin`):** a superfície FTP da `ftpadmin` — chrootada em
> `/mnt`, gravando apenas no pendrive — **não oferece RCE**. Ela não alcança nenhum diretório
> onde o firmware executa comandos (`/var/e8client/...`, `/configs`, `/tmp`), e os pontos de
> execução que ela *toca* (`usbRestoreCfg`, `rts_CtUsbRestoreObject`) exigem disparo via
> TR-069/gerência — não pela conta FTP. Os únicos caminhos que chegam a execução de comando
> ou estouro de stack exigem `useradmin` ou acesso à gerência remota (ver 7.6).

---

## 1. Identificação do binário

| Item | Valor |
|------|-------|
| Origem | **ProFTPD 1.3.5d (maint)** — servidor FTP/SFTP |
| Função | Servidor FTP standalone ("IGD FTP Server"), integrado ao e8client (TR-069) do firmware |
| Arquitetura | ELF 32-bit MSB, **MIPS32 big-endian (R3000)**, uClibc, ABI o32 |
| Linkagem | dinâmica (interpreter `/lib/ld-uClibc.so.0`), **stripped** |
| Build (strings) | `--with-modules=mod_sftp --with-modules=mod_ban --enable-ctrls --enable-openssl` |
| Config | `/etc/proftpd.conf` (gerada em runtime por `cfgmgr` → `/etc/proftpd.conf` ou `/tmp/proftpd.conf`; inicia via `proftpd -c %s`) |
| Entry | `entry @ 0x402...` via `__uClibc_main`; daemon standalone |
| Libs vendor | **`libe8client.so`** (integração TR-069) — única lib de terceiros importada diretamente |

---

## 2. Reconhecimento de device USB (hotplug → montagem → FTP)

### 2.1 Cadeia de hotplug (como o firmware "vê" o pendrive)

```
Kernel detecta bloco USB (sdX)
   │  /proc/sys/kernel/hotplug = /sbin/mdev      (definido em etc/init.d/rcS)
   ▼
/sbin/mdev  (busybox)
   │  regra em /usr/etc/mdev.conf:
   │    sd[a-z]*[0-9]  root:disk  776  */usr/exe/usb_automount.sh
   ▼
/usr/exe/usb_automount.sh   (add/remove do device)
   ▼
mount do filesystem em /mnt/usb<N>_<part>
```

- **`etc/init.d/rcS`** (linha ~120): `echo /sbin/mdev > /proc/sys/kernel/hotplug` + `mdev -s` — o **mdev** é o handler de hotplug do kernel.
- **`usr/etc/mdev.conf`** (linha 24): a única regra de bloco relevante é
  `sd[a-z]*[0-9] root:disk 776 */usr/exe/usb_automount.sh`.
  O `*` significa: rodar `usb_automount.sh` **na criação e na remoção** do nó de device (`/dev/sdX1`, `/dev/sdX2`, ...).
  (As regras de `ttyUSB`/`hidraw`/`usb_serial` estão **comentadas** — só storage de bloco é auto-montado.)

### 2.2 `usb_automount.sh` — montagem e nomeação

| Etapa | Detalhe |
|-------|---------|
| Diretório base | `destdir=/mnt`, prefixo `usb`, `MAXUSB=16` |
| Detecção de FS | `fdisk -l \| grep ...` → `NTFS` / `FAT32` / `FAT` (senão `RAW`) |
| Nome do mountpoint | Sem label: `/mnt/usb<N>_<part>` (ex. `/mnt/usb1_1`, `/mnt/usb2_3`). Com label: `/mnt/<label>` |
| Montagem FAT32/FAT | `mount -t vfat -o iocharset=cp936,umask=000,uid=111 /dev/sdX /mnt/usbN_P` |
| Montagem NTFS | `/bin/ntfs-3g -o iocharset=cp936,umask=000 /dev/sdX /mnt/usbN_P` |
| Registro | append em `/tmp/usbinfo`: `USB<N> /mnt/<dir> <fstype> /dev/<dev>` |
| Remoção | `umount -l`, `rmdir` do mountpoint, `sed -i` do registro em `/tmp/usbinfo` |

- **`umask=000`** → o conteúdo montado fica **legível/gravável por qualquer uid** no plano do filesystem.
- **`iocharset=cp936`** → codificação de nomes GBK/Simplified Chinese (comum em firmware CN).
- **`uid=111`** (FAT) → dono dos arquivos = uid 111 (aplicação/serviço), mas o `umask=000` torna isso irrelevante para leitura.

### 2.3 Conexão do USB com o FTP

- **`proftpd.conf`** expõe `<Directory /mnt/*>`:
  ```apache
  <Directory /mnt/*>
    <Limit DELE RNFR RNTO RMD XRMD STOR>
      DenyUser useradmin-Read     # useradmin-Read NÃO pode escrever/apagar em /mnt/*
    </Limit>
  </Directory>
  ```
  Ou seja, `/mnt/*` é **acessível por leitura** (RETR/STOR para quem não for `useradmin-Read`), restrito a escrita para a conta read-only.
- **`cfgmgr`** (sbin/cfgmgr) usa o mesmo padrão de montagem:
  - string `/mnt/usb1_1` (primeiro USB, partição 1);
  - varre `/mnt/*` procurando arquivos de config `for f in /mnt/*; do [ -f $f/%s/%s_%s.cfg ] ...` e lê `/mnt/%s/%s/%s_%s.cfg` — o USB também serve para **importar/exportar config** do equipamento.
- **Alcance da `ftpadmin` (caso real):** a `ftpadmin` tem home `/mnt` (ver seção 0), portanto
  é **chrootada dentro de `/mnt`** e alcança o pendrive montado. Como não é `useradmin-Read`,
  ela **pode gravar/apagar arquivos no pendrive** via FTP. É por isso que, ao conectar o
  pendrive, a `ftpadmin` "só enxerga o pendrive" — o chroot dela é o próprio diretório de mounts.
  O que ela **não** alcança: `/var`, `/configs`, `/tmp` (tudo fora do chroot `/mnt`).
- **Contas privilegiadas** (`useradmin`/`useradmin-Read`), por não serem chrootadas, enxergam o
  sistema inteiro, incluindo `/var/e8client/...` — o único caminho até os pontos de execução de
  comando.

---

## 3. Pontos de login no FTP

### 3.1 Fluxo de autenticação (do ponto de vista de quem conecta)

```
Cliente:  USER <nome>  ──► FUN_00475270 (cmd_user)
                              ├─ pr_auth_get_anon_config (anon aliases)
                              ├─ pr_auth_getpwnam (procura usuário)
                              ├─ checa RootLogin se uid==0
                              └─ guarda session.user (DAT_0053f048)
Cliente:  PASS <senha> ──► pr_auth_authenticate / pr_auth_check
                              ├─ procura módulo de auth ("check")
                              ├─ mod_auth_unix: getspnam(/etc/shadow) + crypt(3)
                              └─ mod_auth_file (AuthUserFile, se configurado)
Login OK:  FUN_00474fbc (login-success)
                              ├─ pr_log_auth("Login successful")
                              └─ pr_memscrub(senha)  ← zera a senha em memória
```

- **`FUN_00475270` @ 0x475270 = `cmd_user`** (handler USER). O username do cliente (`param_3`) vai para `pr_auth_getpwnam` / `pr_auth_authenticate`. Logs com format strings fixos (`pr_log_auth`). **Sem overflow direto com o username.**
- **`pr_auth_authenticate` @ 0x43ecc8** e **`pr_auth_check` @ 0x43f024**: delegam a um módulo de autenticação via tabela. Os módulos embutidos são `mod_auth_unix` e `mod_auth_file`.
- **`mod_auth_unix`** (decomp ~linha 38681): `pr_privs_root("mod_auth_unix.c")` → `getspnam(3)` → compara `crypt(3)` contra o `/etc/shadow`. Mensagem: *"mod_auth_unix: getspnam(3) for user '%s' error"*.
- **`mod_auth_file`** (~linha 38766): *"mod_auth_file/1.0: using passwd file '%s'"* via `AuthUserFile`/`AuthGroupFile` (não configurado no `proftpd.conf` estático → prevalece `mod_auth_unix`).
- **`FUN_00474fbc` @ 0x474fbc = login-success**: loga `"Login successful."` e faz `pr_memscrub` da senha (`param_1+0x14`).
- **`RootLogin on`** está habilitado no config: em `cmd_user`, se `puVar3[2] == 0` (uid 0), gera evento `mod_auth.root-login`; com `RootLogin on`, o login root é permitido e logado em `pr_log_auth(4,"ROOT FTP login successful")` (linha ~40165). *Isso é um vetor se o root tiver senha conhecida — mas requer credenciais, não é "sem acesso prévio".*

### 3.2 Flag de sessão do `useradmin` (mecanismo custom no binário)

O binário carrega uma lógica própria, fora do ProFTPD vanilla, para controlar a sessão FTP do `useradmin`:

- **Criação:** string `echo "1">/var/proftpd.useradmin_logined` (offset 0x10410c) — a flag é criada quando o `useradmin` loga com sucesso.
- **Remoção:** em `pr_session_disconnect` @ 0x4505e8 (linha ~34282):
  ```c
  iVar1 = strcmp(logined_user,"useradmin");
  if ((iVar1 == 0) && (useradmin_logined == 1)) {
      system("rm -f /var/proftpd.useradmin_logined\n");
      pr_session_end(0);
  }
  ```
- Globais: `logined_user` (nome do usuário logado) e `useradmin_logined` (flag de sessão).

> Isso indica um **gate de sessão exclusivo do `useradmin`** (ex.: só uma sessão admin ativa por vez, sinalizada por arquivo em `/var`). Não é um ponto de entrada para usuário comum, mas é um comportamento custom que difere do vanilla e merece registro.

### 3.3 SFTP (mod_sftp)

- VirtualHost em `192.168.1.254`, porta **2122**, `SFTPEngine off` (desabilitado no template).
- `<Limit LOGIN>  DenyAll; AllowUser sftpadmin  </Limit>` → **somente `sftpadmin`** loga no SFTP.
- Build: `mod_sftp/0.9.9` (strings `SSH-2.0-mod_sftp_0.9.9`), com OpenSSL.
- Chaves: `/etc/ssh/ssh_host_rsa_key`, `/etc/ssh/ssh_host_dsa_key` (ou `/configs/sftp/...`).

### 3.4 Gerenciamento das contas (quem são os usuários)

- **Datamodel** (`usr/etc/datamodel.xml`): `FtpUserName`/`FtpPassword` (default `ftpadmin`), `SftpUserName`/`SftpPassword` (default `sftpadmin`), `FtpEnable`/`SftpEnable` (default false).
- **`cfgmgr`** (sbin/cfgmgr): funções `cfg_modProFtpdConf`, `cfg_modProSftpdConf`, `cfg_handleRemoteSftpAccess`, e strings `ftpadmin`, `sftpadmin`, `proftpd -c %s`. É ele quem **gera o `proftpd.conf` runtime** e (re)grava as contas.
- **Criação da conta `ftpadmin`** (decompilado `handleUSBSharingSysUsers` + `cfgUtladdSysUser`, chamado no boot via `cfg_modProFtpdConf`/`cfg_bootFtp`):
  ```
  adduser -D -H -h /mnt -s /sbin/nologin -u <uid> ftpadmin
  ```
  - Home fixo **`/mnt`** (`DAT_00655030`), shell `/sbin/nologin`, uid inicial `0x70`–`0x73`
    (serviço FTP/SMB/SFTP/USB) reescrito para **uid 111** (`0x6f`) via
    `sed -i 's/%s:x:%d:%d:/%s:x:%d:%d:/' /configs/etc/passwd`.
  - Senha definida por `cfgUtlSetSysUserPassword` → `(echo <pass>; sleep 1; echo <pass>) | passwd <user>`.
  - É por isso que a `ftpadmin` é chrootada em `/mnt`: home `/mnt` + `DefaultRoot ~`.
- **`cfgmgr` em runtime NÃO toca no chroot**: `cfg_modProFtpdConf` só reescreve `Port`,
  `AllowUser`, `MaxLoginAttempts`, `TimeoutIdle` e anexa o bloco `mod_ban` via `sed -i`.
  As linhas `DefaultRoot`, `DenyUser`, e o `<Directory /tmp/var/e8client/...>` ficam como no
  template estático (`/etc/proftpd.conf` → `/tmp/proftpd.conf` via `cp`).
- **`add_mgnt_user.sh`**: adiciona o usuário de gestão a `/etc/passwd`+`/etc/shadow` via `adduser -D` + `chpasswd -m`, e aplica `rootmod.sh` (uid 0). Contas criadas assim são **sistêmicas** e, com uid 0, virariam **RootLogin** no FTP se o `proftpd.conf` runtime permitir.

---

## 4. Integração com as libs vendor (funções importadas)

O proftpd é dinamicamente ligado. Símbolos **UND** (importados) que **não** vêm de
libc/uClibc/OpenSSL provêm de **uma única lib vendor: `libe8client.so`**:

| Import no proftpd | Endereço UND | Exportada por | Endereço na lib | Tamanho |
|---|---|---|---|---|
| `processE8DigConfig` | `0x4f2750` | `libe8client.so` | `0x0001434c` | 6420 B |
| `extract_e8digstatus_info` | `0x4f2920` | `libe8client.so` | `0x00002dd0` | 5500 B |

- **`libcfg.so`** e **`libcs_util.so`** não exportam símbolos importados diretamente pelo
  proftpd — são dependências transitivas (carregadas via `libe8client.so`).
- No `proftpd.decomp.txt` essas duas funções aparecem apenas como **stubs PLT**
  (`processE8DigConfig @ 004f2750`, `extract_e8digstatus_info @ 004f2920`); os callers reais
  são alcançados via GOT preenchido em runtime e não são rastreáveis estaticamente.

**Strings de integração presentes no proftpd:** `libe8client.so`, `/var/e8client/download`,
`e8DigConfig`, `processE8DigConfig`, `extract_e8digstatus_info`.

**Cadeia de entrada via FTP (confirmada pelo `proftpd.conf`):**
- `<Directory /tmp/var/e8client/upload>` — permite `STOR` **apenas ao usuário `useradmin`**
  → o arquivo `e8DigConfig.txt` enviado via FTP é processado por `processE8DigConfig`.
- `<Directory /tmp/var/e8client/download>` — `DenyAll` para `DELE/STOR`; download controlado
  pelo `extract_e8digstatus_info`.
- VirtualHost **SFTP** na porta **2122** com usuário `sftpadmin`.

> **Alcance do usuário comum:** estas vias exigem a conta `useradmin` (upload) ou a capacidade
> de depositar arquivos em `/var/e8client/download` (bloqueado por `DenyAll`). **Não são
> alcançáveis por um usuário comum de FTP** — fora do escopo desta análise.

---

## 5. Decompilação das funções importadas (`libe8client.so`)

### 5.1 `processE8DigConfig` (`0x0001434c`)

Processa um **arquivo TR-069 enviado pelo usuário** (`/var/e8client/upload/e8DigConfig.txt`):

1. Verifica `/tmp/tr069_in_process` (existe → seta flag e chama `FUN_00010ac0`).
2. Senão, verifica se `/var/e8client/upload/e8DigConfig.txt` existe (`access`).
3. **`sprintf(buf, "dos2unix %s", "/var/e8client/upload/e8DigConfig.txt")` → `system(buf)`**
   — converte CRLF→LF executando `dos2unix` no arquivo enviado.
4. `fopen(path, "r")` + `fgets` em loop, copiando cada linha em chunks de **0x100** para um
   buffer de **0x10000** bytes (`acStack_10034`).
5. Para cada parâmetro TR-069 esperado (`...WLANConfiguration.1.BeaconType`, `SSID`,
   `X_CT-COM_APModuleEnable`, etc.), usa `strstr` para localizar e `FUN_00012cf8` para
   extrair o valor, validando BeaconType/WEPKey/WPA e aplicando ao config DB via
   `cfg_getObj`/`cfg_setObj`.

### 5.2 `extract_e8digstatus_info` (`0x00002dd0`)

Extrai parâmetros `DeviceInfo` de um arquivo de status TR-069 baixado:

1. **`popen("ls -l /var/e8client/download/ | sed -n 's/\(.*\)\(e8DigStatus[0-9]\{10\}.txt\)/\2/p'", "r")`**
   — lista arquivos de status; o **`sed` filtra o nome** para o padrão rígido
   `e8DigStatus` + 10 dígitos + `.txt` (o que impede injeção de shell no passo 4).
2. `fgets(acStack_1524[0x80])` pega o primeiro nome; `strtoul` dos dígitos.
3. `snprintf(acStack_14a4, 0x80, ".../e8DigStatus%010lu.txt", n)`; `open(...)`.
4. **`sprintf(acStack_132c[0x100], "rm -rf %s", acStack_1524)` → `system(...)`** — apaga o
   arquivo lido. **Não é RCE**: o `%s` foi filtrado pelo `sed` no passo 1 (ver seção 0.1).
5. Parseia o conteúdo por parâmetros `InternetGatewayDevice.DeviceInfo.*` e escreve no config DB.

### 5.3 `FUN_00012cf8` — extrator de valor (helper central)

```c
undefined4 FUN_00012cf8(char *param_1, char *param_2) {
  pcVar1 = strchr(param_1, 0x3d);              /* acha '=' */
  if (pcVar1 == 0) { log_log(3, ...); return -1; }
  __n = strlen(pcVar1 + 1);                     /* tamanho TOTAL do valor */
  strncpy(param_2, pcVar1 + 1, __n);            /* ← sem limite no destino */
  return 0;
}
```
Recebe uma linha `CHAVE=valor`, acha o `=`, e copia **todo o valor** para o buffer de
destino — **cópia sem limite**.

---

## 6. Análise da entrada de input do usuário (handlers FTP do proftpd)

- **Dispatcher:** `pr_cmd_dispatch_phase` localiza o handler via `pr_stash_get_symbol(2, nome)`.
  Tabela de comandos registrada por `FUN_0043b434`/`FUN_0043b62c` (`pr_module_register`).
- **Tabela de nomes de comando** em `0x52a064`: `USER(1)`, `ACCT`, `XCWD`, `XCUP`, `REIN`,
  `PORT`, `PASV`, `TYPE`, `MODE`, `STOR`, `APPE`, `REST`, `RNTO`, `DELE`, `RMD`, `MKD`,
  `MLST`, `PWD`, `SIZE`, `NLST`, `SYST`, `HELP`, `FEAT`, `LANG`, `AUTH`, `CONF`, `MIC`,
  `PROT`, `MFMT`, ...
- **`FUN_00475270` (0x475270) = `cmd_user`** (USER handler): username → `pr_auth_getpwnam`,
  `pr_auth_authenticate`; strings de log `pr_log_auth` (format strings seguros). **Sem
  overflow direto com o username.**
- **`FUN_00474fbc` = login-success handler** (`pr_memscrub` da senha).
- **Password (`param_4`)** → `pr_auth_check` / `pr_auth_authenticate`.
- **SITE dispatcher** (`site_dispatch @ 0x48b7dc`): tabela `PTR_FUN_0052a324`/
  `PTR_s_CHGRP_0052a338`, stride 7. Subcomandos:
  - **SITE CHMOD** → wrapper `0x48aa4c` → `core_chmod` (`0x466118`) → `pr_fsio_chmod(path, mode)`.
  - **SITE CHGRP** → wrapper `0x48b200` → `core_chgrp` (`0x465ff4`) → `pr_fsio_lchown(path, uid, gid)`.
  - **SITE HELP** → `FUN_0048a660`.
- **HELP handler** = `FUN_0048a660`.

> Os wrappers SITE CHMOD/CHGRP ficam **fundidos** no bloco do `FUN_0048a660` na saída linear
> do Ghidra; a análise estaticamente confirmou apenas os prologues e o destino
> `core_chmod`/`core_chgrp`.

**Conclusão dos handlers nativos do proftpd:** os caminhos USER/PASS são **seguros**
(delegação a `pr_auth_*`, format strings de log fixos, `pr_memscrub` da senha). Os pontos
de maior risco residem nas **funções vendor importadas** (seção 5), que consomem arquivos
entregues via o próprio proftpd — mas só pela conta `useradmin`.

---

## 7. Achados de segurança (por alcance)

> Classificação conforme o acesso exigido. **Fora de escopo** (exigem SSH/root/sistema
> prévio ou interface de gerência) são listados apenas para registro, não como vetor da
> conta `ftpadmin` (o acesso em análise).

### 7.1 Acessíveis à conta `ftpadmin` (chroot `/mnt`)

- **Handlers nativos USER/PASS seguros** (delegação a `pr_auth_*`, senha `pr_memscrub`'d,
  format strings fixos). Sem overflow direto.
- **`DefaultRoot ~`** isola cada usuário comum no seu home (chroot). Para a `ftpadmin`, o
  home é `/mnt` (seção 0), então ela fica chrootada dentro do diretório de mounts USB.
- **`<Directory /tmp/var/e8client/download>` `DenyAll`** para escrita → o vetor de injeção de
  comando do e8client (7.3) **não é alcançável** pela `ftpadmin` (fora do chroot `/mnt` + `DenyAll`).
- **`<Directory /mnt/*>`** restringe escrita a `useradmin-Read`; a `ftpadmin` (não sendo
  `useradmin-Read`) **pode gravar/apagar no pendrive** via FTP. Isso é o que ela observa na
  prática: ao plugar o pendrive, a `ftpadmin` "só enxerga o pendrive" — porque o chroot dela
  é `/mnt`.

### 7.2 Requerem conta privilegiada (`useradmin` / `useradmin-Read` / `sftpadmin`)

- **`processE8DigConfig`** (`0x0001434c`):
  - `strcpy(acStack_13970, acStack_13c40)` **sem limite** na aplicação da chave WPA
    (linha ~3724 do decomp).
  - `system("dos2unix <path>")` com caminho hardcoded.
- **`FUN_00012cf8`** (lib): `strncpy(dst, valor, strlen(valor))` **sem limite** — extrator
  `CHAVE=valor`; estouro se o buffer de destino for menor que o valor máximo.
- **`extract_e8digstatus_info`** (`0x00002dd0`): `sprintf(acStack_132c,"rm -rf %s",
  acStack_1524)` → `system()`. O nome vem do `popen("ls ... | sed -n 's/\(.*\)\(e8DigStatus[0-9]\{10\}.txt\)/\2/p'")`, e o **filtro `sed` neutraliza a injeção** (só passa
  `e8DigStatus` + 10 dígitos + `.txt`). Não é RCE (ver seção 0.1).
- **Flag de sessão `useradmin`** (`/var/proftpd.useradmin_logined`, `echo "1">...` /
  `rm -f ...`) — comportamento custom, exclusivo da conta admin.
- **`RootLogin on`** → se `root` (uid 0) tiver senha válida, loga como root (log
  "ROOT FTP login successful"); requer credenciais de root.

### 7.3 Fora de escopo (exigem SSH/root/acesso prévio ou interface de gerência)

- O `rm -rf` do `extract_e8digstatus_info` (7.2) é **neutralizado pelo filtro `sed`** e, ainda
  assim, exigiria depositar um arquivo em `/var/e8client/download/`, que o `proftpd.conf`
  bloqueia com `DenyAll` e que a `ftpadmin` nem alcança (fora do chroot `/mnt`).
- Qualquer alteração em `/etc/proftpd.conf`, `/etc/passwd`, `/etc/shadow` ou no datamodel
  (contas FTP, `RootLogin`) exige acesso administrativo prévio.
- **Injeção de comando em `rts_CtUsbRestoreObject`** (cfgmgr, seção 7.6) exige chamar o
  objeto via **TR-069/ACS ou RPC local de gerência** — não pela conta FTP.

### 7.4 Pontos positivos

- Handlers FTP nativos (USER/PASS) delegam a `pr_auth_*`; senha é `pr_memscrub`'d.
- `fgets`/`snprintf` com tamanhos fixos nos buffers de nome de arquivo de
  `extract_e8digstatus_info` (`0x80`, `0x7f`).
- Diretórios de upload/download protegidos por `<Limit>` no `proftpd.conf`.
- `DefaultRoot ~` (chroot por usuário, exceto `useradmin`/`useradmin-Read`).
- A conta `ftpadmin` é chrootada em `/mnt`: mesmo podendo gravar no pendrive, ela fica
  isolada do resto do sistema (`/var`, `/configs`, `/tmp`), o que **neutraliza qualquer
  tentativa de plantar arquivo em diretório executado pelo firmware**.
- USB montado com `umask=000`, mas o alcance da `ftpadmin` se limita ao pendrive (chroot `/mnt`).

### 7.5 Riscos a confirmar (limitações desta análise)

- **Layout real de stack** de `processE8DigConfig`/`FUN_00012cf8` (Ghidra impreciso no
  tamanho de `acStack_13970`/`acStack_13c40`) — recomenda-se **disassembly MIPS manual**.
- **Callers reais** de `processE8DigConfig`/`extract_e8digstatus_info` no proftpd não foram
  rastreados (via GOT). Mapear o ponto de chamada (provável hook de upload/download pós-STOR)
  esclarece a trilha de ataque completa.
- **`proftpd.conf` runtime num device ligado**: a análise decompilada do `cfgmgr` confirma que
  ele não altera `DefaultRoot`/`DenyUser`, e que a conta é `ftpadmin` com home `/mnt`. Resta
  confirmar num aparelho real se algum outro mecanismo (script de fábrica/`add_mgnt_user.sh`)
  reescreve o `DefaultRoot` ou adiciona a `ftpadmin` às exceções — o que **mudaria o veredito**
  (se a `ftpadmin` não fosse chrootada, ela alcançaria `/var/e8client/...`). A observação do
  usuário — "a `ftpadmin` só enxerga o pendrive" — é **evidência empírica de que o chroot
  efetivo é `/mnt`** (conforme o template + cfgmgr), corroborando o veredito de **sem RCE**.

### 7.6 Achado em interface de gerência (TR-069) — fora do alcance FTP, mas relevante

Decompilando o `cfgmgr` (não o `proftpd`), encontrou-se um ponto de **injeção de comando**
em `rts_CtUsbRestoreObject` (~linha 109300 do decomp):

```c
// usb_name = param_1 + 0x24 (campo do request TR-069 / RPC local), strcpy sem sanitização
sprintf(acStack_8df0, "echo %s %s >/configs/usb_rtscfg_tmp", usb_name, ModelName);
system(acStack_8df0);
```

- O campo `usb_name` do request é copiado com `strcpy` e interpolado num `echo ... >` via
  `system()`. **Metacaracteres de shell** (`;`, `|`, `$()`, backtick, `>` ...) injetariam
  comando arbitrário como root.
- O mesmo objeto alimenta `usbRestoreCfg` (boot): ele lê `/configs/usb_rtscfg_tmp` e usa o
  modelo para procurar `e8_Config_Backup/ctce8_<model>.cfg` no pendrive (`for f in /mnt/*;...`
  + `cp -f ... /configs/confignew.cfg`).
- **Alcance:** exige chamar `rts_CtUsbRestoreObject` via **TR-069/ACS ou RPC local de gerência**
  (autenticado). **Não é alcançável pela conta `ftpadmin`** — nem por qualquer conta FTP.
  Registrado aqui porque é um vetor real de RCE no dispositivo, porém em outro escopo de
  acesso (gerência remota, não FTP).

---

## 8. Tabela de símbolos-chave

| Endereço | Símbolo | Papel |
|----------|---------|-------|
| `0x475270` | `cmd_user` (`FUN_00475270`) | Handler USER (username → `pr_auth_getpwnam`) |
| `0x474fbc` | `FUN_00474fbc` | login-success / `pr_memscrub` senha |
| `0x43ecc8` | `pr_auth_authenticate` | dispatcher de autenticação por módulo |
| `0x43f024` | `pr_auth_check` | verificação de senha (módulos auth) |
| `0x4505e8` | `pr_session_disconnect` | remove flag `/var/proftpd.useradmin_logined` |
| `0x48b7dc` | `site_dispatch` | Dispatcher de subcomandos SITE |
| `0x48a660` | `FUN_0048a660` | Handler HELP / SITE HELP |
| `0x48aa4c` | SITE CHMOD wrapper | → `core_chmod` (`0x466118`) → `pr_fsio_chmod` |
| `0x48b200` | SITE CHGRP wrapper | → `core_chgrp` (`0x465ff4`) → `pr_fsio_lchown` |
| `0x52a064` | cmd name table | `{id, name_ptr, flags, next}` (USER=1, ...) |
| `0x4f2750` | `processE8DigConfig` (UND) | import de `libe8client.so` |
| `0x4f2920` | `extract_e8digstatus_info` (UND) | import de `libe8client.so` |
| `0x103880` | `/var/proftpd.useradmin_logined` | caminho da flag de sessão admin |
| `0x10410c` | `echo "1">/var/proftpd.useradmin_logined` | criação da flag |

**`libe8client.so` (decompilada):**
| Endereço | Símbolo | Papel |
|----------|---------|-------|
| `0x0001434c` | `processE8DigConfig` | processa `e8DigConfig.txt` (TR-069) → config DB |
| `0x00002dd0` | `extract_e8digstatus_info` | extrai `DeviceInfo` de `e8DigStatus*.txt` |
| `0x00012cf8` | `FUN_00012cf8` | extrator `CHAVE=valor` (cópia sem limite) |

**`cfgmgr` (sbin/cfgmgr, decompilado) — resolveu a relação `ftpadmin`/chroot:**
| Endereço | Símbolo | Papel |
|----------|---------|-------|
| `0x005675ac` | `handleUSBSharingSysUsers` | cria/atualiza conta do serviço USB (FTP/SMB/SFTP) |
| `0x0043ba50` | `cfgUtladdSysUser` | `adduser -D -H -h /mnt -s /sbin/nologin ...` (home `/mnt`) |
| `0x00430f50` | `cfg_modProFtpdConf` | reescreve `Port`/`AllowUser`/`MaxLoginAttempts`/`TimeoutIdle` no proftpd.conf — **não toca em `DefaultRoot`/`DenyUser`** |
| `0x004317d4` | `cfg_modProSftpdConf` | liga/desliga `SFTPEngine` + `AllowUser` |
| `0x00655030` | `DAT_00655030` | string **`"/mnt"`** — home da conta FTP |
| ~`0x004f5430` | `rts_CtUsbRestoreObject` | `echo %s %s >/configs/usb_rtscfg_tmp` via `system()` — **injeção de comando** (TR-069, seção 7.6) |
| `0x005cc90c` | `usbRestoreCfg` | lê pendrive procurando `e8_Config_Backup/ctce8_<model>.cfg` e copia p/ `/configs/confignew.cfg` |

---

## 9. Artefatos gerados

- `/tmp/proftpd_rev/proftpd.decomp.txt` — 1590 funções decompiladas (4.6 MB)
- `/tmp/proftpd_rev/libe8client.decomp.txt` — decompilação de `libe8client.so`
- `/tmp/proftpd_rev/libcfg.decomp.txt`, `libcs_util.decomp.txt` — libs transitivas
- `/tmp/proftpd_rev/proftpd_imports.txt` — lista completa de símbolos importados (373)
- `/tmp/proftpd_rev/proftpd` — cópia do binário; projeto Ghidra em `/tmp/proftpd_rev/ghidra_proj/`
- `/tmp/cfgmgr_rev/cfgmgr` + `/tmp/cfgmgr_rev/cfgmgr.decomp.txt` — decompilação do `cfgmgr` (10.7 MB)
- Este relatório: `rev/proftpd.md`
