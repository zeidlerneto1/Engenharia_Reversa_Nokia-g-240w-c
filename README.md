# Engenharia Reversa — Nokia G-240W-C (firmware Alcatel IAD/router)

Engenharia reversa do firmware do Nokia G-240W-C (Alcatel IAD/router, MIPS32
big-endian, uClibc). O firmware de referência foi extraído de
`_3FE46322BGBB25-AAA.extracted` (squashfs-root).

> **Atenção:** este repositório contém **decompilações** (saída do Ghidra headless)
> de binários do firmware. É material de análise/estudo. Não contém os binários
> originais, nem chaves/credenciais.

## Estrutura

```
relatorios/          Análises escritas (markdown)
  proftpd.md         Reversa do proftpd: reconhecimento de device USB, pontos de
                     login FTP, e avaliação de RCE com a conta comum `ftpadmin`.
                     Inclui o achado de que `ftpadmin` é chrootada em /mnt
                     (home /mnt), sem RCE alcançável.
  reverser_plan.md   Plano de reversa geral.
  orig_system.md     Notas sobre o sistema original.

decompilados/        Saída do Ghidra headless (descompilação C das funções)
  proftpd/           proftpd.decomp.txt + libs vendor (libe8client, libcfg, libcs_util)
  cfgmgr/            cfgmgr.decomp.txt  (geração do proftpd.conf runtime, contas FTP)
  cgi/               *.cgi.decomp.txt + libcgi.so.decomp.txt (CGIs do web server)
  upnpd/             decompiled.txt     (daemon UPnP)

upnp.py              Script UPnP (pré-existente no repo).
```

## Como os binários foram decompilados

Todos os `.decomp.txt` foram gerados com **Ghidra headless** (`analyzeHeadless`),
processador `MIPS:BE:32:default`, script de decompilação exportando as funções
decompiladas para texto. O método está descrito nos relatórios.

## Nota de escopo

A análise do `proftpd` partiu do ponto de vista de um **usuário comum de FTP**
(`ftpadmin`), sem SSH/root. O veredito principal: **com `ftpadmin` não há RCE** —
a conta é chrootada em `/mnt` (home `/mnt`), gravando apenas no pendrive, sem
alcançar os diretórios onde o firmware executa comandos (`/var/e8client/...`).
Um ponto de injeção de comando foi encontrado em `rts_CtUsbRestoreObject`
(interface TR-069/gerência), mas fora do alcance da conta FTP. Detalhes no
`relatorios/proftpd.md`.
