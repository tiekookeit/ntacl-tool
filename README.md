# ntacl_tool

Ferramenta em Python para inspecionar e alterar ACLs NT (SDDL) em arquivos e diretórios via `samba-tool`.

O script foi pensado para ambientes Samba/Active Directory em que você precisa:

- Consultar a ACL NT atual de um caminho.
- Visualizar owner, group, herança e ACEs de forma legível.
- Quebrar herança da ACL.
- Adicionar ou remover permissões.
- Aplicar alterações de forma interativa ou direta por parâmetros.

## O que o projeto faz

O projeto contém um único script principal: [ntacl_tool.py](./ntacl_tool.py).

Ele usa:

- `samba-tool ntacl get --as-sddl` para ler a ACL atual.
- `samba-tool ntacl set` para aplicar a ACL final.
- `wbinfo` para resolver nomes e SIDs quando necessário.

## Modos de uso

O script suporta dois estilos de operação:

- Modo interativo: abre um menu com staging das alterações antes de aplicar.
- Modo direto: recebe alterações por parâmetros, útil para automação e scripts.

Subcomandos disponíveis:

- `interactive`: abre o menu interativo.
- `show`: mostra a ACL atual.
- `set`: altera a ACL por parâmetros.

Se você executar o script sem argumentos, ele mostra um help completo com todas as funcionalidades e exemplos.

## Dependências

### Python

O script usa apenas bibliotecas padrão do Python 3:

- `argparse`
- `json`
- `re`
- `subprocess`
- `sys`
- `dataclasses`
- `typing`

Não há dependências Python para instalar via `pip`.

### Pacotes necessários no Debian

Para o script funcionar no Debian, os componentes mínimos são:

- `python3`: interpretador Python.
- `samba-common-bin`: fornece o comando `samba-tool`.
- `winbind`: fornece o comando `wbinfo`.

Comando pronto para instalação:

```bash
sudo apt update
sudo apt install -y python3 samba-common-bin winbind
```

Referências oficiais Debian usadas para confirmar os pacotes:

- `samba-tool` aparece no pacote `samba-common-bin`:
  https://packages.debian.org/bookworm/amd64/samba-common-bin/filelist
- `wbinfo` aparece no pacote `winbind`:
  https://packages.debian.org/sid/amd64/winbind/filelist
- detalhes do pacote `winbind` no Debian:
  https://packages.debian.org/bookworm/winbind

## Observações importantes sobre o ambiente

Instalar os pacotes não é suficiente por si só se o servidor não estiver corretamente integrado ao ambiente Samba/AD.

Na prática, para o script funcionar de forma útil, o host normalmente precisa:

- Ter acesso ao ambiente Samba/AD.
- Conseguir executar `samba-tool ntacl`.
- Conseguir resolver usuários e grupos com `wbinfo`.

Se `wbinfo` não resolver nomes/SIDs, o script ainda pode funcionar parcialmente, mas a exibição amigável de identidades e algumas operações por nome podem falhar.

## Exemplos de uso

### Mostrar a ajuda geral

```bash
python3 ntacl_tool.py
```

ou:

```bash
python3 ntacl_tool.py --help
```

### Modo interativo

```bash
python3 ntacl_tool.py interactive /caminho/pasta
```

### Consultar ACL atual

```bash
python3 ntacl_tool.py show /caminho/pasta
```

### Consultar ACL em JSON

```bash
python3 ntacl_tool.py show /caminho/pasta --json
```

### Desativar herança sem aplicar

```bash
python3 ntacl_tool.py set /caminho/pasta --disable-inheritance --dry-run
```

Para desativar herança removendo ACEs herdadas:

```bash
python3 ntacl_tool.py set /caminho/pasta --disable-inheritance --drop-inherited --dry-run
```

Para reativar herança:

```bash
python3 ntacl_tool.py set /caminho/pasta --enable-inheritance --dry-run
```

### Adicionar permissão

```bash
python3 ntacl_tool.py set /caminho/pasta \
  --add "principal=DOM\\usuario,perm=modify,flags=OICI,type=A" \
  --dry-run
```

Campos aceitos em `--add`:

- `principal` ou `sid`: usuário, grupo, alias conhecido ou SID.
- `perm` ou `mask`: `read`, `modify`, `full` ou uma máscara hexadecimal.
- `flags`: flags de herança, por exemplo `OICI`.
- `type`: `A` para allow ou `D` para deny.

### Remover permissão por índice

```bash
python3 ntacl_tool.py set /caminho/pasta --remove-index 2 --dry-run
```

### Remover permissão por filtro

```bash
python3 ntacl_tool.py set /caminho/pasta \
  --remove "principal=DU,type=A" \
  --dry-run
```

Exemplos de filtros aceitos em `--remove`:

- `principal=DU`
- `sid=S-1-5-...`
- `type=A`
- `perm=read`
- `mask=0x001200a9`
- `inherited=yes`

### Aplicar de fato a ACL final

```bash
python3 ntacl_tool.py set /caminho/pasta \
  --disable-inheritance \
  --add "principal=DA,perm=full,flags=OICI,type=A" \
  --apply
```

## Segurança operacional

O modo `set` não aplica alterações sem `--apply`.

Se você usar apenas `--dry-run`, o script:

- monta a ACL final;
- mostra a ACL prevista;
- mostra a SDDL final;
- não executa `samba-tool ntacl set`.

O script também emite um aviso se não encontrar `DA` (`Domain Admins`) com controle total na ACL final.

## Limitações atuais

- O parser de SDDL é simplificado e pode não cobrir todos os formatos possíveis.
- O projeto ainda não possui suíte de testes automatizados.
- O comportamento depende das ferramentas externas `samba-tool` e `wbinfo`.

## Estrutura do projeto

```text
.
├── ntacl_tool.py
└── README.md
```
