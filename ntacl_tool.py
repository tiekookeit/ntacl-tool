#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

KNOWN_ALIASES = {
    "DA": "Domain Admins",
    "DU": "Domain Users",
    "AU": "Authenticated Users",
    "LA": "Local Administrator",
    "SY": "SYSTEM",
    "WD": "Everyone",
    "BA": "Builtin Administrators",
}

PERM_MASKS = {
    "read": "0x001200a9",
    "modify": "0x001301bf",
    "full": "0x001f01ff",
}

MASK_LABELS = {
    "0x001200a9": "Leitura",
    "0x001301bf": "Leitura e escrita",
    "0x001f01ff": "Controle total",
}

ACE_TYPE_LABELS = {
    "A": "Allow",
    "D": "Deny",
}

HELP_TEXT = """\
Ferramenta para inspecionar e alterar ACLs NT (SDDL) via Samba.

Modos disponíveis:
  interactive   Abre o menu interativo com staging e confirmação final.
  show          Exibe a ACL atual de um caminho, em texto ou JSON.
  set           Altera a ACL diretamente por parâmetros, com opção de dry-run.

Funcionalidades:
  - Ler ACL atual com 'samba-tool ntacl get --as-sddl'
  - Exibir owner, group, flags da DACL e ACEs resolvendo aliases/SIDs
  - Desativar herança mantendo ACEs herdadas como explícitas
  - Desativar herança removendo ACEs herdadas
  - Reativar herança removendo a proteção da DACL
  - Adicionar permissões Allow/Deny com máscaras read/modify/full
  - Remover ACEs por índice ou por filtros no modo direto
  - Mostrar SDDL final antes de aplicar
  - Aplicar ACL final com 'samba-tool ntacl set'

Exemplos:
  ntacl_tool.py interactive /dados/pasta
  ntacl_tool.py show /dados/pasta
  ntacl_tool.py show /dados/pasta --json
  ntacl_tool.py set /dados/pasta --disable-inheritance --dry-run
  ntacl_tool.py set /dados/pasta --disable-inheritance --drop-inherited --dry-run
  ntacl_tool.py set /dados/pasta --enable-inheritance --dry-run
  ntacl_tool.py set /dados/pasta --add "principal=DOM\\usuario,perm=modify,flags=OICI,type=A" --dry-run
  ntacl_tool.py set /dados/pasta --remove-index 2 --apply
  ntacl_tool.py set /dados/pasta --remove "principal=DU,type=A" --apply

Observações:
  - Dependências externas: samba-tool e wbinfo
  - O modo 'set' não aplica nada sem --apply; use --dry-run para pré-visualizar
  - A ferramenta emite aviso se 'DA' não ficar com controle total ao final
"""


@dataclass
class Ace:
    ace_type: str
    flags: str
    mask: str
    sid: str

    def is_inherited(self) -> bool:
        return "ID" in self.flags

    def as_sddl(self) -> str:
        return f"({self.ace_type};{self.flags};{self.mask};;;{self.sid})"


@dataclass
class SecurityDescriptor:
    owner: str = ""
    group: str = ""
    dacl_flags: str = ""
    aces: List[Ace] = field(default_factory=list)

    def as_sddl(self) -> str:
        ace_blob = "".join(ace.as_sddl() for ace in self.aces)
        return f"O:{self.owner}G:{self.group}D:{self.dacl_flags}{ace_blob}"


def run_cmd(cmd: List[str], check: bool = True) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or f"Command failed: {' '.join(cmd)}"
        raise RuntimeError(err)
    return (proc.stdout or "").strip()


def get_sddl(path: str) -> str:
    return run_cmd(["samba-tool", "ntacl", "get", "--as-sddl", path])


def set_sddl(path: str, sddl: str) -> str:
    return run_cmd(["samba-tool", "ntacl", "set", sddl, path])


def parse_sddl(sddl: str) -> SecurityDescriptor:
    if not sddl.startswith("O:"):
        raise ValueError(f"SDDL não reconhecida: {sddl}")

    g_idx = sddl.find("G:", 2)
    d_idx = sddl.find("D:", g_idx + 2 if g_idx != -1 else 2)
    if g_idx == -1 or d_idx == -1:
        raise ValueError(f"SDDL não reconhecida: {sddl}")

    owner = sddl[2:g_idx]
    group = sddl[g_idx + 2:d_idx]

    rest = sddl[d_idx + 2:]
    ace_start = rest.find("(")
    if ace_start == -1:
        dacl_flags = rest
        ace_blob = ""
    else:
        dacl_flags = rest[:ace_start]
        ace_blob = rest[ace_start:]

    aces: List[Ace] = []
    for chunk in re.findall(r"\(([^)]*)\)", ace_blob):
        parts = chunk.split(";")
        if len(parts) != 6:
            continue
        ace_type, flags, mask, _obj_guid, _inh_guid, sid = parts
        aces.append(Ace(ace_type=ace_type, flags=flags, mask=mask.lower(), sid=sid))
    return SecurityDescriptor(owner=owner, group=group, dacl_flags=dacl_flags, aces=aces)


def sid_to_name(sid: str) -> str:
    if sid in KNOWN_ALIASES:
        return KNOWN_ALIASES[sid]
    if sid.startswith("S-"):
        try:
            out = run_cmd(["wbinfo", "--sid-to-name", sid], check=False)
            if out:
                return out.rsplit(" ", 1)[0]
        except Exception:
            pass
    return sid


def name_to_sid(name: str) -> Optional[str]:
    if name in KNOWN_ALIASES:
        return name
    try:
        out = run_cmd(["wbinfo", "-n", name], check=False)
        if out:
            return out.split()[0]
    except Exception:
        pass
    return None


def normalize_principal(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Identidade vazia.")
    if raw in KNOWN_ALIASES:
        return raw
    if raw.startswith("S-"):
        return raw
    sid = name_to_sid(raw)
    if not sid:
        raise ValueError(f"Não foi possível resolver '{raw}' para SID.")
    return sid


def normalize_ace_type(value: str) -> str:
    ace_type = value.strip().upper()
    if ace_type not in ACE_TYPE_LABELS:
        raise ValueError(f"Tipo de ACE inválido: {value}")
    return ace_type


def normalize_perm(value: str) -> str:
    perm = value.strip().lower()
    if perm in PERM_MASKS:
        return PERM_MASKS[perm]
    value_lower = value.strip().lower()
    if value_lower in MASK_LABELS:
        return value_lower
    if re.fullmatch(r"0x[0-9a-fA-F]+", value.strip()):
        return value.strip().lower()
    raise ValueError(f"Permissão/máscara inválida: {value}")


def mask_to_label(mask: str) -> str:
    return MASK_LABELS.get(mask.lower(), mask)


def explain_inheritance(dacl_flags: str) -> str:
    if "P" in dacl_flags:
        return "Quebrada"
    if "AI" in dacl_flags or "AR" in dacl_flags:
        return "Herdada/auto-inherit"
    return "Indefinida"


def ace_to_dict(ace: Ace) -> Dict[str, str]:
    return {
        "type": ace.ace_type,
        "type_label": ACE_TYPE_LABELS.get(ace.ace_type, ace.ace_type),
        "flags": ace.flags,
        "mask": ace.mask,
        "mask_label": mask_to_label(ace.mask),
        "sid": ace.sid,
        "principal": sid_to_name(ace.sid),
        "inherited": ace.is_inherited(),
    }


def sd_to_dict(sd: SecurityDescriptor) -> Dict[str, object]:
    return {
        "owner": sd.owner,
        "owner_name": sid_to_name(sd.owner),
        "group": sd.group,
        "group_name": sid_to_name(sd.group),
        "inheritance": explain_inheritance(sd.dacl_flags),
        "dacl_flags": sd.dacl_flags,
        "sddl": sd.as_sddl(),
        "aces": [ace_to_dict(ace) for ace in sd.aces],
    }


def render_sd(sd: SecurityDescriptor) -> str:
    lines = []
    lines.append(f"Owner      : {sd.owner} ({sid_to_name(sd.owner)})")
    lines.append(f"Group      : {sd.group} ({sid_to_name(sd.group)})")
    lines.append(f"Herança    : {explain_inheritance(sd.dacl_flags)}")
    lines.append(f"DACL flags : {sd.dacl_flags or '-'}")
    lines.append("")
    lines.append("Permissões:")
    if not sd.aces:
        lines.append("  [nenhuma ACE]")
    for idx, ace in enumerate(sd.aces, 1):
        who = sid_to_name(ace.sid)
        inherited = "sim" if ace.is_inherited() else "não"
        scope = ace.flags or "-"
        lines.append(
            f"  [{idx}] {who} | {ACE_TYPE_LABELS.get(ace.ace_type, ace.ace_type)} | {mask_to_label(ace.mask)} | flags={scope} | herdada={inherited}"
        )
    return "\n".join(lines)


def break_inheritance(sd: SecurityDescriptor, keep_existing: bool = True) -> None:
    flags = sd.dacl_flags or ""
    if "P" not in flags:
        flags = "P" + flags
    if "AI" not in flags:
        flags += "AI"
    sd.dacl_flags = flags
    if keep_existing:
        for ace in sd.aces:
            ace.flags = ace.flags.replace("ID", "")
    else:
        sd.aces = [ace for ace in sd.aces if not ace.is_inherited()]


def enable_inheritance(sd: SecurityDescriptor) -> None:
    sd.dacl_flags = sd.dacl_flags.replace("P", "")


def add_permission(sd: SecurityDescriptor, sid: str, perm: str, flags: str = "OICI", ace_type: str = "A") -> None:
    sd.aces.append(
        Ace(
            ace_type=normalize_ace_type(ace_type),
            flags=flags.strip().upper(),
            mask=normalize_perm(perm),
            sid=normalize_principal(sid),
        )
    )


def add_permission_interactive(sd: SecurityDescriptor) -> None:
    raw = input("Usuário/grupo/SID: ").strip()
    print("Tipo de permissão:")
    print("  1) Leitura")
    print("  2) Leitura e escrita")
    print("  3) Controle total")
    opt = input("Escolha [1-3]: ").strip()
    perm_key = {"1": "read", "2": "modify", "3": "full"}.get(opt)
    if not perm_key:
        raise ValueError("Opção inválida.")
    flags = input("Flags de herança [padrão OICI]: ").strip().upper() or "OICI"
    ace_type = input("Tipo [A=allow, D=deny, padrão A]: ").strip().upper() or "A"
    add_permission(sd, raw, perm_key, flags=flags, ace_type=ace_type)


def remove_permission_by_index(sd: SecurityDescriptor, idx: int) -> Ace:
    if idx < 1 or idx > len(sd.aces):
        raise ValueError("Índice inválido.")
    return sd.aces.pop(idx - 1)


def remove_permission_interactive(sd: SecurityDescriptor) -> None:
    if not sd.aces:
        print("Nenhuma ACE para remover.")
        return
    print(render_sd(sd))
    raw = input("Índice da ACE a remover: ").strip()
    removed = remove_permission_by_index(sd, int(raw))
    print(f"Removido: {sid_to_name(removed.sid)} / {mask_to_label(removed.mask)}")


def parse_kv_spec(spec: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for chunk in spec.split(","):
        item = chunk.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"Parâmetro inválido em especificação: {item}")
        key, value = item.split("=", 1)
        data[key.strip().lower()] = value.strip()
    return data


def apply_add_specs(sd: SecurityDescriptor, specs: List[str], pending: List[str]) -> None:
    for spec in specs:
        data = parse_kv_spec(spec)
        principal = data.get("principal") or data.get("sid")
        if not principal:
            raise ValueError("Especificação --add exige 'principal=' ou 'sid='.")
        perm = data.get("perm") or data.get("mask")
        if not perm:
            raise ValueError("Especificação --add exige 'perm=' ou 'mask='.")
        flags = data.get("flags", "OICI")
        ace_type = data.get("type", "A")
        add_permission(sd, principal, perm, flags=flags, ace_type=ace_type)
        pending.append(f"adicionar permissão para {principal}")


def ace_matches_filters(ace: Ace, filters: Dict[str, str]) -> bool:
    principal = filters.get("principal")
    sid = filters.get("sid")
    ace_type = filters.get("type")
    mask = filters.get("mask")
    perm = filters.get("perm")
    inherited = filters.get("inherited")

    if principal:
        resolved = normalize_principal(principal)
        if ace.sid != resolved:
            return False
    if sid and ace.sid != sid:
        return False
    if ace_type and ace.ace_type != normalize_ace_type(ace_type):
        return False
    if mask and ace.mask != normalize_perm(mask):
        return False
    if perm and ace.mask != normalize_perm(perm):
        return False
    if inherited:
        expected = inherited.strip().lower()
        if expected not in {"yes", "no", "sim", "nao", "não", "true", "false"}:
            raise ValueError(f"Valor inválido para inherited: {inherited}")
        want_inherited = expected in {"yes", "sim", "true"}
        if ace.is_inherited() != want_inherited:
            return False
    return True


def remove_permissions_by_spec(sd: SecurityDescriptor, spec: str) -> List[Ace]:
    filters = parse_kv_spec(spec)
    removed: List[Ace] = []
    kept: List[Ace] = []
    for ace in sd.aces:
        if ace_matches_filters(ace, filters):
            removed.append(ace)
        else:
            kept.append(ace)
    sd.aces = kept
    return removed


def ensure_admin_warning(sd: SecurityDescriptor) -> Optional[str]:
    for ace in sd.aces:
        if ace.sid == "DA" and ace.mask.lower() == PERM_MASKS["full"] and ace.ace_type == "A":
            return None
    return "Aviso: não encontrei 'DA' (Domain Admins) com Controle total na ACL final."


def load_sd(path: str) -> tuple[str, SecurityDescriptor]:
    original_sddl = get_sddl(path)
    return original_sddl, parse_sddl(original_sddl)


def print_summary(original_sddl: str, staged: SecurityDescriptor) -> None:
    print("\n=== RESUMO ===")
    print("SDDL original:")
    print(original_sddl)
    print("\nSDDL final:")
    print(staged.as_sddl())
    warn = ensure_admin_warning(staged)
    if warn:
        print(f"\n{warn}")


def handle_interactive(path: str) -> int:
    try:
        original_sddl, staged = load_sd(path)
    except Exception as e:
        print(f"Erro ao ler ACL: {e}")
        return 2

    pending: List[str] = []

    while True:
        print("\n=== ACL atual em staging ===")
        print(render_sd(staged))
        print("\nAlterações pendentes:")
        if pending:
            for item in pending:
                print(f"  - {item}")
        else:
            print("  [nenhuma]")

        print("\nMenu:")
        print("  1) Desativar herança (converter herdadas em explícitas)")
        print("  2) Desativar herança (remover ACEs herdadas)")
        print("  3) Reativar herança")
        print("  4) Adicionar permissão")
        print("  5) Remover permissão")
        print("  6) Mostrar SDDL final")
        print("  7) Aplicar alterações")
        print("  8) Sair sem aplicar")
        choice = input("Escolha: ").strip()

        try:
            if choice == "1":
                break_inheritance(staged, keep_existing=True)
                pending.append("desativar herança convertendo ACEs herdadas em explícitas")
            elif choice == "2":
                break_inheritance(staged, keep_existing=False)
                pending.append("desativar herança removendo ACEs herdadas")
            elif choice == "3":
                enable_inheritance(staged)
                pending.append("reativar herança removendo a proteção da DACL")
            elif choice == "4":
                add_permission_interactive(staged)
                pending.append("adicionar permissão")
            elif choice == "5":
                remove_permission_interactive(staged)
                pending.append("remover permissão")
            elif choice == "6":
                print("\nSDDL final prevista:")
                print(staged.as_sddl())
            elif choice == "7":
                print_summary(original_sddl, staged)
                confirm = input("\nDigite SIM para aplicar: ").strip()
                if confirm == "SIM":
                    out = set_sddl(path, staged.as_sddl())
                    print("\nACL aplicada com sucesso.")
                    if out:
                        print(out)
                    return 0
                print("Aplicação cancelada.")
            elif choice == "8":
                print("Saindo sem aplicar alterações.")
                return 0
            else:
                print("Opção inválida.")
        except KeyboardInterrupt:
            print("\nInterrompido.")
            return 130
        except Exception as e:
            print(f"Erro: {e}")


def handle_show(path: str, as_json: bool) -> int:
    try:
        _original_sddl, sd = load_sd(path)
    except Exception as e:
        print(f"Erro ao ler ACL: {e}")
        return 2

    if as_json:
        print(json.dumps(sd_to_dict(sd), ensure_ascii=False, indent=2))
    else:
        print(render_sd(sd))
    return 0


def handle_set(args: argparse.Namespace) -> int:
    try:
        original_sddl, staged = load_sd(args.path)
    except Exception as e:
        print(f"Erro ao ler ACL: {e}")
        return 2

    pending: List[str] = []

    try:
        if args.enable_inheritance and args.disable_inheritance:
            raise ValueError("Use apenas uma entre --disable-inheritance e --enable-inheritance.")

        if args.enable_inheritance:
            enable_inheritance(staged)
            pending.append("reativar herança removendo a proteção da DACL")

        if args.disable_inheritance:
            keep_existing = not args.drop_inherited
            break_inheritance(staged, keep_existing=keep_existing)
            if keep_existing:
                pending.append("desativar herança convertendo ACEs herdadas em explícitas")
            else:
                pending.append("desativar herança removendo ACEs herdadas")

        if args.drop_inherited and not args.disable_inheritance:
            raise ValueError("--drop-inherited exige --disable-inheritance.")

        apply_add_specs(staged, args.add or [], pending)

        for idx in args.remove_index or []:
            removed = remove_permission_by_index(staged, idx)
            pending.append(f"remover ACE índice {idx} ({sid_to_name(removed.sid)})")

        for spec in args.remove or []:
            removed = remove_permissions_by_spec(staged, spec)
            if not removed:
                pending.append(f"nenhuma ACE correspondeu a remove '{spec}'")
            else:
                pending.append(f"remover {len(removed)} ACE(s) por filtro '{spec}'")
    except Exception as e:
        print(f"Erro ao montar ACL final: {e}")
        return 3

    if not pending:
        print("Nenhuma alteração solicitada. Use 'show' para apenas consultar ou passe opções ao comando 'set'.")
        return 1

    print(render_sd(staged))
    print_summary(original_sddl, staged)

    if args.dry_run or not args.apply:
        print("\nAlterações não aplicadas.")
        if not args.apply:
            print("Use --apply para confirmar a aplicação da ACL final.")
        return 0

    try:
        out = set_sddl(args.path, staged.as_sddl())
    except Exception as e:
        print(f"Erro ao aplicar ACL: {e}")
        return 4

    print("\nACL aplicada com sucesso.")
    if out:
        print(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ntacl_tool.py",
        description="Inspeciona e altera ACLs NT (SDDL) via Samba.",
        epilog=HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    interactive_parser = subparsers.add_parser(
        "interactive",
        help="abre o modo interativo",
        description="Abre um menu interativo para editar a ACL em staging e aplicar ao final.",
    )
    interactive_parser.add_argument("path", help="caminho do diretório/arquivo a consultar")

    show_parser = subparsers.add_parser(
        "show",
        help="mostra a ACL atual",
        description="Lê a ACL atual e exibe em texto ou JSON.",
    )
    show_parser.add_argument("path", help="caminho do diretório/arquivo a consultar")
    show_parser.add_argument("--json", action="store_true", dest="as_json", help="exibe a ACL em JSON")

    set_parser = subparsers.add_parser(
        "set",
        help="altera a ACL por parâmetros",
        description="Monta uma ACL final a partir da ACL atual e aplica as alterações pedidas.",
    )
    set_parser.add_argument("path", help="caminho do diretório/arquivo a alterar")
    set_parser.add_argument(
        "--disable-inheritance",
        action="store_true",
        help="desativa herança e protege a DACL; por padrão mantém ACEs herdadas como explícitas",
    )
    set_parser.add_argument(
        "--drop-inherited",
        action="store_true",
        help="junto com --disable-inheritance, remove ACEs herdadas em vez de convertê-las em explícitas",
    )
    set_parser.add_argument(
        "--enable-inheritance",
        action="store_true",
        help="reativa herança removendo a proteção da DACL atual",
    )
    set_parser.add_argument(
        "--add",
        action="append",
        metavar="SPEC",
        help="adiciona ACE. Ex.: principal=DOM\\\\usuario,perm=modify,flags=OICI,type=A",
    )
    set_parser.add_argument(
        "--remove-index",
        action="append",
        type=int,
        metavar="N",
        help="remove ACE pelo índice mostrado na listagem",
    )
    set_parser.add_argument(
        "--remove",
        action="append",
        metavar="SPEC",
        help="remove ACEs por filtro. Ex.: principal=DU,type=A ou sid=S-1-5-...,mask=0x001200a9",
    )
    set_parser.add_argument("--dry-run", action="store_true", help="mostra o resultado final sem aplicar")
    set_parser.add_argument("--apply", action="store_true", help="aplica efetivamente a ACL final")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    if not args_list:
        parser.print_help()
        return 1

    args = parser.parse_args(args_list)

    if args.command == "interactive":
        return handle_interactive(args.path)
    if args.command == "show":
        return handle_show(args.path, args.as_json)
    if args.command == "set":
        return handle_set(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
