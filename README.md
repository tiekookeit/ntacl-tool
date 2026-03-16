# ntacl_tool

Python utility for inspecting and changing NT ACLs (SDDL) on files and directories through `samba-tool`.

The script is intended for Samba / Active Directory environments where you need to:

- Inspect the current NT ACL of a path.
- View owner, group, inheritance, and ACEs in a readable format.
- Disable or re-enable ACL inheritance.
- Add or remove permissions.
- Apply changes either interactively or directly through command-line parameters.

## What This Project Does

The project contains a single main script: [ntacl_tool.py](./ntacl_tool.py).

It uses:

- `samba-tool ntacl get --as-sddl` to read the current ACL.
- `samba-tool ntacl set` to apply the final ACL.
- `wbinfo` to resolve names and SIDs when needed.

## Usage Modes

The script supports two operation styles:

- Interactive mode: opens a menu with staging before applying changes.
- Direct mode: receives changes through parameters, useful for automation and scripts.

Available subcommands:

- `interactive`: opens the interactive menu.
- `show`: displays the current ACL.
- `set`: changes the ACL through parameters.

If you run the script without arguments, it displays a full help message with all supported features and examples.

## Dependencies

### Python

The script uses only Python 3 standard library modules:

- `argparse`
- `json`
- `re`
- `subprocess`
- `sys`
- `dataclasses`
- `typing`

There are no Python dependencies to install with `pip`.

### Required Debian Packages

For the script to work on Debian, the minimum required components are:

- `python3`: Python interpreter.
- `samba-common-bin`: provides the `samba-tool` command.
- `winbind`: provides the `wbinfo` command.

Ready-to-use installation command:

```bash
sudo apt update
sudo apt install -y python3 samba-common-bin winbind
```

Official Debian package references used to confirm the packages:

- `samba-tool` is provided by `samba-common-bin`:
  https://packages.debian.org/bookworm/amd64/samba-common-bin/filelist
- `wbinfo` is provided by `winbind`:
  https://packages.debian.org/sid/amd64/winbind/filelist
- `winbind` package details on Debian:
  https://packages.debian.org/bookworm/winbind

### Operational Prerequisites

Besides installing the packages, the environment must already have Samba installed and configured in a way that supports:

- the `samba-tool` command;
- `samba-tool ntacl` operations;
- `wbinfo -u` listing domain users;
- `wbinfo -g` listing domain groups.

Recommended quick checks:

```bash
samba-tool --help
wbinfo -u
wbinfo -g
```

Expected behavior:

- `samba-tool --help` should run successfully.
- `wbinfo -u` should list users.
- `wbinfo -g` should list groups.

If these commands do not work, this tool will not operate correctly.

## Important Environment Notes

Installing the packages alone is not sufficient if the server is not correctly integrated with the Samba / AD environment.

In practice, for the script to work usefully, the host usually needs to:

- Have access to the Samba / AD environment.
- Have Samba installed and configured.
- Be able to execute `samba-tool ntacl`.
- Be able to resolve users and groups through `wbinfo`.
- Be able to list users with `wbinfo -u`.
- Be able to list groups with `wbinfo -g`.

If `wbinfo` cannot resolve names or SIDs, the script may still work partially, but friendly identity display and some name-based operations may fail.

## Usage Examples

### Show General Help

```bash
python3 ntacl_tool.py
```

or:

```bash
python3 ntacl_tool.py --help
```

### Interactive Mode

```bash
python3 ntacl_tool.py interactive /path/folder
```

### Show Current ACL

```bash
python3 ntacl_tool.py show /path/folder
```

### Show Current ACL as JSON

```bash
python3 ntacl_tool.py show /path/folder --json
```

### Disable Inheritance Without Applying

```bash
python3 ntacl_tool.py set /path/folder --disable-inheritance --dry-run
```

To disable inheritance and remove inherited ACEs:

```bash
python3 ntacl_tool.py set /path/folder --disable-inheritance --drop-inherited --dry-run
```

To re-enable inheritance:

```bash
python3 ntacl_tool.py set /path/folder --enable-inheritance --dry-run
```

### Add a Permission

```bash
python3 ntacl_tool.py set /path/folder \
  --add "principal=DOMAIN\\user,perm=modify,flags=OICI,type=A" \
  --dry-run
```

Accepted fields for `--add`:

- `principal` or `sid`: user, group, known alias, or SID.
- `perm` or `mask`: `read`, `modify`, `full`, or a hexadecimal mask.
- `flags`: inheritance flags, for example `OICI`.
- `type`: `A` for allow or `D` for deny.

### Remove a Permission by Index

```bash
python3 ntacl_tool.py set /path/folder --remove-index 2 --dry-run
```

### Remove a Permission by Filter

```bash
python3 ntacl_tool.py set /path/folder \
  --remove "principal=DU,type=A" \
  --dry-run
```

Examples of accepted filters in `--remove`:

- `principal=DU`
- `sid=S-1-5-...`
- `type=A`
- `perm=read`
- `mask=0x001200a9`
- `inherited=yes`

### Apply the Final ACL for Real

```bash
python3 ntacl_tool.py set /path/folder \
  --disable-inheritance \
  --add "principal=DA,perm=full,flags=OICI,type=A" \
  --apply
```

## Operational Safety

The `set` mode does not apply changes without `--apply`.

If you use only `--dry-run`, the script:

- builds the final ACL;
- shows the predicted ACL;
- shows the final SDDL;
- does not run `samba-tool ntacl set`.

The script also emits a warning if it does not find `DA` (`Domain Admins`) with full control in the final ACL.

## Current Limitations

- The SDDL parser is simplified and may not cover every possible format.
- The project does not yet include an automated test suite.
- Behavior depends on external tools such as `samba-tool` and `wbinfo`.

## Project Structure

```text
.
├── doc/
│   ├── manual-en.html
│   └── manual-pt.html
├── ntacl_tool.py
└── README.md
```
