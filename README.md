# 1p-exporter — 1Password vault exporter and secure local backup

## Overview

1p-exporter exports all your 1Password vaults/items to local files, packages them into a timestamped archive, and optionally encrypts that archive client‑side. It produces machine‑readable JSON and human‑readable Markdown, stores a `manifest.json` with checksums, and provides helpers for safe passphrase storage.

Note: the Python import package name remains `onep_exporter` (use `import onep_exporter`); the user-facing project/CLI name is `1p-exporter`.

## Features

- Export vaults/items using the `op` CLI (requires sign‑in or `OP_SESSION_*`)
- Per‑vault `JSON` and `Markdown` exports
- Attachment download (best‑effort) and `manifest.json` with SHA256 checksums
- Optional client‑side encryption with `age` (recommended)
- Interactive `init` flow and persistent configuration (`~/.config/1p-exporter/config.json`)
- Helpers to store/retrieve passphrases in 1Password or macOS Keychain (Touch ID supported)

## Installation

1. Install `pipx`, 1Password CLI (`op`) and `age` using the system package manager, e.g:

     ```shell
     brew install pipx
     brew install 1password-cli
     brew install age
     ```

2. Install 1p-exporter

   - Install via `pipx` from GitHub (recommended):

     ```shell
     pipx install git+https://github.com/EricMountain/onep-exporter.git
     ```

   - Or install from local source if checked out (development):

     ```shell
     python3 -m pipx install --user .
     ```

### Setup

- Ensure the 1Password app has [1Password CLI integration enabled](https://developer.1password.com/docs/cli/app-integration/#set-up-the-app-integration)
  - Settings → Developer → Integrate with 1Password CLI

- Run interactive setup

   ```shell
   onep-exporter init
   ```

- By default, MacOS' `security` app gets access to onep-exporter's secrets stored in the keychain. So an unlocked laptop gives direct access to 1Password exports.
  - Open the MacOS `keychain` app (_not_ the Passwords app)
  - In the `login` keychain, open the `onep-exporter` entry (or whatever `onep_exporter keychain list` reports for `keychain_service`)
  - Open the Access Control tab
    - Remove "security" from the list of authorised apps
    - Select "Confirm before allowing access"
    - Save changes

- Create a backup

   ```shell
   onep-exporter backup
   ```

- Browse the backup

    ```shell
    onep-exporter browse
    ```

### Updating

If installed with `pipx` from a Git URL, re-run the same `pipx install` command to upgrade, or:

```shell
pipx upgrade --pip-args="--upgrade" onep-exporter
```

### Uninstall

pipx:

```shell
pipx uninstall onep-exporter
```

### Notes & troubleshooting

- Your saved configuration and any stored passphrases are preserved across upgrades (the config live under `~/.config/1p-exporter/`).  
- If you need help connecting `op` (1Password CLI), see the [1Password CLI docs](https://developer.1password.com/docs/cli/).

## Encryption

- `age` (recommended): supports passphrase recipients and public‑key recipients.
  - `--age-pass-source` may be `env`, `prompt`, `1password`, or `keychain`.
  - If the passphrase is present in multiple stores (1Password, Keychain, or the `BACKUP_PASSPHRASE` env), 1p-exporter will verify they are identical and will abort if they differ.
  - Use `--sync-passphrase-from-1password` to treat the value in 1Password as authoritative and copy it to other configured stores (keychain/ENV) before encrypting.
  - Use `--age-recipients` to include public recipients (e.g. YubiKey‑backed identities).
  *Note:* age does **not** allow combining an explicit recipient list with the
  `--passphrase` mode.  1p‑exporter will abort if both a passphrase is
  configured (via env/1password/keychain) and one or more recipients are
  specified; pick one method or remove the undesired value from your
  configuration.  (If `pass_source` is set to `prompt` and recipients are present,
  the prompt is skipped – the recipient list takes precedence.)  The
  `doctor` command also checks for conflicting settings and will report an
  error before you run a backup.

Examples:

```bash
# age passphrase from a 1Password item (field defaults to "passphrase")
onep-exporter backup --encrypt age --age-pass-source 1password --age-pass-item "Backup Passphrase"

# age passphrase from macOS Keychain
onep-exporter backup --encrypt age --age-pass-source keychain
```

By default the tool looks for a field named **passphrase** in the referenced
1Password item.  You can override it with the `--age-pass-field` CLI option or
`age.pass_field` in the config; if you specify a name and the field is not
found or no field name is provided, the backup will abort.

## Configuration

- Default config file: `~/.config/onep-exporter/config.json`.
  - On Windows the tool uses an XDG-style `~/.config/onep-exporter/config.json` path.
  - Override with: `ONEP_EXPORTER_CONFIG=/path/to/config.json`
- CLI flags override saved config values.

Use the `init` subcommand to build a config.

## Commands (summary)

- `1p-exporter init` — interactive setup and optional passphrase storage
- `1p-exporter backup [--encrypt age|none]` — run export (CLI overrides config)
- `1p-exporter browse` - run a TUI to browse archives.
- `1p-exporter verify <manifest.json>` — verify manifest integrity
- `1p-exporter query list <regexp> [--dir DIR] [--age-identity PATH] [--age-passphrase PASS]` — inspect existing exports and print item titles that match the given regular expression (default directory is current working directory).  When the target is an encrypted archive the command will attempt to decrypt it using the `age` tool.  Decryption credentials may be provided in several ways:
  - `--age-identity PATH` (repeatable) or `AGE_IDENTITIES` env var – path(s) to age identity file(s).
  - `--age-passphrase PASS` or `BACKUP_PASSPHRASE` env var – symmetric passphrase (user will need to supply it manually since age does not support non‑interactive passphrase input).
  - **automatic lookup** – if no credentials are supplied the tool will consult your saved configuration and, if you previously stored an age private key/passphrase in 1Password or the macOS keychain, it will fetch them and use them transparently.

### Query examples

```bash
# find every exported item whose title contains "github"
1p-exporter query list github
```

## Development & tests

### Development environment (direnv)

- A `.envrc` is provided in the project root to automatically add `src/` to `PYTHONPATH` and expose the project's `.venv/bin` on `PATH`.
- After installing `direnv` and adding its shell hook to your shell, run:

```bash
direnv allow
```

You can still run the package without direnv using `PYTHONPATH=src .venv/bin/python -m onep_exporter ...`.

### Run tests

```bash
make test
```

## References

- 1Password CLI: [1Password CLI docs](https://developer.1password.com/docs/cli/)
- age: [age encryption](https://age-encryption.org/)
- sops: [mozilla/sops](https://github.com/mozilla/sops)
