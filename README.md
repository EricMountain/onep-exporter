# 1p-exporter — 1Password vault exporter and secure local backup

## Overview

1p-exporter exports all your 1Password vaults/items to local files, packages them into a timestamped archive, and optionally encrypts that archive client‑side. It produces machine‑readable JSON and human‑readable Markdown, stores a `manifest.json` with checksums, and provides helpers for safe passphrase storage.

Note: the Python import package name remains `onep_exporter` (use `import onep_exporter`); the user-facing project/CLI name is `1p-exporter`.

## Features

- Export vaults/items using the `op` CLI (requires sign‑in or `OP_SESSION_*`)
- Per‑vault `JSON` and `Markdown` exports
- Attachment download (best‑effort) and `manifest.json` with SHA256 checksums
- Optional client‑side encryption with `age` (recommended) or symmetric `gpg`
- Interactive `init` flow and persistent configuration (`~/.config/1p-exporter/config.json`)
- Helpers to store/retrieve passphrases in 1Password or macOS Keychain (Touch ID supported)

## Prerequisites

- `op` — 1Password CLI
  - MacOS `brew install 1password-cli`
- `age` for encryption (install via Homebrew or your distro package manager)
  - MacOS `brew install age`
- macOS: `security` CLI (built‑in) or Python `keyring` for Keychain integration

## Installation

1. Install pipx (only once):

     ```shell
     python3 -m pip install --user pipx
     # or use OS package manager, e.g:
     brew install pipx
     ```

2. Install 1p-exporter (not published on PyPI)

   Install using `pipx` from the project's Git repository, or install from source.

   - Install via `pipx` from GitHub (recommended):

     ```shell
     pipx install git+https://github.com/<owner>/<repo>.git
     ```

   - Or install from local source if checked out (development):

     ```shell
     python3 -m pipx install --user .
     ```

### Quick verification

After installation, check the CLI is available:

```shell
onep-exporter --help   # or try 1p-exporter --help
```

If neither command runs, use:

```shell
python -m onep_exporter --help
```

### First-time setup (after install)

1. Ensure the 1Password CLI is signed in:

   ```shell
   op signin
   ```

2. Run the interactive setup to create and store an encryption passphrase and save defaults:

   ```shell
   onep-exporter init
   ```

3. Create a backup:

   ```shell
   onep-exporter backup --output ~/onep-backups
   ```

### Updating

- If installed with `pipx` from a Git URL, re-run the same `pipx install` command to upgrade, or:

  ```shell
  pipx upgrade --pip-args="--upgrade" 1p-exporter
  ```

### Uninstall

- pipx:

  ```shell
  pipx uninstall 1p-exporter
  ```

### Notes & troubleshooting

- Your saved configuration and any stored passphrases are preserved across upgrades (the config live under `~/.config/1p-exporter/`).  
- If you need help connecting `op` (1Password CLI), see the [1Password CLI docs](https://developer.1password.com/docs/cli/).

## Quick start

Sign in (interactive):

```bash
op signin <your-domain>
# or
1p-exporter init --signin
```

Run a backup (unencrypted):

```bash
1p-exporter backup --output ~/onep-backups
```

Verify the backup:

```bash
1p-exporter verify ~/onep-backups/<timestamp>/manifest.json
```

## Interactive setup & helpers

- `1p-exporter init` — interactive configuration; can generate/store an `age` passphrase in 1Password or Keychain and persists defaults.
- Programmatic helpers: `configure_interactive()`, `init_setup()`, `OpExporter.signin_interactive()`

## Encryption

- `gpg` (symmetric): passphrase via `BACKUP_PASSPHRASE` env or prompt.
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
1p-exporter backup --encrypt age --age-pass-source 1password --age-pass-item "Backup Passphrase"

# age passphrase from macOS Keychain (Touch ID may prompt)
1p-exporter backup --encrypt age --age-pass-source keychain
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
- `1p-exporter backup [--encrypt age|gpg|none]` — run export (CLI overrides config)
- `1p-exporter browse` - run a TUI to browse archives.
- `1p-exporter verify <manifest.json>` — verify manifest integrity
- `1p-exporter query list <regexp> [--dir DIR] [--age-identity PATH] [--age-passphrase PASS]` — inspect existing exports and print item titles that match the given regular expression (default directory is current working directory).  When the target is an encrypted archive the command will attempt to decrypt it using the `age` tool.  Decryption credentials may be provided in several ways:
  - `--age-identity PATH` (repeatable) or `AGE_IDENTITIES` env var – path(s) to age identity file(s).
  - `--age-passphrase PASS` or `BACKUP_PASSPHRASE` env var – symmetric passphrase (user will need to supply it manually since age does not support non‑interactive passphrase input).
  - **automatic lookup** – if no credentials are supplied the tool will consult your saved configuration and, if you previously stored an age private key/passphrase in 1Password or the macOS keychain, it will fetch them and use them transparently.

### Query examples

```bash
# find every exported item whose title contains "github"
1p-exporter query list github --dir ~/onep-backups/20250101T120000Z
```

- `1p-exporter query list <regexp> [--dir DIR]` — search exported JSON files for item titles matching a regular expression

## Development & tests

```bash
python -m pytest
```

### Development environment (direnv)

- A `.envrc` is provided in the project root to automatically add `src/` to `PYTHONPATH` and expose the project's `.venv/bin` on `PATH`.
- After installing `direnv` and adding its shell hook to your shell, run:

```bash
direnv allow
```

You can still run the package without direnv using `PYTHONPATH=src .venv/bin/python -m onep_exporter ...`.

## References

- 1Password CLI: [1Password CLI docs](https://developer.1password.com/docs/cli/)
- age: [age encryption](https://age-encryption.org/)
- sops: [mozilla/sops](https://github.com/mozilla/sops)

## Dev Setup Notes

### MacOS

- Ensure `op` and `age` are installed
  - `brew install 1password-cli`
  - `brew install age`
- Run `op account add`: should report 1Password CLI is connected with the 1Password app.
- Run `op signin`: should be prompted to authorise 1Password access.
  - **macOS "access data from other apps" prompt:**
    The `op` CLI communicates with the 1Password desktop app through its group
    container.  On macOS Sequoia (15+) this triggers an "App Data" permission
    prompt: *"iTerm.app would like to access data from other apps."*
    - Click **Allow** — the decision should be remembered.  If macOS keeps
      prompting on every `op` call restart iTerm/Terminal.
- [Setup](https://developer.1password.com/docs/cli/app-integration/#set-up-the-app-integration) the `op` to `1Password` integration
- `python -m onep_exporter doctor`
  - Need `age` and `op` installed.
  - It's OK if the `config` is missing at this point.
- `python -m onep_exporter init`
  - Accept all defaults
  - `doctor` run at the end should be all green
