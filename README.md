# onep-exporter — 1Password vault exporter and secure local backup

## Overview

onep-exporter exports your 1Password vaults and items to local files, packages them into a timestamped archive, and can optionally encrypt that archive client-side. It produces machine-readable JSON and human-readable Markdown, stores a `manifest.json` with checksums, and provides helpers for safe passphrase storage.

Note: the Python import package name is `onep_exporter` (use `import onep_exporter`). The user-facing CLI name is `onep-exporter`.

## Quick start

Install from source for development:

```bash
python -m pip install -e .
```

Show help:

```bash
onep-exporter --help
# or
python -m onep_exporter --help
```

Initialize configuration and store an age passphrase interactively:

```bash
onep-exporter init
```

Create an unencrypted backup:

```bash
onep-exporter backup --output ~/onep-backups
```

Verify a backup:

```bash
onep-exporter verify ~/onep-backups/<timestamp>/manifest.json
```

## Configuration

Default config file: `~/.config/onep-exporter/config.json` (override with `ONEP_EXPORTER_CONFIG`).

See `examples/config.example.json` for a sample configuration.

## Development & tests

Run tests with:

```bash
python -m pytest
```
