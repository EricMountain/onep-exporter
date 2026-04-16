"""Configuration persistence and interactive setup for onep-exporter."""

import json
from pathlib import Path
from typing import Optional

from .utils import run_cmd, ensure_tool


def _config_file_path() -> Path:
    """Return path to config file (respect ONEP_EXPORTER_CONFIG or XDG_CONFIG_HOME).

    Uses ``~/.config/onep-exporter/config.json`` by default; legacy
    ``onep-exporter`` path is still supported when loading.
    """
    import os

    cfg = os.environ.get("ONEP_EXPORTER_CONFIG")
    if cfg:
        return Path(cfg)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "onep-exporter" / "config.json"


def save_config(data: dict) -> Path:
    """Save configuration (JSON) to the configured config file location and restrict file perms."""
    p = _config_file_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    try:
        p.chmod(0o600)
    except Exception:
        pass
    return p


def load_config() -> dict:
    """Load configuration from the configured config file location."""
    p = _config_file_path()
    if p.exists():
        try:
            with p.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            import sys

            print(
                f"warning: failed to parse config {p}: {exc}", file=sys.stderr
            )
            return {}
    # fallback to legacy config path (``onep-exporter``) for backward compatibility
    legacy = p.parent.parent / "onep-exporter" / p.name
    if legacy.exists():
        try:
            with legacy.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            import sys

            print(
                f"warning: failed to parse config {legacy}: {exc}",
                file=sys.stderr,
            )
            return {}
    return {}



def configure_interactive() -> dict:
    """Interactive setup helper that prompts for common options and persists them.

    When age encryption is chosen, recipients and private key are
    stored in a single 1Password Secure Note item.  Existing secrets are
    detected and the user is offered the choice to reuse or overwrite them.
    """
    import getpass
    import os
    import secrets

    from .exporter import OpExporter
    from .encryption import generate_age_keypair_and_store
    from .keychain import store_passphrase_in_keychain
    from .utils import item_field_value

    print("Interactive setup — configure defaults for onep-exporter backups")
    cfg = load_config()

    def prompt(prompt_text: str, default: Optional[str] = None) -> str:
        if default:
            resp = input(f"{prompt_text} [{default}]: ")
            return resp.strip() or default
        return input(f"{prompt_text}: ").strip()

    output = prompt(
        "Default backup directory",
        cfg.get("backup_directory", cfg.get("output_base", str(Path.home() / "1p-backups"))),
    )
    formats = prompt(
        "Default formats (comma-separated)",
        ",".join(cfg.get("formats", ["json", "md"])),
    )
    encrypt = prompt(
        "Default encryption (none/age)", cfg.get("encrypt", "age")
    )
    download_attachments = prompt(
        "Download attachments by default? (y/n)",
        "y" if cfg.get("download_attachments", True) else "n",
    )

    age_cfg = cfg.get("age", {})
    age_pass_item = None
    age_keychain_service = age_cfg.get("keychain_service", "onep-exporter")
    age_keychain_username = age_cfg.get("keychain_username", "backup")
    age_recipients = age_cfg.get("recipients", "")
    age_use_yubikey = age_cfg.get("use_yubikey", False)
    op_vault = None

    if encrypt == "age":
        import sys

        is_macos = sys.platform == "darwin"

        # --- single 1Password item for all secrets ---
        default_title = age_cfg.get(
                "pass_item"
            ) or f"onep-exporter backup - {getpass.getuser()}"
        op_item_title = prompt(
            "1Password item title for backup secrets", default_title
        )
        op_vault = prompt(
            "1Password vault (optional)",
            age_cfg.get("onepassword_vault") or None,
        )
        age_pass_item = op_item_title

        # --- (no passphrase support) ---
        # The 1Password item is used to hold the age private key and the
        # configured recipients.  We still allow selecting a vault.

        # --- ensure the 1Password item exists and inspect existing fields ---
        exporter = OpExporter()
        item = exporter.ensure_secrets_item(
            op_item_title, vault=op_vault or None
        )
        item_id = item.get("id")


        existing_private_key = item_field_value(item, "age_private_key")
        existing_recipients = item_field_value(item, "age_recipients")

        # --- age keypair ---
        generated_pub = None
        if existing_private_key:
            reuse = prompt(
                "Existing age private key found in 1Password. Reuse? (y/n)",
                "y",
            )
            if not reuse.lower().startswith("y"):
                generated_pub = generate_age_keypair_and_store(
                    exporter, item_id
                )
            else:
                # sync existing private key to local keychain
                try:
                    store_passphrase_in_keychain(
                        age_keychain_service,
                        "age_private_key",
                        existing_private_key,
                    )
                except Exception as e:
                    print(
                        f"warning: failed to sync private key to keychain: {e}"
                    )
        else:
            gen_key = prompt("Generate a new age keypair? (y/n)", "y")
            if gen_key.lower().startswith("y"):
                generated_pub = generate_age_keypair_and_store(
                    exporter, item_id
                )

        # --- recipients ---
        default_recipients = existing_recipients or age_recipients or ""
        if generated_pub:
            parts = [
                r.strip()
                for r in default_recipients.split(",")
                if r.strip()
            ]
            if generated_pub not in parts:
                parts.append(generated_pub)
            default_recipients = ",".join(parts)

        age_recipients = prompt(
            "Age recipients (comma-separated public recipients)",
            default_recipients or None,
        )
        # store recipients in 1P item
        if age_recipients:
            try:
                exporter.upsert_item_field(
                    item_id,
                    "age_recipients",
                    age_recipients,
                    field_type="TEXT",
                )
            except Exception as e:
                print(
                    f"warning: failed to store recipients in 1Password: {e}"
                )

        yub = prompt(
            "Include YubiKey recipient by default? (y/n)",
            "y" if age_use_yubikey else "n",
        )
        age_use_yubikey = yub.lower().startswith("y")

    # assemble global config
    new_cfg = {
        "backup_directory": output,
        "formats": [f.strip() for f in formats.split(",") if f.strip()],
        "encrypt": encrypt,
        "download_attachments": download_attachments.lower().startswith("y"),
        "age": {
            "pass_item": age_pass_item,
            "recipients": age_recipients,
            "use_yubikey": bool(age_use_yubikey),
            "keychain_service": age_keychain_service,
            "keychain_username": age_keychain_username,
            "onepassword_vault": op_vault or None,
        },
    }

    save_config(new_cfg)
    print(f"Configuration saved to {_config_file_path()}")
    return new_cfg
