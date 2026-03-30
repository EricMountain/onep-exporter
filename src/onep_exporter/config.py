"""Configuration persistence and interactive setup for 1p-exporter."""

import json
from pathlib import Path
from typing import Optional

from .utils import run_cmd, ensure_tool


def _config_file_path() -> Path:
    """Return path to config file (respect ONEP_EXPORTER_CONFIG or XDG_CONFIG_HOME).

    Uses ``~/.config/1p-exporter/config.json`` by default; legacy
    ``onep-exporter`` path is still supported when loading.
    """
    import os

    cfg = os.environ.get("ONEP_EXPORTER_CONFIG")
    if cfg:
        return Path(cfg)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "1p-exporter" / "config.json"


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


def init_setup(
    *,
    passphrase: Optional[str] = None,
    generate: bool = False,
    store_in_1password: Optional[str] = None,
    onepassword_vault: Optional[str] = None,
    store_in_keychain: bool = False,
    keychain_service: str = "1p-exporter",
    keychain_username: str = "backup",
    onepassword_field: str = "passphrase",
) -> str:
    """Create or store an age passphrase according to provided options.

    Returns the plaintext passphrase (also stores it as requested).
    """
    import secrets
    import getpass

    from .exporter import OpExporter
    from .keychain import store_passphrase_in_keychain

    if generate and passphrase:
        raise RuntimeError("cannot specify --generate and --passphrase")
    if not passphrase:
        if generate:
            passphrase = secrets.token_urlsafe(32)
        else:
            passphrase = getpass.getpass("Passphrase to store: ")

    exporter = OpExporter()

    if store_in_1password:
        try:
            res = exporter.store_passphrase_in_1password(
                store_in_1password,
                onepassword_field,
                passphrase,
                vault=onepassword_vault,
            )
            if res.get("id"):
                print(
                    f"passphrase stored or already exists in 1Password item: {res.get('id')}"
                )
        except Exception as e:
            print(f"failed to store passphrase in 1Password: {e}")

    if store_in_keychain:
        try:
            store_passphrase_in_keychain(
                keychain_service, keychain_username, passphrase
            )
            print(
                f"stored passphrase in macOS Keychain: service={keychain_service} account={keychain_username}"
            )
        except Exception as e:
            print(f"failed to store passphrase in keychain: {e}")

    print("Passphrase (keep this safe):", passphrase)
    return passphrase


def configure_interactive() -> dict:
    """Interactive setup helper that prompts for common options and persists them.

    When age encryption is chosen, all secrets (private key, passphrase) are
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

    print("Interactive setup — configure defaults for 1p-exporter backups")
    cfg = load_config()

    def prompt(prompt_text: str, default: Optional[str] = None) -> str:
        if default:
            resp = input(f"{prompt_text} [{default}]: ")
            return resp.strip() or default
        return input(f"{prompt_text}: ").strip()

    output = prompt(
        "Default backup directory",
        cfg.get("output_base", str(Path.home() / "1p-backups")),
    )
    formats = prompt(
        "Default formats (comma-separated)",
        ",".join(cfg.get("formats", ["json", "md"])),
    )
    encrypt = prompt(
        "Default encryption (none/gpg/age)", cfg.get("encrypt", "age")
    )
    download_attachments = prompt(
        "Download attachments by default? (y/n)",
        "y" if cfg.get("download_attachments", True) else "n",
    )

    age_cfg = cfg.get("age", {})
    age_pass_source = None
    age_pass_item = None
    age_pass_field = "passphrase"
    age_keychain_service = age_cfg.get("keychain_service", "1p-exporter")
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
        ) or f"1p-exporter backup - {getpass.getuser()}"
        op_item_title = prompt(
            "1Password item title for backup secrets", default_title
        )
        op_vault = prompt(
            "1Password vault (optional)",
            age_cfg.get("onepassword_vault") or None,
        )
        age_pass_item = op_item_title

        # passphrase source (for backup-time retrieval)
        pass_source_choices = (
            "env/prompt/1password/keychain"
            if is_macos
            else "env/prompt/1password"
        )
        default_pass_source = age_cfg.get("pass_source", "1password")
        age_pass_source = prompt(
            f"age passphrase source ({pass_source_choices})",
            default_pass_source,
        )
        if is_macos and age_pass_source == "keychain":
            age_keychain_service = prompt(
                "Keychain service name", age_keychain_service
            )
            age_keychain_username = prompt(
                "Keychain account name", age_keychain_username
            )

        # --- ensure the 1Password item exists and inspect existing fields ---
        exporter = OpExporter()
        item = exporter.ensure_secrets_item(
            op_item_title, vault=op_vault or None
        )
        item_id = item.get("id")

        existing_private_key = item_field_value(item, "age_private_key")
        existing_passphrase = item_field_value(item, "passphrase")
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

        # --- passphrase ---
        if existing_passphrase:
            reuse_pp = prompt(
                "Existing passphrase found in 1Password. Reuse? (y/n)", "y"
            )
            if not reuse_pp.lower().startswith("y"):
                passphrase = secrets.token_urlsafe(32)
                try:
                    exporter.upsert_item_field(
                        item_id, "passphrase", passphrase
                    )
                except Exception as e:
                    print(
                        f"warning: failed to store passphrase in 1Password: {e}"
                    )
                print(
                    f"New passphrase stored in 1Password item "
                    f"'{op_item_title}', field 'passphrase'."
                )
                print(
                    f"To export it safely, use:  "
                    f"op item get '{op_item_title}' --field passphrase"
                )
            else:
                passphrase = existing_passphrase
            # sync passphrase to local keychain
            try:
                store_passphrase_in_keychain(
                    age_keychain_service, age_keychain_username, passphrase
                )
            except Exception as e:
                print(
                    f"warning: failed to sync passphrase to keychain: {e}"
                )
        else:
            gen_pp = prompt("Generate a new passphrase? (y/n)", "y")
            if gen_pp.lower().startswith("y"):
                passphrase = secrets.token_urlsafe(32)
            else:
                passphrase = getpass.getpass("Enter passphrase to store: ")
            try:
                exporter.upsert_item_field(
                    item_id, "passphrase", passphrase
                )
            except Exception as e:
                print(
                    f"warning: failed to store passphrase in 1Password: {e}"
                )
            # sync passphrase to local keychain
            try:
                store_passphrase_in_keychain(
                    age_keychain_service, age_keychain_username, passphrase
                )
            except Exception as e:
                print(
                    f"warning: failed to sync passphrase to keychain: {e}"
                )
            print(
                f"Passphrase stored in 1Password item "
                f"'{op_item_title}', field 'passphrase'."
            )
            print(
                f"To export it safely, use:  "
                f"op item get '{op_item_title}' --field passphrase"
            )

    # assemble global config
    new_cfg = {
        "output_base": output,
        "formats": [f.strip() for f in formats.split(",") if f.strip()],
        "encrypt": encrypt,
        "download_attachments": download_attachments.lower().startswith("y"),
        "age": {
            "pass_source": age_pass_source,
            "pass_item": age_pass_item,
            "pass_field": age_pass_field,
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
