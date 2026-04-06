"""Age encryption helpers for onep-exporter."""

import hashlib
import re
from typing import TYPE_CHECKING, Optional, Union

from .utils import run_cmd, ensure_tool

if TYPE_CHECKING:
    from .exporter import OpExporter


class HashingWriter:
    """Writable file-like object that hashes bytes as they pass through.

    Used when streaming tar output through an encryptor subprocess so that
    the archive hash is computed without writing plaintext to disk.
    """

    def __init__(self, sink):
        self.sink = sink
        self.hasher = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.hasher.update(data)
        return self.sink.write(data)

    def flush(self):
        try:
            return self.sink.flush()
        except Exception:
            pass

    def close(self):
        try:
            return self.sink.close()
        except Exception:
            pass


def resolve_age_config(
    exporter: "OpExporter",
    *,
    age_pass_source: str,
    age_pass_item: Optional[str],
    age_pass_field: str,
    age_recipients: str,
    age_use_yubikey: bool,
    sync_passphrase_from_1password: bool,
    age_keychain_service: str,
    age_keychain_username: str,
) -> tuple[Optional[str], list[str]]:
    """Return *(passphrase, recipients)* for age encryption.

    The logic is executed early so we can fail before doing any network
    activity.  Raises ``RuntimeError`` on mis-configuration.
    """
    import os
    import getpass

    from .keychain import (
        get_passphrase_from_keychain,
        store_passphrase_in_keychain,
    )

    if not ensure_tool("age"):
        raise RuntimeError("age not found for encryption")

    recipients = [
        r.strip() for r in (age_recipients or "").split(",") if r.strip()
    ]
    if age_use_yubikey and not recipients:
        print(
            "warning: --age-use-yubikey set but no explicit recipient "
            "provided; ensure your yubikey recipient is added via "
            "--age-recipients if you want hardware unlock"
        )

    passphrase: Optional[str] = None
    stored_values: dict[str, str] = {}

    # collect any stored passphrases we are aware of (1Password / keychain)
    if age_pass_item:
        try:
            v = exporter.get_item_field_value(age_pass_item, age_pass_field)
        except Exception:
            v = None
        if v:
            stored_values["1password"] = v

    try:
        kc = get_passphrase_from_keychain(
            age_keychain_service, age_keychain_username
        )
    except Exception:
        kc = None
    if kc:
        stored_values["keychain"] = kc

    # if the caller asked to treat the 1Password value as authoritative,
    # copy it to other configured stores
    if sync_passphrase_from_1password and stored_values.get("1password"):
        auth = stored_values["1password"]
        os.environ["BACKUP_PASSPHRASE"] = auth
        stored_values["env"] = auth
        try:
            store_passphrase_in_keychain(
                age_keychain_service, age_keychain_username, auth
            )
            stored_values["keychain"] = auth
        except Exception as e:  # pragma: no cover - best effort
            raise RuntimeError(
                f"failed to store passphrase in keychain during sync: {e}"
            )

    # if we found values in multiple stores verify they all agree
    if len(stored_values) > 1:
        unique_vals = set(stored_values.values())
        if len(unique_vals) > 1:
            raise RuntimeError(
                f"passphrase mismatch between configured stores: "
                f"{', '.join(sorted(stored_values.keys()))}"
            )

    # pick a passphrase according to the requested source
    if age_pass_source == "env":
        passphrase = os.environ.get("BACKUP_PASSPHRASE")
    elif age_pass_source == "prompt":
        if not recipients:
            passphrase = getpass.getpass("Age passphrase for encryption: ")
    elif age_pass_source == "1password":
        if not age_pass_item:
            raise RuntimeError(
                "--age-pass-item is required when --age-pass-source=1password"
            )
        passphrase = exporter.get_item_field_value(
            age_pass_item, age_pass_field
        )
    elif age_pass_source == "keychain":
        try:
            passphrase = get_passphrase_from_keychain(
                age_keychain_service, age_keychain_username
            )
        except Exception as e:
            raise RuntimeError(
                f"failed to read passphrase from keychain: {e}"
            )

    if not passphrase and not recipients:
        if age_pass_source == "1password":
            raise RuntimeError(
                f"could not extract passphrase from the specified 1Password "
                f"item/field ('{age_pass_item}', '{age_pass_field}'). "
                "ensure the item exists, the field name is correct, and that "
                "it contains a non-empty string"
            )
        raise RuntimeError(
            "age encryption requires at least a passphrase or one recipient"
        )

    if passphrase and recipients:
        raise RuntimeError(
            "cannot use both a passphrase and recipients with age; "
            "specify only one mechanism (remove --age-recipients or "
            "disable the configured passphrase source)"
        )

    return passphrase, recipients


def resolve_decrypt_credentials(
    cfg: dict, *, verbose: Optional[bool] = None
) -> tuple[Optional[Union[str, tuple[str, str]]], Optional[str]]:
    """Resolve credentials for age decryption, preferring **local** stores.

    Returns ``(identity_or_none, passphrase_or_none)``.

    Resolution order (stops at first hit):

    1. ``AGE_IDENTITIES`` environment variable
    2. ``BACKUP_PASSPHRASE`` environment variable
    3. macOS keychain — ``age_private_key`` entry
    4. macOS keychain — passphrase entry
    5. Default age keys file (``~/.config/age/keys.txt``)
    6. 1Password item (if configured) — ``age_private_key`` field
    7. 1Password item (if configured) — passphrase field

    This function **never prompts** for input.
    """
    import os
    import sys
    from pathlib import Path

    from .config import _config_file_path
    from .keychain import get_passphrase_from_keychain

    age_cfg = cfg.get("age", {})
    kc_service = age_cfg.get("keychain_service", "onep-exporter")

    def _log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    # if caller didn't explicitly request verbose output, respect the
    # ONEP_EXPORTER_VERBOSE environment variable (off by default)
    if verbose is None:
        verbose = bool(os.environ.get("ONEP_EXPORTER_VERBOSE"))

    _log("resolving age decryption credentials …")
    _log(f"  config: {_config_file_path()}")
    _log(f"  age section: {age_cfg!r}")

    # 1. environment: identity file
    ids = os.environ.get("AGE_IDENTITIES")
    if ids:
        _log(f"  ✓ AGE_IDENTITIES env var → {ids}")
        return (ids, None)
    _log("  ✗ AGE_IDENTITIES env var not set")

    # 2. environment: passphrase
    env_pass = os.environ.get("BACKUP_PASSPHRASE")
    if env_pass:
        _log("  ✓ BACKUP_PASSPHRASE env var set")
        return (None, env_pass)
    _log("  ✗ BACKUP_PASSPHRASE env var not set")

    # 3. keychain: private key (stored under account "age_private_key")
    kc_key_desc = f"keychain service={kc_service!r} account='age_private_key'"
    try:
        priv = get_passphrase_from_keychain(kc_service, "age_private_key")
    except Exception as exc:
        priv = None
        _log(f"  ✗ {kc_key_desc}: {exc}")
    if priv:
        _log(
            f"  ✓ {kc_key_desc} → will stream identity via stdin (no temp file)"
        )
        return (("stdin", priv), None)
    if priv is None:
        _log(f"  ✗ {kc_key_desc}: not found")

    # 4. keychain: passphrase
    kc_username = age_cfg.get("keychain_username", "backup")
    kc_pass_desc = (
        f"keychain service={kc_service!r} account={kc_username!r}"
    )
    try:
        kc_pass = get_passphrase_from_keychain(kc_service, kc_username)
    except Exception as exc:
        kc_pass = None
        _log(f"  ✗ {kc_pass_desc}: {exc}")
    if kc_pass:
        _log(f"  ✓ {kc_pass_desc} → passphrase found")
        return (None, kc_pass)
    if kc_pass is None:
        _log(f"  ✗ {kc_pass_desc}: not found")

    # 5. default age keys file
    xdg = os.environ.get("XDG_CONFIG_HOME")
    keys_dir = (
        Path(xdg) / "age" if xdg else Path.home() / ".config" / "age"
    )
    keys_file = keys_dir / "keys.txt"
    if keys_file.is_file():
        _log(f"  ✓ default keys file → {keys_file}")
        return (str(keys_file), None)
    _log(f"  ✗ default keys file not found ({keys_file})")

    # 6/7. 1Password (remote — last resort)
    item_ref = age_cfg.get("pass_item")
    if item_ref:
        from .exporter import OpExporter

        _log(
            f"  … trying 1Password item {item_ref!r} (field 'age_private_key')"
        )
        exporter = None
        try:
            exporter = OpExporter()
            priv = exporter.get_item_field_value(
                item_ref, "age_private_key"
            )
            if priv:
                _log(
                    f"  ✓ 1Password age_private_key → will stream identity "
                    f"via stdin (no temp file)"
                )
                return (("stdin", priv), None)
            else:
                _log(
                    f"  ✗ 1Password item {item_ref!r} field "
                    f"'age_private_key': empty/missing"
                )
        except Exception as exc:
            _log(
                f"  ✗ 1Password item {item_ref!r} field "
                f"'age_private_key': {exc}"
            )
        # try passphrase field
        if exporter:
            pass_field = age_cfg.get("pass_field", "passphrase")
            _log(
                f"  … trying 1Password item {item_ref!r} (field {pass_field!r})"
            )
            try:
                passphrase = exporter.get_item_field_value(
                    item_ref, pass_field
                )
                if passphrase:
                    _log(f"  ✓ 1Password passphrase found")
                    return (None, passphrase)
                else:
                    _log(
                        f"  ✗ 1Password item {item_ref!r} field "
                        f"{pass_field!r}: empty/missing"
                    )
            except Exception as exc:
                _log(
                    f"  ✗ 1Password item {item_ref!r} field "
                    f"{pass_field!r}: {exc}"
                )
    else:
        _log("  ✗ no 1Password item configured (age.pass_item not set)")

    _log("  no credentials found")
    return (None, None)


def sync_age_credentials_to_keychain(
    exporter: "OpExporter",
    *,
    age_pass_item: Optional[str],
    age_pass_field: str = "passphrase",
    age_keychain_service: str = "onep-exporter",
    age_keychain_username: str = "backup",
    passphrase: Optional[str] = None,
) -> None:
    """Ensure age decryption credentials are available in local stores.

    Called during backup to copy secrets from 1Password into macOS keychain
    so that query-time operations can work without 1Password being available.
    """
    from .keychain import store_passphrase_in_keychain

    # sync private key
    if age_pass_item:
        try:
            priv = exporter.get_item_field_value(
                age_pass_item, "age_private_key"
            )
        except Exception:
            priv = None
        if priv:
            try:
                store_passphrase_in_keychain(
                    age_keychain_service, "age_private_key", priv
                )
            except Exception as e:
                print(
                    f"warning: failed to sync age private key to keychain: {e}"
                )

    # sync passphrase
    if passphrase:
        try:
            store_passphrase_in_keychain(
                age_keychain_service, age_keychain_username, passphrase
            )
        except Exception as e:
            print(f"warning: failed to sync passphrase to keychain: {e}")
    elif age_pass_item:
        try:
            pp = exporter.get_item_field_value(
                age_pass_item, age_pass_field
            )
        except Exception:
            pp = None
        if pp:
            try:
                store_passphrase_in_keychain(
                    age_keychain_service, age_keychain_username, pp
                )
            except Exception as e:
                print(
                    f"warning: failed to sync passphrase to keychain: {e}"
                )


def generate_age_keypair_and_store(
    exporter: "OpExporter", item_id: str
) -> Optional[str]:
    """Generate an age keypair, store private key in the given 1Password item.

    Returns the public recipient string on success, or None on failure.
    """
    from .keychain import store_passphrase_in_keychain

    if not ensure_tool("age-keygen"):
        print(
            "warning: 'age-keygen' not available; cannot generate age keypair"
        )
        return None

    try:
        _, out, _ = run_cmd(["age-keygen"])
    except Exception as e:
        print(f"warning: failed to generate age keypair: {e}")
        return None

    private_key = None
    pub = None

    # PEM-like block
    m_block = re.search(
        r"(-----BEGIN AGE (?:PRIVATE KEY|KEY FILE|KEY-FILE)-----"
        r".*?"
        r"-----END AGE (?:PRIVATE KEY|KEY FILE|KEY-FILE)-----)",
        out,
        re.S,
    )
    if m_block:
        private_key = m_block.group(1).strip()

    # AGE-SECRET-KEY token
    if not private_key:
        m_secret = re.search(r"(AGE-SECRET-KEY-[0-9A-Za-z\-_=]+)", out)
        if m_secret:
            private_key = m_secret.group(1).strip()

    # comment line fallback
    if not private_key:
        m_line = re.search(
            r"(?m)^\s*#?\s*(?:secret|secret key):\s*(\S+)", out
        )
        if m_line:
            private_key = m_line.group(1).strip()

    # public key
    m_pub = re.search(r"(?m)^\s*#?\s*public key:\s*(age1[0-9a-z]+)", out)
    if m_pub:
        pub = m_pub.group(1)
    else:
        m_any = re.search(r"(age1[0-9a-z]+)", out)
        if m_any:
            pub = m_any.group(1)

    if not private_key or not pub:
        print("warning: could not parse generated age keypair output")
        return None

    # Store private key in 1Password item
    try:
        exporter.upsert_item_field(
            item_id, "age_private_key", private_key
        )
    except Exception as e:
        print(f"warning: failed to store private key in 1Password: {e}")

    # Also store in local keychain
    try:
            store_passphrase_in_keychain(
                "onep-exporter", "age_private_key", private_key
            )
    except Exception as e:
        print(f"warning: failed to store private key in keychain: {e}")

    print(f"Generated age recipient: {pub}")
    return pub
