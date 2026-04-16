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
    age_recipients: str,
    age_use_yubikey: bool,
) -> list[str]:
    """Return the list of age *recipients* for encryption.

    """
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

    if not recipients:
        raise RuntimeError(
            "age encryption requires at least one recipient (no passphrases)"
        )

    return recipients


def resolve_decrypt_credentials(
    cfg: dict, *, verbose: Optional[bool] = None
) -> tuple[Optional[Union[str, tuple[str, str]]], Optional[str]]:
    """Resolve credentials for age decryption, preferring **local** stores.

    Returns ``(identity_or_none, None)``. Passphrase-based decryption is no
    longer supported; only identity-based mechanisms (AGE_IDENTITIES,
    keychain/private key file, or default keys file) are considered.

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

    # 2. keychain: private key (stored under account "age_private_key")
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

    # 3. default age keys file
    xdg = os.environ.get("XDG_CONFIG_HOME")
    keys_dir = (
        Path(xdg) / "age" if xdg else Path.home() / ".config" / "age"
    )
    keys_file = keys_dir / "keys.txt"
    if keys_file.is_file():
        _log(f"  ✓ default keys file → {keys_file}")
        return (str(keys_file), None)
    _log(f"  ✗ default keys file not found ({keys_file})")

    # 4. 1Password (remote — last resort)
    item_ref = age_cfg.get("pass_item")
    if item_ref:
        from .exporter import OpExporter

        _log(
            f"  … trying 1Password item {item_ref!r} (field 'age_private_key')"
        )
        try:
            exporter = OpExporter()
            priv = exporter.get_item_field_value(item_ref, "age_private_key")
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
                f"  ✗ 1Password item {item_ref!r} field 'age_private_key': {exc}"
            )
    else:
        _log("  ✗ no 1Password item configured (age.pass_item not set)")

    _log("  no credentials found")
    return (None, None)


def sync_age_credentials_to_keychain(
    exporter: "OpExporter",
    *,
    age_pass_item: Optional[str],
    age_keychain_service: str = "onep-exporter",
    age_keychain_username: str = "backup",
) -> None:
    """Ensure age private key is available in local keychain.

    Called during backup to copy the ``age_private_key`` field from a
    configured 1Password item into the macOS keychain so that
    query-time operations can work without 1Password being available.
    """
    from .keychain import store_passphrase_in_keychain

    # sync private key
    if age_pass_item:
        try:
            priv = exporter.get_item_field_value(age_pass_item, "age_private_key")
        except Exception:
            priv = None
        if priv:
            try:
                store_passphrase_in_keychain(age_keychain_service, age_keychain_username, priv)
            except Exception as e:
                print(f"warning: failed to sync age private key to keychain: {e}")


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
