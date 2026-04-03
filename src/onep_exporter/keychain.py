"""macOS keychain and cross-platform keyring helpers for 1p-exporter."""

import sys
from typing import List, Optional

from .utils import run_cmd


def _macos_find_password(service: str, username: str) -> Optional[str]:
    """Read a generic-password item using macOS ``security`` CLI."""
    rc, out, _ = run_cmd(
        [
            "security",
            "find-generic-password",
            "-s",
            service,
            "-a",
            username,
            "-w",
        ],
        check=False,
    )
    if rc != 0:
        return None
    return out.strip() or None


def _exporter_keychain_targets(
    cfg: Optional[dict] = None,
    *,
    service: Optional[str] = None,
    accounts: Optional[List[str]] = None,
) -> List[tuple[str, str]]:
    """Return candidate (service, account) tuples used by 1p-exporter."""
    cfg = cfg or {}
    age_cfg = cfg.get("age", {})

    services = []
    if service:
        services.append(service)
    else:
        configured = age_cfg.get("keychain_service")
        if configured:
            services.append(configured)
        services.append("1p-exporter")

    account_values = []
    if accounts:
        account_values.extend(accounts)
    else:
        configured_user = age_cfg.get("keychain_username")
        if configured_user:
            account_values.append(configured_user)
        account_values.extend(["backup", "age_private_key"])

    pairs = {(svc, acct) for svc in services for acct in account_values if svc and acct}
    return sorted(pairs)


def list_exporter_keychain_entries(
    cfg: Optional[dict] = None,
    *,
    service: Optional[str] = None,
    accounts: Optional[List[str]] = None,
) -> List[dict]:
    """List existing keychain entries that 1p-exporter may use."""
    if sys.platform != "darwin":
        raise RuntimeError("keychain entry listing is supported on macOS only")

    entries: List[dict] = []
    for svc, acct in _exporter_keychain_targets(
        cfg, service=service, accounts=accounts
    ):
        secret = _macos_find_password(svc, acct)
        if secret is None:
            continue
        entries.append(
            {
                "service": svc,
                "account": acct,
                "secret_length": len(secret),
            }
        )
    return entries


def tighten_keychain_entry_access(service: str, username: str) -> bool:
    """Re-save an item with tighter ACL (no default trusted app).

    Uses ``-T ""`` so the creating app is not implicitly trusted.
    """
    if sys.platform != "darwin":
        raise RuntimeError("keychain access tightening is supported on macOS only")

    secret = _macos_find_password(service, username)
    if secret is None:
        return False

    run_cmd(
        [
            "security",
            "add-generic-password",
            "-s",
            service,
            "-a",
            username,
            "-w",
            secret,
            "-U",
            "-T",
            "",
        ]
    )
    return True


def get_passphrase_from_keychain(
    service: str, username: str
) -> Optional[str]:
    """Attempt to get a password from macOS keychain (or platform keyring).

    On macOS the ``security`` CLI is used as a fallback which will prompt the
    user (Touch ID) if the item requires confirmation.
    """
    # try python-keyring first (if installed)
    try:
        import keyring  # pyright: ignore[reportMissingImports]

        val = keyring.get_password(service, username)
        if val:
            return val
    except Exception:
        pass

    if sys.platform != "darwin":
        raise RuntimeError(
            "keychain access supported only on macOS when keyring is not "
            "available"
        )

    _, out, _ = run_cmd(
        [
            "security",
            "find-generic-password",
            "-s",
            service,
            "-a",
            username,
            "-w",
        ]
    )
    return out.strip()


def store_passphrase_in_keychain(
    service: str, username: str, passphrase: str
) -> None:
    """Store a password in macOS keychain (or platform keyring)."""
    # prefer keyring if installed
    try:
        import keyring  # pyright: ignore[reportMissingImports]

        keyring.set_password(service, username, passphrase)
        return
    except Exception:
        pass

    if sys.platform != "darwin":
        raise RuntimeError(
            "keychain storage supported only on macOS when keyring is not "
            "available"
        )

    run_cmd(
        [
            "security",
            "add-generic-password",
            "-s",
            service,
            "-a",
            username,
            "-w",
            passphrase,
            "-U",
        ]
    )


def sync_keychain() -> bool:
    """Pull age credentials from 1Password and store them in macOS keychain.

    Reads the saved configuration to find the 1Password item, fetches the
    ``age_private_key`` and ``passphrase`` fields, and writes them to the
    keychain.  Returns True if at least one credential was synced.
    """
    from .config import load_config
    from .exporter import OpExporter

    cfg = load_config()
    age_cfg = cfg.get("age", {})
    item_ref = age_cfg.get("pass_item")
    if not item_ref:
        print(
            "error: age.pass_item is not set in config; "
            "run `1p-exporter init` first",
            file=sys.stderr,
        )
        return False

    kc_service = age_cfg.get("keychain_service", "1p-exporter")
    kc_username = age_cfg.get("keychain_username", "backup")
    pass_field = age_cfg.get("pass_field", "passphrase")

    exporter = OpExporter()
    synced = 0

    # private key
    print(
        f"fetching age_private_key from 1Password item '{item_ref}' …"
    )
    try:
        priv = exporter.get_item_field_value(item_ref, "age_private_key")
    except Exception as e:
        print(f"  ✗ failed: {e}", file=sys.stderr)
        priv = None
    if priv:
        try:
            store_passphrase_in_keychain(
                kc_service, "age_private_key", priv
            )
            print(
                f"  ✓ stored in keychain "
                f"(service={kc_service!r} account='age_private_key')"
            )
            synced += 1
        except Exception as e:
            print(f"  ✗ keychain write failed: {e}", file=sys.stderr)
    else:
        print("  ✗ no age_private_key found in 1Password item")

    # passphrase
    print(
        f"fetching {pass_field!r} from 1Password item '{item_ref}' …"
    )
    try:
        pp = exporter.get_item_field_value(item_ref, pass_field)
    except Exception as e:
        print(f"  ✗ failed: {e}", file=sys.stderr)
        pp = None
    if pp:
        try:
            store_passphrase_in_keychain(kc_service, kc_username, pp)
            print(
                f"  ✓ stored in keychain "
                f"(service={kc_service!r} account={kc_username!r})"
            )
            synced += 1
        except Exception as e:
            print(f"  ✗ keychain write failed: {e}", file=sys.stderr)
    else:
        print(f"  ✗ no {pass_field!r} found in 1Password item")

    if synced:
        print(f"synced {synced} credential(s) to keychain")
    else:
        print("no credentials synced", file=sys.stderr)
    return synced > 0
