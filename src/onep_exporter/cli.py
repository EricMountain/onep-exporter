import argparse
import sys
import os

from .config import load_config, configure_interactive
from .doctor import doctor
from .exporter import run_backup, OpExporter
from .keychain import (
    sync_keychain,
    list_exporter_keychain_entries,
)
from .query import query_list_titles, query_get_item
from .tui import run_tui, _find_latest_archive
from .utils import verify_manifest, item_field_value
from .templates import item_to_md


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="onep-exporter", description="Export 1Password vaults and create backups")
    p.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="enable verbose output (overrides config)",
    )
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser(
        "backup", help="Create a backup archive from 1Password using `op` CLI")
    b.add_argument("--output", "-o", default=argparse.SUPPRESS,
                   help="output base directory (overrides saved config)")
    b.add_argument("--formats", "-f", default=argparse.SUPPRESS,
                   help="comma-separated formats to write (json,md). Overrides saved config")
    b.add_argument("--encrypt", choices=["age", "none"],
                   default=argparse.SUPPRESS, help="encrypt archive (age/none) — overrides saved config")
    # keychain-related flags are macOS-specific — hide them from help on other platforms
    is_macos = sys.platform == "darwin"
    keychain_help = "macOS keychain service name" if is_macos else argparse.SUPPRESS
    b.add_argument("--age-keychain-service", default=argparse.SUPPRESS,
                   help=keychain_help)
    keychain_user_help = "macOS keychain account/username" if is_macos else argparse.SUPPRESS
    b.add_argument("--age-keychain-username", default=argparse.SUPPRESS,
                   help=keychain_user_help)
    b.add_argument("--age-pass-item", default=argparse.SUPPRESS,
                   help="1Password item title or id that contains age secrets (private key and recipients)")
    b.add_argument("--age-recipients", default=argparse.SUPPRESS,
                   help="comma-separated age public recipients (optional)")
    b.add_argument("--age-use-yubikey", action="store_true", default=argparse.SUPPRESS,
                   help="(optional) include a YubiKey-backed recipient (requires user to have configured a yubikey age identity)")
    b.add_argument("--no-attachments", action="store_true", default=argparse.SUPPRESS,
                   help="do not attempt to download attachments (overrides saved config)")
    b.add_argument("--vault", action="append", dest="vaults",
                   help="vault id or name to include in the backup (repeatable). By default all vaults are backed up.")
    b.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                   help="minimal output (overrides saved config)")

    # init: generate a configuration
    i = sub.add_parser(
        "init", help="Run interactive configuration and optionally sign in to 1Password")
    i.add_argument("--signin", action="store_true",
                   help="invoke `op signin` to allow interactive unlock (Touch ID) and print session token")

    v = sub.add_parser("verify", help="Verify a produced manifest and files")
    v.add_argument("manifest", help="path to manifest.json")

    d = sub.add_parser(
        "doctor", help="Sanity-check environment and configuration")

    sk = sub.add_parser(
        "sync-keychain",
        help="Pull age credentials from 1Password into macOS keychain for offline decryption")

    kc = sub.add_parser(
        "keychain",
        help="List macOS keychain entries used by onep-exporter",
    )
    kcsub = kc.add_subparsers(dest="keychain_cmd")

    kcl = kcsub.add_parser("list", help="List existing exporter keychain entries")
    kcl.add_argument(
        "--service",
        default=None,
        help="keychain service name (default: configured service and onep-exporter)",
    )
    kcl.add_argument(
        "--account",
        action="append",
        dest="accounts",
        default=None,
        help="account to include (can be repeated; default: exporter-related accounts)",
    )
    

    # 'query' command for post-processing exported data
    q = sub.add_parser("query", help="Query exported backup data")
    qsub = q.add_subparsers(dest="query_cmd")

    ql = qsub.add_parser("list", help="List item titles matching a regexp")
    ql.add_argument("pattern", help="regular expression to match item titles")
    ql.add_argument("--dir", "-d", default=None,
                    help="path to directory containing exported JSON (default: most recent backup archive)")
    ql.add_argument("--age-identity", action="append", dest="age_identities",
                    help="path to an age identity file to use for decrypting archives; can be repeated."
                    )

    qg = qsub.add_parser("get", help="Retrieve the full contents of a single item")
    qg.add_argument("item", help="item title (exact, case-sensitive) or item id to retrieve")
    qg.add_argument("--dir", "-d", default=None,
                    help="path to directory containing exported JSON (default: most recent backup archive)")
    qg.add_argument("--format", choices=["json", "md"], default="md",
                    dest="output_format",
                    help="output format: md/markdown (default) or json")
    qg.add_argument("--field", metavar="FIELD",
                    help="print only the value of the named field instead of the full item")
    qg.add_argument("--age-identity", action="append", dest="age_identities",
                    help="path to an age identity file to use for decrypting archives; can be repeated.")

    # 'browse' command — interactive TUI
    br = sub.add_parser("browse", help="Interactive TUI to search and view exported items")
    br.add_argument("--dir", "-d", default=None,
                    help="path to backup directory or archive (default: latest under backups/)")
    br.add_argument("--backup-base", default="backups",
                    help="base directory containing backup archives (default: backups/)")

    return p


def _setup_query_env(args) -> None:
    """Set environment variables for age decryption based on CLI flags."""
    identities = getattr(args, "age_identities", None)
    if identities:
        os.environ["AGE_IDENTITIES"] = os.pathsep.join(identities)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # enable verbose logging when requested on the CLI
    if getattr(args, "verbose", False):
        os.environ["ONEP_EXPORTER_VERBOSE"] = "1"

    if args.cmd == "backup":
        # merge saved config with CLI args (CLI overrides saved config)
        cfg = load_config()
        age_cfg = cfg.get("age", {})

        # Table-driven merge: (cli_attr, config_key, default, transform)
        # When the CLI flag uses argparse.SUPPRESS, hasattr() is False if
        # the user did not supply it — fall back to config then default.
        def _opt(attr, cfg_val, default=None, transform=None):
            if hasattr(args, attr):
                v = getattr(args, attr)
            else:
                v = cfg_val if cfg_val is not None else default
            return transform(v) if transform else v

        output_base = _opt("output", cfg.get("backup_directory") or cfg.get("output_base"), "backups")
        formats = _opt("formats", cfg.get("formats"), ["json", "md"],
                        lambda v: v.split(",") if isinstance(v, str) else v)
        encrypt = _opt("encrypt", cfg.get("encrypt"), "none")
        download_attachments = (
            not args.no_attachments if hasattr(args, "no_attachments")
            else cfg.get("download_attachments", True)
        )
        quiet = _opt("quiet", cfg.get("quiet"), False)

        age_pass_item = _opt("age_pass_item", age_cfg.get("pass_item"))
        age_recipients = _opt("age_recipients", age_cfg.get("recipients"), "")
        age_use_yubikey = _opt("age_use_yubikey", age_cfg.get("use_yubikey"), False)
        age_keychain_service = _opt("age_keychain_service", age_cfg.get("keychain_service"), "onep-exporter")
        age_keychain_username = _opt("age_keychain_username", age_cfg.get("keychain_username"), "backup")
        selected_vaults = _opt("vaults", None, None)

        try:
            run_backup(
                output_base=output_base,
                formats=formats,
                encrypt=encrypt,
                download_attachments=download_attachments,
                quiet=quiet,
                selected_vaults=selected_vaults,
                age_pass_item=age_pass_item,
                age_recipients=age_recipients,
                age_use_yubikey=age_use_yubikey,
                age_keychain_service=age_keychain_service,
                age_keychain_username=age_keychain_username,
                fail_on_error=True,
            )
        except Exception as e:
            print(f"error: {e}")
            sys.exit(1)
    elif args.cmd == "init":
        # Interactive flow — allow signin then run interactive configuration
        if args.signin:
            OpExporter().signin_interactive()
        configure_interactive()
        # After configuration, run a `doctor` check on the generated configuration
        ok = doctor()
        sys.exit(0 if ok else 2)
    elif args.cmd == "verify":
        ok = verify_manifest(args.manifest)
        sys.exit(0 if ok else 2)
    elif args.cmd == "doctor":
        ok = doctor()
        sys.exit(0 if ok else 2)
    elif args.cmd == "sync-keychain":
        ok = sync_keychain()
        sys.exit(0 if ok else 1)
    elif args.cmd == "keychain":
        if sys.platform != "darwin":
            print("error: keychain helpers are only supported on macOS")
            sys.exit(2)

        cfg = load_config()

        if args.keychain_cmd == "list":
            entries = list_exporter_keychain_entries(
                cfg,
                service=args.service,
                accounts=args.accounts,
            )
            if not entries:
                print("No exporter keychain entries found.")
                sys.exit(1)
            for ent in entries:
                print(
                    f"service={ent['service']} account={ent['account']} "
                    f"secret_length={ent['secret_length']}"
                )
            sys.exit(0)
        
        else:
            parser.print_help()
            sys.exit(2)
    elif args.cmd == "query":
        # Resolve directory: if not provided, default to most recent backup
        cfg = load_config()

        def _resolved_dir(arg_dir):
            if arg_dir is not None:
                return arg_dir
            backup_base = cfg.get("backup_directory") or cfg.get("output_base") or "backups"
            try:
                return _find_latest_archive(backup_base)
            except FileNotFoundError as e:
                print(f"error: {e}")
                sys.exit(1)

        if args.query_cmd == "list":
            _setup_query_env(args)
            try:
                resolved = _resolved_dir(getattr(args, "dir", None))
                matches = query_list_titles(resolved, args.pattern)
            except Exception as e:
                print(f"error: {e}")
                sys.exit(1)
            for t in matches:
                print(t)
            sys.exit(0)
        elif args.query_cmd == "get":
            _setup_query_env(args)
            try:
                resolved = _resolved_dir(getattr(args, "dir", None))
                item = query_get_item(resolved, args.item)
            except (KeyError, ValueError) as e:
                print(f"error: {e}")
                sys.exit(1)
            except Exception as e:
                print(f"error: {e}")
                sys.exit(1)

            if args.field:
                value = item_field_value(item, args.field)
                if value is None:
                    print(f"error: field {args.field!r} not found in item")
                    sys.exit(1)
                print(value)
            elif args.output_format == "json":
                import json
                print(json.dumps(item, indent=2))
            else:
                print(item_to_md(item))
            sys.exit(0)
        else:
            parser.print_help()
            sys.exit(2)
    elif args.cmd == "browse":
        cfg = load_config()
        backup_base = args.backup_base if args.backup_base != "backups" else (
            cfg.get("backup_directory") or cfg.get("output_base") or "backups"
        )
        try:
            run_tui(path=args.dir, backup_base=backup_base)
        except FileNotFoundError as e:
            print(f"error: {e}")
            sys.exit(1)
    else:
        parser.print_help()
