"""Core 1Password exporter: OpExporter class and run_backup orchestrator."""

import atexit
import getpass
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, UTC
from pathlib import Path
from typing import List, Optional, Union

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    MofNCompleteColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.table import Table

from .utils import run_cmd, write_json, sha256_file, ensure_tool, CommandError
from .templates import vault_to_md
from .encryption import (
    HashingWriter,
    resolve_age_config,
    sync_age_credentials_to_keychain,
)

# --- Re-exports for backward compatibility ---
# Several modules and tests import these symbols from exporter; keep them
# available here so existing ``from .exporter import X`` statements continue
# to work during the transition.
from .config import (  # noqa: F401
    load_config,
    save_config,
    _config_file_path,
    configure_interactive,
    init_setup,
)
from .encryption import (  # noqa: F401
    resolve_decrypt_credentials as _resolve_decrypt_credentials,
    generate_age_keypair_and_store as _generate_age_keypair_and_store,
    resolve_age_config as _resolve_age_config,
    sync_age_credentials_to_keychain as _sync_age_credentials_to_keychain,
)
from .keychain import (  # noqa: F401
    get_passphrase_from_keychain as _get_passphrase_from_keychain,
    store_passphrase_in_keychain as _store_passphrase_in_keychain,
    sync_keychain,
)
from .query import (  # noqa: F401
    query_list_titles,
    query_get_item,
    _iter_exported_items,
)
from .doctor import doctor  # noqa: F401
from .utils import (  # noqa: F401
    verify_manifest,
    item_field_value as _item_field_value,
)



class OpExporter:
    def __init__(self):
        if not ensure_tool("op"):
            raise RuntimeError(
                "`op` (1Password CLI) not found in PATH — please install and sign in first")

    def list_vaults(self) -> List[dict]:
        _, out, _ = run_cmd(["op", "vault", "list", "--format=json"])
        return json.loads(out)

    def list_items(self, vault_id: str) -> List[dict]:
        _, out, _ = run_cmd(
            ["op", "item", "list", "--vault", vault_id, "--format=json"])
        return json.loads(out)

    def get_item(self, item_id: str) -> dict:
        _, out, _ = run_cmd(["op", "item", "get", item_id, "--format=json"])
        return json.loads(out)

    def download_document(self, doc_id: str, dest: Path) -> None:
        # Try `op document get <id> --output <file>` (works for document/file objects)
        try:
            run_cmd(["op", "document", "get", doc_id, "--output", str(dest)])
        except CommandError as e:
            raise RuntimeError(f"failed to download document {doc_id}: {e}")

    def download_document_bytes(self, doc_id: str) -> bytes:
        """Download a document and return its raw bytes.

        This is used when we're encrypting and do not want to write the
        attachment to disk.  We run `op document get <id>` without the
        --output flag and capture stdout.
        """
        try:
            rc, out, err = run_cmd(["op", "document", "get", doc_id], capture_output=True)
        except CommandError as e:
            raise RuntimeError(f"failed to download document {doc_id}: {e}")
        return out.encode("utf-8") if isinstance(out, str) else out

    def get_item_field_value(self, item_ref: str, field_name: Optional[str] = None) -> Optional[str]:
        """Return a field value from a 1Password item JSON.

        *item_ref* may be an item id or title (passed to ``op item get``).
        When *field_name* is supplied we look **only** for a field whose
        `name` or `label` exactly matches that value; if no such field exists the
        result is ``None``.  This preserves the caller's explicit intent and
        avoids ambiguous heuristics.

        When *field_name* is ``None`` we fall back to a simple heuristic that
        returns the first field whose type is ``password`` or whose name/label
        contains the substring ``pass``.  This allows callers to omit a field
        name while still finding either a "password" or "passphrase" entry.
        """
        item = self.get_item(item_ref)
        fields = item.get("fields") or []
        # explicit lookup; if a name is given we only look for that field
        if field_name:
            for f in fields:
                if (f.get("name") == field_name) or (f.get("label") == field_name):
                    val = f.get("value")
                    if isinstance(val, str):
                        return val
            # explicit name supplied but not found -> return None
            return None

        # no explicit field name supplied; use heuristic fallback
        for f in fields:
            # treat any field whose type is `password` or whose name/label
            # contains the substring "pass" as a candidate.  this catches both
            # "password" and "passphrase" (and other reasonable variants).
            if f.get("type") == "password" or "pass" in (f.get("name") or "").lower() or "pass" in (f.get("label") or "").lower():
                val = f.get("value")
                if isinstance(val, str):
                    return val

        # no match
        return None

    def find_item_by_title(self, title: str, vault: Optional[str] = None) -> Optional[dict]:
        """Return the item JSON for a given title if it exists (optionally restricted to a vault).

        Uses `op item get <title>` (which resolves by title or id). If the returned item is in a
        different vault than requested, treat as not found.
        """
        try:
            _, out, _ = run_cmd(["op", "item", "get", title, "--format=json"])
            item = json.loads(out)
            if vault:
                v = item.get("vault") or {}
                if vault != v.get("id") and vault != v.get("name"):
                    return None
            return item
        except CommandError:
            return None

    def store_passphrase_in_1password(self, title: str, field_name: str, passphrase: str, vault: Optional[str] = None) -> dict:
        """Create a Secure Note item in 1Password **only if it does not already exist**.

        The secret is stored as a CONCEALED custom field so it stays hidden in the
        1Password UI.  The JSON template is piped via stdin (``-`` positional arg)
        because ``op item create`` interprets bare positional args as assignment
        statements, not JSON.

        Returns the existing item JSON if present, or the created item JSON.

        See https://developer.1password.com/docs/cli/item-create/#with-an-item-json-template
        """
        existing = self.find_item_by_title(title, vault=vault)
        if existing:
            # do not overwrite existing item
            return existing

        # Build a JSON template.
        # • We omit "category" from the JSON and pass it via --category flag
        #   instead, because `op` expects an enum identifier (e.g. SECURE_NOTE)
        #   in JSON but the display name ("Secure Note") via the flag.
        # • category "Secure Note" — avoids built-in required fields that other
        #   categories (e.g. Password) enforce, which causes "cannot add a field
        #   with no value" errors.
        # • field type CONCEALED — keeps the value hidden in 1Password.
        payload = {
            "title": title,
            "fields": [
                {
                    "id": field_name,
                    "label": field_name,
                    "type": "CONCEALED",
                    "value": passphrase,
                }
            ],
        }

        cmd = ["op", "item", "create", "--category", "Secure Note",
               "--format", "json"]
        if vault:
            cmd.extend(["--vault", vault])
        # `-` tells op to read the item template from stdin
        cmd.append("-")

        _, out, _ = run_cmd(cmd, input=json.dumps(payload).encode())
        return json.loads(out)

    def ensure_secrets_item(self, title: str, vault: Optional[str] = None) -> dict:
        """Ensure a Secure Note item exists in 1Password for storing backup secrets.

        Creates an empty Secure Note if one with the given title doesn't exist.
        Returns the item JSON (existing or newly created).
        """
        existing = self.find_item_by_title(title, vault=vault)
        if existing:
            return existing
        payload = {"title": title, "fields": []}
        cmd = ["op", "item", "create", "--category", "Secure Note",
               "--format", "json"]
        if vault:
            cmd.extend(["--vault", vault])
        cmd.append("-")
        _, out, _ = run_cmd(cmd, input=json.dumps(payload).encode())
        return json.loads(out)

    def upsert_item_field(self, item_id: str, field_label: str, value: str,
                          field_type: str = "CONCEALED") -> dict:
        """Add or update a field on an existing 1Password item.

        The previous implementation used the ``<label>[type=...]=<value>``
        assignment syntax, which could confuse the CLI and result in a field
        whose name included ``[type``.  Instead we now retrieve the current
        item JSON, mutate the fields list, and resubmit the full object via
        ``op item edit --format json -``.  This mirrors the behaviour of
        :meth:`store_passphrase_in_1password` and avoids any parsing edge cases.

        ``field_type`` should be either ``CONCEALED`` or ``TEXT``.  Returns
        the updated item JSON as parsed from the CLI output.
        """
        # fetch existing item so we can modify its fields list
        item = self.get_item(item_id)
        fields = item.get("fields") or []

        # look for an existing field with matching name/label
        updated = False
        for f in fields:
            if (f.get("name") == field_label) or (f.get("label") == field_label):
                f["value"] = value
                f["type"] = field_type
                updated = True
                break
        if not updated:
            # add new field; use field_label for both id and label so the
            # field can be re-identified later
            fields.append({
                "id": field_label,
                "label": field_label,
                "type": field_type,
                "value": value,
            })
        item["fields"] = fields

        # send modified item JSON back to op via stdin
        cmd = ["op", "item", "edit", "--format", "json", item_id, "-"]
        _, out, _ = run_cmd(cmd, input=json.dumps(item).encode())
        return json.loads(out)

    def signin_interactive(self, account: Optional[str] = None) -> str:
        """Run `op signin --raw` to obtain a session token (user will be prompted; Touch ID may be used by the 1Password app).

        Returns the token string printed by `op`.
        """
        cmd = ["op", "signin", "--raw"]
        if account:
            cmd.insert(2, account)
        _, out, _ = run_cmd(cmd)
        token = out.strip()
        print("op session token obtained. Set OP_SESSION_<account> in your shell to use it for automation.")
        print("(example) export OP_SESSION_your-account=", token)
        return token


def _make_progress(quiet: bool) -> Progress:
    """Build a rich Progress bar (or a no-op equivalent when quiet)."""
    if quiet:
        # Return a Progress that renders nothing
        return Progress(
            TextColumn(""),
            transient=True,
            disable=True,
        )
    return Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TextColumn("·"),
        TimeElapsedColumn(),
        transient=False,
    )


def run_backup(*, output_base: Union[str, Path] = "backups", formats=("json", "md"), encrypt: str = "none", download_attachments: bool = True, quiet: bool = False, age_pass_source: str = "prompt", age_pass_item: Optional[str] = None, age_pass_field: str = "passphrase", age_recipients: str = "", age_use_yubikey: bool = False, sync_passphrase_from_1password: bool = False, age_keychain_service: str = "1p-exporter", age_keychain_username: str = "backup") -> Path:
    output_base = Path(output_base)
    # create output directory right away; the encrypted archive is written to
    # this location even when we stream through age/gpg, so the parent must
    # exist or the subprocess will fail with "no such file or directory".
    output_base.mkdir(parents=True, exist_ok=True)

    console = Console(quiet=quiet)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    # when encrypting we don't want persistent plaintext files left behind,
    # so create a temporary work directory that will be removed after the
    # archive is built.  If no encryption is requested we keep the timestamped
    # directory under output_base so users can examine files.
    if encrypt != "none":
        work_dir = Path(tempfile.mkdtemp())
        atexit.register(lambda p=work_dir: shutil.rmtree(p, ignore_errors=True))
    else:
        work_dir = output_base / ts
        work_dir.mkdir(parents=True, exist_ok=True)
    outdir = work_dir

    exporter = OpExporter()

    # if we're going to use age encryption we want to resolve the passphrase
    # / recipient configuration immediately, before we start fetching anything
    # from 1Password.  this allows us to fail fast for common mis‑configurations
    # (e.g. specifying both a passphrase source and explicit recipients) and
    # avoids downloading vaults/attachments only to error out later.
    passphrase = None
    recipients: list[str] = []
    if encrypt == "age":
        passphrase, recipients = resolve_age_config(
            exporter,
            age_pass_source=age_pass_source,
            age_pass_item=age_pass_item,
            age_pass_field=age_pass_field,
            age_recipients=age_recipients,
            age_use_yubikey=age_use_yubikey,
            sync_passphrase_from_1password=sync_passphrase_from_1password,
            age_keychain_service=age_keychain_service,
            age_keychain_username=age_keychain_username,
        )

        # sync decryption credentials to local keychain so that query-time
        # operations work without 1Password being available.
        sync_age_credentials_to_keychain(
            exporter,
            age_pass_item=age_pass_item,
            age_pass_field=age_pass_field,
            age_keychain_service=age_keychain_service,
            age_keychain_username=age_keychain_username,
            passphrase=passphrase,
        )

    vaults = exporter.list_vaults()
    manifest = {
        "timestamp": ts,
        "vaults": [],
        "files": [],
    }

    # list of (relative_name, bytes) for files we generate in memory
    # and later inject into the tar instead of writing to disk
    memory_files: list[tuple[str, bytes]] = []

    attachments_dir = outdir / "attachments"
    if download_attachments:
        attachments_dir.mkdir(parents=True, exist_ok=True)

    # --- progress-tracked vault/item export ---
    total_items = 0
    total_attachments = 0
    warnings: list[str] = []

    progress = _make_progress(quiet)
    with progress:
        vault_task = progress.add_task("Vaults", total=len(vaults))

        for v in vaults:
            vault_id = v.get("id")
            if not vault_id:
                warnings.append(f"skipping vault with missing id: {v}")
                progress.advance(vault_task)
                continue
            vault_name = v.get("name") or vault_id
            progress.update(vault_task, description=f"Vault: [cyan]{vault_name}[/cyan]")

            items_summary = exporter.list_items(vault_id)
            item_task = progress.add_task(
                f"  {vault_name}", total=len(items_summary),
            )
            items_full = []
            for s in items_summary:
                item_id = s.get("id")
                if not item_id:
                    warnings.append(f"skipping item with missing id in {vault_name}: {s}")
                    progress.advance(item_task)
                    continue
                try:
                    item = exporter.get_item(item_id)
                except Exception as e:
                    warnings.append(f"failed to fetch item {item_id}: {e}")
                    progress.advance(item_task)
                    continue
                # download attachments if present
                files_meta = item.get("files") or item.get("documents") or []
                for fmeta in files_meta:
                    fid = fmeta.get("id") or fmeta.get("file_id")
                    name = fmeta.get("name") or fmeta.get("filename")
                    if fid and name and download_attachments:
                        if encrypt == "none":
                            dest = attachments_dir / f"{fid}-{name}"
                            try:
                                exporter.download_document(fid, dest)
                            except Exception as e:
                                warnings.append(f"could not download attachment {name}: {e}")
                            else:
                                manifest["files"].append(
                                    {"path": str(dest.relative_to(outdir)), "sha256": sha256_file(dest)})
                                total_attachments += 1
                        else:
                            # fetch bytes directly and keep in memory
                            try:
                                data = exporter.download_document_bytes(fid)
                            except Exception as e:
                                warnings.append(f"could not download attachment {name}: {e}")
                                continue
                            sha = hashlib.sha256(data).hexdigest()
                            relpath = f"attachments/{fid}-{name}"
                            manifest["files"].append({"path": relpath, "sha256": sha})
                            memory_files.append((relpath, data))
                            total_attachments += 1
                items_full.append(item)
                total_items += 1
                progress.advance(item_task)

            # always serialise vault JSON into memory; never write it to disk
            vault_data = json.dumps(items_full, indent=2, ensure_ascii=False).encode("utf-8")
            vault_sha = hashlib.sha256(vault_data).hexdigest()
            memory_files.append((f"vault-{vault_id}.json", vault_data))
            manifest["vaults"].append({
                "id": vault_id,
                "name": vault_name,
                "items": len(items_full),
                "file": f"vault-{vault_id}.json",
                "sha256": vault_sha,
            })

            if "md" in formats:
                md_name = f"vault-{vault_id}.md"
                md_text = vault_to_md(vault_name, items_full)
                md_bytes = md_text.encode("utf-8")
                sha = hashlib.sha256(md_bytes).hexdigest()
                manifest["files"].append({"path": md_name, "sha256": sha})
                memory_files.append((md_name, md_bytes))

            progress.advance(vault_task)

    # print any warnings that were collected during export
    for w in warnings:
        console.print(f"  [yellow]warning:[/yellow] {w}")

    # write manifest
    manifest_path = outdir / "manifest.json"
    write_json(manifest_path, manifest)
    manifest_hash = sha256_file(manifest_path)
    manifest["manifest_sha256"] = manifest_hash
    write_json(manifest_path, manifest)  # update with hash

    # create archive path (used for naming even if we stream)
    archive_path = output_base / f"1p-backup-{ts}.tar.gz"

    # write either to disk or stream directly into encryption tool
    if encrypt == "none":
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(outdir, arcname=ts)
            # also add any in-memory files (markdown/vault JSON)
            for name, data in memory_files:
                ti = tarfile.TarInfo(name=f"{ts}/{name}")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
        archive_sha = sha256_file(archive_path)
        _print_summary(console, archive_path, archive_sha, encrypt, len(vaults), total_items, total_attachments)
        return archive_path

    # At this point we know encryption is requested.
    if encrypt == "gpg":
        if not ensure_tool("gpg"):
            raise RuntimeError("gpg not found for encryption")

        passphrase = os.environ.get("BACKUP_PASSPHRASE")
        if not passphrase:
            passphrase = getpass.getpass(
                "GPG passphrase for symmetric encryption: ")
        out_enc = str(archive_path) + ".gpg"
        cmd = ["gpg", "--symmetric", "--cipher-algo", "AES256", "--batch",
               "--pinentry-mode", "loopback", "--passphrase", passphrase,
               "--output", out_enc]
    elif encrypt == "age":
        if not ensure_tool("age"):
            raise RuntimeError("age not found for encryption")
        out_enc = str(archive_path) + ".age"
        cmd = ["age", "-o", out_enc]
        for r in recipients:
            cmd.extend(["-r", r])
        if passphrase:
            cmd.append("--passphrase")
    else:
        raise RuntimeError(f"unsupported encrypt mode: {encrypt}")

    # now stream the tarball through the encryptor subprocess
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    writer = HashingWriter(proc.stdin)
    with tarfile.open(fileobj=writer, mode="w|gz") as tar:
        tar.add(outdir, arcname=ts)
        for name, data in memory_files:
            ti = tarfile.TarInfo(name=f"{ts}/{name}")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    writer.flush()
    proc.stdin.close()
    rc = proc.wait()
    if rc != 0:
        raise CommandError(cmd=cmd, rc=rc, stderr="encryption failed")
    archive_sha = writer.hasher.hexdigest()
    # clean up temporary directory when encryption was used
    if encrypt != "none":
        try:
            shutil.rmtree(outdir)
        except Exception:
            pass
    _print_summary(console, Path(out_enc), archive_sha, encrypt, len(vaults), total_items, total_attachments)
    return Path(out_enc)


def _print_summary(
    console: Console,
    path: Path,
    sha256: str,
    encrypt: str,
    vault_count: int,
    item_count: int,
    attachment_count: int,
) -> None:
    """Print a rich summary panel after backup completes."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Archive", str(path))
    table.add_row("SHA-256", sha256)
    if encrypt != "none":
        table.add_row("Encryption", encrypt)
    table.add_row("Vaults", str(vault_count))
    table.add_row("Items", str(item_count))
    if attachment_count:
        table.add_row("Attachments", str(attachment_count))
    console.print()
    console.print(Panel(table, title="[bold green]Backup complete[/bold green]", border_style="green"))

