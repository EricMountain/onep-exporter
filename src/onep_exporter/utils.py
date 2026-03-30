import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


import re


def _redact_sensitive(text: Optional[str]) -> Optional[str]:
    """Redact sensitive tokens and private-key material for safe display.

    - Truncates AGE secret tokens (keeps readable prefix + ellipsis)
    - Redacts AGE private key blocks (preserve header/footer)
    - Truncates long JSON `"value"` fields that likely contain secrets
    """
    if not text:
        return text

    redacted = text

    # redact AGE secret tokens (show short prefix + ellipsis)
    def _redact_token(m: re.Match) -> str:
        tok = m.group(0)
        return tok[:16] + "…"

    redacted = re.sub(
        r"AGE-SECRET-KEY-[A-Za-z0-9\-_=]+", _redact_token, redacted)

    # redact AGE private key blocks but keep headers
    redacted = re.sub(
        r"(-----BEGIN AGE [^-]+-----)(.*?)(-----END AGE [^-]+-----)",
        lambda m: m.group(1) + "\n<redacted private key>\n" + m.group(3),
        redacted,
        flags=re.S,
    )

    # redact long values in JSON-like payloads (e.g. value fields)
    def _redact_json_value(m: re.Match) -> str:
        prefix, val, suffix = m.group(1), m.group(2), m.group(3)
        # prefix already contains the opening quote for the value; avoid inserting extra quotes
        if len(val) > 16 or "AGE-SECRET-KEY" in val or "-----BEGIN AGE" in val:
            return f'{prefix}{val[:12]}…{suffix}'
        return m.group(0)

    redacted = re.sub(
        r'("value"\s*:\s*")([^"]*)("\s*[,}])', _redact_json_value, redacted)

    return redacted


class CommandError(RuntimeError):
    """CommandError holds structured data about a failed subprocess invocation and
    redacts sensitive bits when converted to string.

    Can be constructed either with a plain message or with keyword args `cmd`, `rc`, `stderr`.
    """

    def __init__(self, message: Optional[str] = None, *, cmd: Optional[list] = None, rc: Optional[int] = None, stderr: Optional[str] = None):
        if cmd is not None:
            self.cmd = cmd
            self.rc = rc
            self.stderr = stderr
            raw = f"Command {cmd!r} failed: {rc}: {stderr}"
            super().__init__(raw)
        else:
            self.cmd = None
            self.rc = None
            self.stderr = None
            super().__init__(message)

    def __str__(self) -> str:  # redacted representation for safe display
        return _redact_sensitive(super().__str__() or "")


def run_cmd(cmd: list[str], capture_output: bool = True, check: bool = True, input: Optional[bytes] = None) -> Tuple[int, str, str]:
    """Run subprocess command and return (rc, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=capture_output, input=input)
    rc = proc.returncode
    out = proc.stdout.decode("utf-8") if proc.stdout else ""
    err = proc.stderr.decode("utf-8") if proc.stderr else ""
    if check and rc != 0:
        raise CommandError(cmd=cmd, rc=rc, stderr=err)
    return rc, out, err


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj, *, indent: int = 2):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=False)


def ensure_tool(name: str) -> bool:
    return shutil.which(name) is not None


AGE_MIN_VERSION = (1, 1, 0)


def check_age_version() -> None:
    """Raise RuntimeError if age is missing or older than 1.1.0.

    age >= 1.1.0 is required for ``-i -`` (reading the identity from stdin),
    which lets us avoid ever writing the private key to disk.
    """
    if not ensure_tool("age"):
        raise RuntimeError("age not found; install it with: brew install age")
    try:
        _, out, _ = run_cmd(["age", "--version"], check=False)
    except Exception as e:
        raise RuntimeError(f"could not determine age version: {e}") from e
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", out)
    if not m:
        raise RuntimeError(f"could not parse age version from: {out!r}")
    found = tuple(int(x) for x in m.groups())
    if found < AGE_MIN_VERSION:
        req = ".".join(str(x) for x in AGE_MIN_VERSION)
        raise RuntimeError(
            f"age {'.'.join(str(x) for x in found)} is too old; "
            f">= {req} is required for '-i -' (stdin identity) support. "
            f"Upgrade with: brew upgrade age"
        )


def item_field_value(item: dict, field_name: str) -> Optional[str]:
    """Extract a field value from a 1Password item dict by label or name."""
    for f in (item.get("fields") or []):
        if f.get("label") == field_name or f.get("name") == field_name:
            val = f.get("value")
            if isinstance(val, str) and val:
                return val
    return None


def verify_manifest(manifest_path: str) -> bool:
    """Verify that all files listed in a manifest exist and match their checksums."""
    p = Path(manifest_path)
    if not p.exists():
        print(f"manifest not found: {manifest_path}")
        return False
    data = json.loads(p.read_text(encoding="utf-8"))
    base = p.parent
    ok = True
    for f in data.get("files", []):
        path = base / f["path"]
        if not path.exists():
            print(f"missing file: {path}")
            ok = False
            continue
        sha = sha256_file(path)
        if sha != f.get("sha256"):
            print(
                f"sha mismatch: {path} (expected {f.get('sha256')}, got {sha})")
            ok = False
    print("manifest verification:", "OK" if ok else "FAILED")
    return ok
