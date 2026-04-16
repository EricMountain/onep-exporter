"""Environment and configuration diagnostics for onep-exporter."""

import os
import sys
from typing import Optional

from .config import load_config, _config_file_path
from .utils import ensure_tool


def doctor() -> bool:
    """Perform sanity checks on environment and configuration.

    Prints a grouped, colorized summary of checks and returns True when all
    critical checks pass.  Colors are emitted only when stdout is a TTY.
    """
    OK_ICON = "✅"
    FAIL_ICON = "❌"
    WARN_ICON = "⚠️"
    INFO_ICON = "ℹ️"
    HEADER_ICON = "🔎"

    use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    def _color(text: str, code: str) -> str:
        if not use_color:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    def _ok(msg: str):
        icon = _color(OK_ICON, "32")
        print(f" {icon}  {_color(msg, '0')}")

    def _err(msg: str):
        icon = _color(FAIL_ICON, "31")
        print(f" {icon}  {_color(msg, '0')}")

    def _warn(msg: str):
        icon = _color(WARN_ICON, "33")
        print(f" {icon}  {_color(msg, '0')}")

    ok = True

    # header
    print()
    title = f"{HEADER_ICON}  onep-exporter doctor — environment & configuration checks"
    print(_color(title, "1;36"))
    print(_color("─" * 52, "36"))

    # Environment checks
    print(_color("\nEnvironment:", "1;34"))
    if not ensure_tool("op"):
        _err("`op` (1Password CLI) not found in PATH")
        ok = False
    else:
        _ok("`op` available")

    # Tools availability (informational)
    print(_color("\nTools:", "1;34"))

    def _suggest_install_cmd(tool: str) -> Optional[str]:
        pkg_map = {
            "age": "age",
            "age-keygen": "age",
            "security": None,
        }
        pkg = pkg_map.get(tool, tool)

        if sys.platform == "darwin":
            if ensure_tool("brew") and pkg:
                return f"brew install {pkg}"
            if tool == "security":
                return (
                    "macOS: install Xcode Command Line Tools: "
                    "`xcode-select --install`"
                )
            return (
                f"install {pkg} via Homebrew (https://brew.sh/)"
                if pkg
                else None
            )

        if ensure_tool("apt") and pkg:
            return f"sudo apt install -y {pkg}"
        if ensure_tool("dnf") and pkg:
            return f"sudo dnf install -y {pkg}"
        if ensure_tool("pacman") and pkg:
            return f"sudo pacman -S --noconfirm {pkg}"

        return f"install package: {pkg}" if pkg else None

    tools_to_check = ["age", "age-keygen"]
    if sys.platform == "darwin":
        tools_to_check.append("security")

    for _tool in tools_to_check:
        try:
            present = ensure_tool(_tool)
        except Exception:
            present = False
        if present:
            _ok(f"`{_tool}` available")
        else:
            suggestion = _suggest_install_cmd(_tool)
            if suggestion:
                _warn(
                    f"`{_tool}` not found in PATH — suggestion: {suggestion}"
                )
            else:
                _warn(f"`{_tool}` not found in PATH")

    # Configuration checks
    print(_color("\nConfiguration:", "1;34"))
    cfg = load_config()
    if not cfg:
        _warn("config: not found (using defaults)")
    else:
        _ok(f"loaded from {_config_file_path()}")

        encrypt = cfg.get("encrypt", "none")
        if encrypt not in ("none", "age"):
            _err(f"invalid encrypt in config: {encrypt}")
            ok = False
        else:
            _ok(f"encrypt={encrypt}")
        # tool checks required by config
        if encrypt == "age":
            if not ensure_tool("age"):
                _err("config requests age encryption but `age` not found")
                ok = False
            else:
                _ok("`age` available")

        # formats
        fmts = cfg.get("formats", ["json", "md"]) or []
        invalid = [f for f in fmts if f not in ("json", "md")]
        if invalid:
            _err(f"invalid formats in config: {', '.join(invalid)}")
            ok = False
        else:
            _ok(f"formats={','.join(fmts)}")

    # Age-specific checks
    age_cfg = (cfg.get("age", {}) if cfg else {}) or {}
    if age_cfg:
        print(_color("\nAge checks:", "1;34"))

        recipients = (age_cfg.get("recipients") or "").strip()
        if recipients:
            _ok("age.recipients configured")

    # final summary
    print(_color("\n" + "─" * 52, "36"))
    summary_icon = OK_ICON if ok else FAIL_ICON
    summary_color = "32" if ok else "31"
    print(
        f"doctor result: "
        f"{_color(summary_icon + ' ' + ('OK' if ok else 'FAILED'), summary_color)}"
    )
    print()
    return ok
