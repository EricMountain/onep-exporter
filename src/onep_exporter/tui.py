"""Interactive text UI for browsing exported 1Password backup data."""

import re
import sys
import time as _time
from pathlib import Path
from typing import List, Optional, Union
from urllib.parse import parse_qs, urlparse

from textual import on
from textual.app import App, ComposeResult
from textual.worker import Worker, WorkerState
from textual.binding import Binding
from textual.containers import Horizontal, Vertical

from textual.widgets import Footer, Header, Input, OptionList, Static
from textual.strip import Strip
from textual.timer import Timer
from rich.text import Text
from .config import load_config, save_config
from .query import _iter_exported_items
from .templates import _totp_now

_CATEGORY_ICONS: dict[str, str] = {
    "LOGIN": "\U0001f511",           # 🔑
    "SECURE_NOTE": "\U0001f4dd",     # 📝
    "PASSWORD": "\U0001f510",        # 🔐
    "CREDIT_CARD": "\U0001f4b3",     # 💳
    "IDENTITY": "\U0001f464",        # 👤
    "BANK_ACCOUNT": "\U0001f3e6",    # 🏦
    "SOFTWARE_LICENSE": "\U0001f4bf", # 💿
    "SERVER": "\U0001f5a5",          # 🖥
    "EMAIL_ACCOUNT": "\u2709",       # ✉
    "DOCUMENT": "\U0001f4c4",        # 📄
    "DATABASE": "\U0001f5c4",        # 🗄
    "MEDICAL_RECORD": "\U0001f3e5",  # 🏥
    "PASSPORT": "\U0001f6c2",        # 🛂
    "SSH_KEY": "\U0001f5dd",         # 🗝
    "WIRELESS_ROUTER": "\U0001f4f6", # 📶
    "API_CREDENTIAL": "\U0001f517",  # 🔗
    "MEMBERSHIP": "\U0001f3ab",      # 🎫
    "REWARD_PROGRAM": "\U0001f3c6",  # 🏆
    "SOCIAL_SECURITY_NUMBER": "\U0001f4cb", # 📋
    "DRIVER_LICENSE": "\U0001f697",  # 🚗
    "OUTDOOR_LICENSE": "\U0001f3d5", # 🏕
    "CRYPTO_WALLET": "\U0001fa99",   # 🪙
}

_SENSITIVE_TYPES = frozenset({"CONCEALED", "PASSWORD", "OTP", "TOTP"})
_SENSITIVE_LABELS = frozenset({
    "password", "passphrase", "secret", "token", "api key", "private key",
    "access token", "secret key", "pin", "credential",
})


def _field_is_sensitive(field: dict) -> bool:
    """Return True if *field* should be treated as a sensitive/secret value."""
    ftype = (field.get("type") or "").upper()
    if ftype in _SENSITIVE_TYPES:
        return True
    label = (field.get("name") or field.get("label") or "").lower()
    return any(s in label for s in _SENSITIVE_LABELS)


def _find_latest_archive(base: Union[str, Path]) -> Path:
    """Find the most recent backup under *base* (directory or archive).

    Looks for timestamped sub-directories (``YYYYMMDDTHHMMSSZ``) first,
    then falls back to archive files sorted by name.
    """
    base = Path(base)
    if not base.is_dir():
        raise FileNotFoundError(f"backup base directory not found: {base}")

    ts_re = re.compile(r"^\d{8}T\d{6}Z$")
    dirs = sorted(
        [d for d in base.iterdir() if d.is_dir() and ts_re.match(d.name)],
        key=lambda d: d.name,
        reverse=True,
    )
    for d in dirs:
        # skip directories that contain no vault data (e.g. only manifest.json)
        has_data = any(
            f.name != "manifest.json"
            for f in d.rglob("*.json")
        )
        if has_data:
            return d

    archive_re = re.compile(r"\d{8}T\d{6}Z")
    archives = sorted(
        [f for f in base.iterdir() if f.is_file() and archive_re.search(f.name)],
        key=lambda f: f.name,
        reverse=True,
    )
    if archives:
        return archives[0]

    raise FileNotFoundError(f"no backup archives found under {base}")


def _load_items(path: Path) -> List[dict]:
    """Load all items from the archive at *path* into memory."""
    return list(_iter_exported_items(path))


class Spinner(Static):
    """Simple bouncing-dot spinner using set_interval."""

    _DOTS = 5
    _LIT = "\u25cf"
    _DIM = "\u25cb"

    def __init__(self, **kwargs) -> None:
        super().__init__(self._render_frame(0), **kwargs)
        self._pos = 0
        self._direction = 1
        self._timer: Optional[Timer] = None

    def _render_frame(self, pos: int) -> str:
        return " ".join(
            self._LIT if i == pos else self._DIM for i in range(self._DOTS)
        )

    def on_mount(self) -> None:
        self._timer = self.set_interval(1 / 12, self._tick)

    def _tick(self) -> None:
        self.update(self._render_frame(self._pos))
        self._pos += self._direction
        if self._pos >= self._DOTS - 1:
            self._direction = -1
        elif self._pos <= 0:
            self._direction = 1

    def stop(self) -> None:
        if self._timer is not None:
            self._timer.stop()


class ItemList(OptionList):
    """Scrollable, filterable list of 1Password items."""

    def render_line(self, y: int) -> Strip:
        line_number = self.scroll_offset.y + y
        try:
            option_index, line_offset = self._lines[line_number]
            option = self.options[option_index]
        except IndexError:
            return Strip.blank(
                self.scrollable_content_region.width,
                self.get_visual_style("option-list--option").rich_style,
            )

        mouse_over = self._mouse_hovering_over == option_index
        component_class = ""
        if option.disabled:
            component_class = "option-list--option-disabled"
        elif self.highlighted == option_index:
            component_class = "option-list--option-highlighted"
        elif mouse_over:
            component_class = "option-list--option-hover"

        if component_class:
            style = self.get_visual_style("option-list--option", component_class)
        else:
            style = self.get_visual_style("option-list--option")
            # Apply even-row striping only for default (non-highlighted/hover) rows.
            if option_index % 2 == 0:
                from dataclasses import replace as _dc_replace
                bg = style.background
                if bg is not None:
                    stripe_bg = bg.lighten(0.05) if bg.brightness < 0.5 else bg.darken(0.05)
                    style = _dc_replace(style, background=stripe_bg)

        strips = self._get_option_render(option, style)
        try:
            strip = strips[line_offset]
        except IndexError:
            return Strip.blank(
                self.scrollable_content_region.width,
                self.get_visual_style("option-list--option").rich_style,
            )
        return strip


class SecretLabel(Static):
    """Shows ••••••••; reveals on hover, copies to clipboard on click."""

    DEFAULT_CSS = """
    SecretLabel {
        color: $text-muted;
    }
    SecretLabel:hover {
        background: $boost;
        color: $success;
    }
    """

    def __init__(self, field_name: str, secret: str) -> None:
        self._field_name = field_name
        self._secret = secret
        display = f"- {_style_label(field_name)}: \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
        super().__init__(Text.from_markup(display))

    def on_enter(self) -> None:
        self.update(Text.from_markup(f"- {_style_label(self._field_name)}: {_escape_value(self._secret)}"))

    def on_leave(self) -> None:
        self.update(Text.from_markup(f"- {_style_label(self._field_name)}: \u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"))

    def on_click(self) -> None:
        self.app.copy_to_clipboard(self._secret)
        self.app.notify(f'Copied "{self._field_name}" to clipboard', timeout=2)


class ValueLabel(Static):
    """Shows a field label and value; clicking copies the value."""

    DEFAULT_CSS = """
    ValueLabel {
        color: $text;
    }
    ValueLabel:hover {
        background: $boost;
    }
    """

    def __init__(self, field_name: str, value: str) -> None:
        self._field_name = field_name
        self._value = value
        # build a Text where label is styled (markup) and value is plain
        text = Text.from_markup(_style_label(field_name) + ": ") + Text(str(value))
        super().__init__(text)

    def on_enter(self) -> None:
        # no reveal behaviour; keep label styled and value plain
        pass

    def on_click(self) -> None:
        self.app.copy_to_clipboard(self._value)
        self.app.notify(f'Copied "{self._field_name}" to clipboard', timeout=2)


class TotpLabel(Static):
    """Shows a live TOTP code with segmented progress bar and traffic-light colour."""

    # Three CSS classes drive the traffic-light colour.  Hover only adds a
    # background boost so the time-based colour remains visible when revealed.
    DEFAULT_CSS = """
    TotpLabel {
        color: $text-muted;
    }
    TotpLabel.totp-fresh {
        color: $success;
    }
    TotpLabel.totp-warning {
        color: $warning;
    }
    TotpLabel.totp-urgent {
        color: $error;
    }
    TotpLabel:hover {
        background: $boost;
    }
    """

    _BAR_WIDTH = 8  # number of block segments

    def __init__(self, field_name: str, otpauth: str, period: int = 30) -> None:
        self._field_name = field_name
        self._otpauth = otpauth
        self._period = period
        self._revealed = False
        super().__init__(Text.from_markup(self._masked()))

    def _seconds_remaining(self) -> int:
        return self._period - int(_time.time()) % self._period

    def _current_code(self) -> str:
        return _totp_now(self._otpauth) or "------"

    def _bar(self, secs: int) -> str:
        filled = max(0, min(self._BAR_WIDTH, round(secs / self._period * self._BAR_WIDTH)))
        return "\u2588" * filled + "\u2591" * (self._BAR_WIDTH - filled)

    def _color_class(self, secs: int) -> str:
        ratio = secs / self._period
        if ratio > 2 / 3:
            return "totp-fresh"
        if ratio > 1 / 3:
            return "totp-warning"
        return "totp-urgent"

    def _masked(self) -> str:
        secs = self._seconds_remaining()
        return f"- {_style_label(self._field_name)}: \u2022\u2022\u2022\u2022\u2022\u2022  {self._bar(secs)} {secs:2}s"

    def _revealed_text(self) -> str:
        secs = self._seconds_remaining()
        return f"- {_style_label(self._field_name)}: {_escape_value(self._current_code())}  {self._bar(secs)} {secs:2}s"

    def _update_color(self) -> None:
        secs = self._seconds_remaining()
        self.remove_class("totp-fresh", "totp-warning", "totp-urgent")
        self.add_class(self._color_class(secs))

    def on_mount(self) -> None:
        self._update_color()
        self._timer = self.set_interval(1, self._tick)

    def on_unmount(self) -> None:
        self._timer.stop()

    def _tick(self) -> None:
        self._update_color()
        self.update(Text.from_markup(self._revealed_text() if self._revealed else self._masked()))

    def on_enter(self) -> None:
        self._revealed = True
        self.update(Text.from_markup(self._revealed_text()))

    def on_leave(self) -> None:
        self._revealed = False
        self.update(Text.from_markup(self._masked()))

    def on_click(self) -> None:
        code = self._current_code()
        self.app.copy_to_clipboard(code)
        self.app.notify(f'Copied "{self._field_name}" to clipboard', timeout=2)


class ItemDetail(Vertical):
    """Panel that renders a single item with interactive fields."""

    def set_content(self, *widgets: Static) -> None:
        self.query("*").remove()
        if widgets:
            self.mount(*widgets)


def _get_totp_period(value: str) -> int:
    """Return the TOTP period (in seconds) from an otpauth URI, defaulting to 30."""
    if value.lower().startswith("otpauth://"):
        qs = parse_qs(urlparse(value).query)
        return int(qs.get("period", ["30"])[0])
    return 30


def _md_to_rich(s: str) -> str:
    """Convert a tiny subset of Markdown to Rich markup for Textual.

    - Leading `# ` -> bold heading
    - `**bold**` -> [bold]...[/bold]
    - `_italic_` -> [italic]...[/italic]
    - Inline code using backticks -> [bold]...[/bold]
    """
    if s.startswith("# "):
        return f"[bold]{s[2:]}[/bold]"
    s = re.sub(r"\*\*(.+?)\*\*", r"[bold]\1[/bold]", s)
    # only treat underscores as italics when they're not inside words
    s = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"[italic]\1[/italic]", s)
    s = re.sub(r"`(.+?)`", r"[bold]\1[/bold]", s)
    return s


def _style_label(s: str) -> str:
    """Style a field/label string (honour **bold**, _italic_, `code`)."""
    s = re.sub(r"\*\*(.+?)\*\*", r"[bold]\1[/bold]", s)
    s = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"[italic]\1[/italic]", s)
    s = re.sub(r"`(.+?)`", r"[bold]\1[/bold]", s)
    return s


def _escape_value(s: str) -> str:
    """Escape Rich markup-sensitive characters in values so they render plain."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace("[", "\\[")
    s = s.replace("]", "\\]")
    # also escape common markdown triggers so they aren't interpreted
    s = s.replace("_", "\\_")
    s = s.replace("*", "\\*")
    s = s.replace("`", "\\`")
    return s


def _build_item_widgets(item: dict) -> List:
    """Build a list of Static / SecretLabel / TotpLabel widgets that render *item*."""
    widgets: List = []
    pending: List[Text] = []

    def flush() -> None:
        if pending:
            combined = Text()
            for i, part in enumerate(pending):
                if i:
                    combined.append("\n")
                combined.append(part)
            widgets.append(Static(combined))
            pending.clear()

    title = item.get("title") or item.get("name") or "(no title)"
    pending.append(Text.from_markup(_md_to_rich(f"# {title}")))
    pending.append(Text(""))

    if category := item.get("category"):
        pending.append(Text.from_markup(_style_label('Category') + ": ") + Text(str(category)))
    if tags := item.get("tags"):
        pending.append(Text.from_markup(_style_label('Tags') + ": ") + Text(', '.join(tags)))

    for url in item.get("urls", []):
        href = url.get("href") or url.get("url") or ""
        label = url.get("label", "")
        if href:
            if label:
                pending.append(Text("- ") + Text.from_markup(_style_label(label) + " ") + Text(href))
            else:
                pending.append(Text("- ") + Text(href))

    pending.append(Text(""))

    for f in item.get("fields", []):
        # Prefer `purpose` (lowercased) when present, otherwise fall back
        # to label, name, type, or a generic fallback.
        purpose = f.get("purpose")
        if purpose:
            name = purpose.lower()
        else:
            name = f.get("label") or f.get("name") or f.get("type") or "field"
        value = f.get("value")
        if not value:
            continue
        ftype = (f.get("type") or "").upper()
        if ftype in ("OTP", "TOTP"):
            flush()
            if _totp_now(value) is not None:
                period = _get_totp_period(value)
                widgets.append(TotpLabel(f"{name} (TOTP)", value, period))
            else:
                pending.append(Text("- ") + Text.from_markup(_style_label(name) + ": ") + Text("(TOTP — unable to generate code)"))
        elif _field_is_sensitive(f):
            flush()
            widgets.append(SecretLabel(name, value))
        else:
            # make non-sensitive values clickable/copiable
            flush()
            widgets.append(ValueLabel(name, value))

    if note := item.get("notesPlain"):
        pending.append(Text("---"))
        pending.append(Text(str(note)))

    flush()
    return widgets


class BrowseApp(App):
    """TUI for searching and viewing exported 1Password items."""

    TITLE = "1p-exporter · Browse Archive"

    # ListItem:even has a perf impact. Might remove this if it's too bad.
    CSS = """
    #search {
        margin: 0;
        border: solid $accent;
    }
    #search:focus {
        border: solid $accent-lighten-2;
    }
    #main {
        height: 1fr;
    }
    #item-list {
        width: 1fr;
        min-width: 30;
        max-width: 50;
    }
    #detail-scroll {
        width: 3fr;
        overflow-y: auto;
        padding: 1 2;
    }
    #detail {
        width: 100%;
        height: auto;
    }
    #spinner {
        width: 100%;
        height: 100%;
        content-align: center middle;
        color: $accent;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
        Binding("escape", "focus_search", "Search", show=True),
        Binding("ctrl+j", "cursor_down", "Next", show=True),
        Binding("ctrl+k", "cursor_up", "Prev", show=True),
    ]

    def __init__(self, archive_path: Path) -> None:
        super().__init__()
        self._archive_path = archive_path
        self._all_items: List[dict] = []
        self._filtered_items: List[dict] = []
        self._filter_seq: int = 0
        self._rebuild_timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Type to search items…", id="search")
        with Horizontal(id="main"):
            yield Spinner(id="spinner")
        yield Footer()

    async def on_mount(self) -> None:
        cfg = load_config()
        if saved_theme := cfg.get("tui_theme"):
            self.theme = saved_theme
        self.run_worker(self._do_load_subprocess, description="load_items")

    async def _do_load_subprocess(self) -> List[dict]:
        import asyncio
        import json
        archive_str = str(self._archive_path)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c",
            "import json, sys; "
            "from pathlib import Path; "
            "from onep_exporter.query import _iter_exported_items; "
            "items = list(_iter_exported_items(Path(sys.argv[1]))); "
            "json.dump(items, sys.stdout)",
            archive_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                f"load subprocess failed: {stderr.decode(errors='replace')}"
            )
        items: List[dict] = json.loads(stdout)
        items.sort(key=lambda i: (i.get("title") or "").lower())
        return items

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.description != "load_items":
            return
        if event.state == WorkerState.SUCCESS:
            result = event.worker.result
            if isinstance(result, list):
                self._all_items = result
            spinner = self.query_one("#spinner", Spinner)
            spinner.stop()
            main = self.query_one("#main", Horizontal)
            await spinner.remove()
            await main.mount(ItemList(id="item-list"))
            await main.mount(Vertical(ItemDetail(id="detail"), id="detail-scroll"))
            self._show_archive_stats()
            self._apply_filter()
            self._rebuild_list()
            self._update_status()
            self.query_one("#search", Input).focus()

    # --- search filtering ---------------------------------------------------

    @on(Input.Changed, "#search")
    def _on_search_changed(self, event: Input.Changed) -> None:
        """Debounce: each keystroke resets a short timer.  When the timer
        fires it reads the *current* Input.value and rebuilds the list
        entirely synchronously — no ``await`` anywhere in the path."""
        if self._rebuild_timer is not None:
            self._rebuild_timer.stop()
        self._rebuild_timer = self.set_timer(
            0.15, self._do_search_rebuild
        )

    def _do_search_rebuild(self) -> None:
        self._rebuild_timer = None
        value = self.query_one("#search", Input).value
        self._apply_filter(value)
        self._rebuild_list()

    def _apply_filter(self, search_text: str = "") -> None:
        text = search_text.strip().lower()
        if text:
            self._filtered_items = [
                it for it in self._all_items
                if text in (it.get("title") or "").lower()
            ]
        else:
            self._filtered_items = list(self._all_items)

    def _rebuild_list(self) -> None:
        self._filter_seq += 1
        lv = self.query_one("#item-list", ItemList)
        options = []
        for item in self._filtered_items:
            title = item.get("title") or "(no title)"
            category = (item.get("category") or "").upper()
            icon = _CATEGORY_ICONS.get(category, "\U0001f4e6")  # \U0001f4e6 fallback
            options.append(f"{icon} {title}")
        lv.set_options(options)
        self._update_status()
        if not self._filtered_items:
            self._show_archive_stats()

    # --- item detail ---------------------------------------------------------

    @on(OptionList.OptionHighlighted, "#item-list")
    def _on_item_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        idx = event.option_index
        if 0 <= idx < len(self._filtered_items):
            item = self._filtered_items[idx]
            detail = self.query_one("#detail", ItemDetail)
            detail.query("*").remove()
            widgets = _build_item_widgets(item)
            if widgets:
                detail.mount(*widgets)

    def _show_archive_stats(self) -> None:
        """Display archive summary in the detail pane."""
        total = len(self._all_items)
        categories: dict = {}
        vaults: set = set()
        for it in self._all_items:
            cat = it.get("category") or "Unknown"
            categories[cat] = categories.get(cat, 0) + 1
            if v := (it.get("vault") or {}).get("name"):
                vaults.add(v)

        lines = [
            f"# {self._archive_path.name}",
            "",
            f"{_style_label('Path')}: {_escape_value(self._archive_path)}",
            f"{_style_label('Items loaded')}: {_escape_value(total)}",
        ]
        if vaults:
            lines.append(f"{_style_label('Vaults')}: {_escape_value(', '.join(sorted(vaults)))}")
        if categories:
            lines.append("")
            lines.append(_style_label('By category:'))
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                lines.append(f"- {_escape_value(cat)}: {_escape_value(count)}")
        if total == 0:
            lines += ["", "⚠ No items found — check the archive path."]
        rendered = "\n".join(_md_to_rich(line) if line.startswith('# ') else line for line in lines)
        self.query_one("#detail", ItemDetail).set_content(
            Static(Text.from_markup(rendered))
        )
        self._update_status()

    # --- status bar ----------------------------------------------------------

    def _update_status(self) -> None:
        total = len(self._all_items)
        shown = len(self._filtered_items)
        archive_name = self._archive_path.name
        self.sub_title = f"{archive_name}  ·  {shown}/{total} items"

    # --- theme persistence --------------------------------------------------

    def watch_theme(self, theme: str) -> None:
        cfg = load_config()
        cfg["tui_theme"] = theme
        save_config(cfg)

    # --- key bindings --------------------------------------------------------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_cursor_down(self) -> None:
        self.query_one("#item-list", ItemList).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#item-list", ItemList).action_cursor_up()


def run_tui(path: Optional[str] = None, backup_base: str = "backups") -> None:
    """Entry point: launch the TUI browser.

    *path* overrides the archive path; otherwise the latest archive under
    *backup_base* is used.
    """
    if path:
        archive = Path(path)
        if not archive.exists():
            raise FileNotFoundError(f"path not found: {archive}")
    else:
        archive = _find_latest_archive(backup_base)

    app = BrowseApp(archive)
    app.run()
