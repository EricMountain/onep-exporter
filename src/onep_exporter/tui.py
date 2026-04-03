"""Interactive text UI for browsing exported 1Password backup data."""

import re
from pathlib import Path
from typing import List, Optional, Union

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, ListItem, ListView, Static

from .config import load_config, save_config
from .query import _iter_exported_items
from .templates import item_to_md


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


class ItemList(ListView):
    """Scrollable, filterable list of 1Password items."""


class ItemDetail(Static):
    """Panel that renders a single item in markdown-ish format."""


class BrowseApp(App):
    """TUI for searching and viewing exported 1Password items."""

    TITLE = "1p-exporter · browse"

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
        border-right: solid $accent;
    }
    #item-list:focus {
        border-right: solid $accent-lighten-2;
    }
    #detail-scroll {
        width: 3fr;
        overflow-y: auto;
        padding: 1 2;
    }
    #detail {
        width: 100%;
    }
    ListItem {
        padding: 0 1;
    }
    ListItem > .item-title {
        width: 100%;
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

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="Type to search items…", id="search")
        with Horizontal(id="main"):
            yield ItemList(id="item-list")
            with Vertical(id="detail-scroll"):
                yield ItemDetail(id="detail", markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        cfg = load_config()
        if saved_theme := cfg.get("tui_theme"):
            self.theme = saved_theme
        self._all_items = _load_items(self._archive_path)
        self._all_items.sort(key=lambda i: (i.get("title") or "").lower())
        self._show_archive_stats()
        await self._apply_filter()
        self._update_status()
        self.query_one("#search", Input).focus()

    # --- search filtering ---------------------------------------------------

    @on(Input.Changed, "#search")
    async def _on_search_changed(self, event: Input.Changed) -> None:
        await self._apply_filter(event.value)

    async def _apply_filter(self, search_text: str = "") -> None:
        text = search_text.strip().lower()
        if text:
            self._filtered_items = [
                it for it in self._all_items
                if text in (it.get("title") or "").lower()
            ]
        else:
            self._filtered_items = list(self._all_items)
        await self._rebuild_list()

    async def _rebuild_list(self) -> None:
        lv = self.query_one("#item-list", ItemList)
        await lv.clear()
        new_items = []
        for item in self._filtered_items:
            title = item.get("title") or "(no title)"
            category = item.get("category") or ""
            label = f"{title}  [{category}]" if category else title
            new_items.append(
                ListItem(Static(label, classes="item-title", markup=False))
            )
        if new_items:
            await lv.extend(new_items)
        self._update_status()
        if not self._filtered_items:
            self._show_archive_stats()

    # --- item detail ---------------------------------------------------------

    @on(ListView.Highlighted, "#item-list")
    def _on_item_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is not None:
            idx = event.list_view.index
            if idx is not None:
                self._show_item(idx)

    def _show_item(self, index: int) -> None:
        if 0 <= index < len(self._filtered_items):
            item = self._filtered_items[index]
            rendered = item_to_md(item)
            self.query_one("#detail", ItemDetail).update(rendered)

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
            f"**Path:** `{self._archive_path}`",
            f"**Items loaded:** {total}",
        ]
        if vaults:
            lines.append(f"**Vaults:** {', '.join(sorted(vaults))}")
        if categories:
            lines.append("")
            lines.append("**By category:**")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                lines.append(f"- {cat}: {count}")
        if total == 0:
            lines += ["", "⚠ No items found — check the archive path."]
        self.query_one("#detail", ItemDetail).update("\n".join(lines))
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
