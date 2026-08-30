"""
Autobahn Defender v2.0 -- Security News Tab UI.

A standalone tab (the AI does NOT need to be running) that lets users browse
RSS security news articles polled daily by rss_feeds.poll_all_feeds().

Layout:
  - Header: "Security News" title + "Refresh Feeds Now" button + "Last Updated" label
  - Left panel: Article list (QListWidget) with severity badge prefixes, newest first
  - Right panel: Article detail (QTextBrowser) + "Open in Browser" button
  - Bottom: Collapsible feed-sources section with per-source checkboxes + counts
  - Top search/filter input (filters by title + summary, case-insensitive)

The tab reads from security_news.jsonl via intel_db.read_all(). main.py connects
the refresh_requested signal to rss_feeds.poll_all_feeds() (run off the UI thread
by the caller) and calls refresh_articles() + set_last_updated() afterwards.
"""

from __future__ import annotations

import html
import logging
import re
from collections import Counter
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl

from ai import intel_db, rss_feeds

log = logging.getLogger(__name__)

# Reuse theme colors from ui_tabs for visual consistency with the rest of the app.
try:
    from ui_tabs import (
        BG_DARK, BG_CARD, BORDER, ACCENT, ACCENT_HOVER,
        TEXT_PRIMARY, TEXT_SECONDARY, DANGER, SUCCESS,
    )
except Exception:
    BG_DARK = "#121212"
    BG_CARD = "#1E1E1E"
    BORDER = "#2C2C2C"
    ACCENT = "#2962FF"
    ACCENT_HOVER = "#1E53E0"
    TEXT_PRIMARY = "#E0E0E0"
    TEXT_SECONDARY = "#A0A0A0"
    DANGER = "#CF6679"
    SUCCESS = "#4CAF50"

# Severity badge colors (used as inline HTML in list items + detail view).
SEV_ZERO_DAY_COLOR = "#E53935"   # red, for flag == "zero_day_candidate"
SEV_CVE_COLOR = "#FB8C00"        # orange, for CVE-YYYY in title
SEV_NONE_COLOR = TEXT_SECONDARY

# Regex to detect a CVE identifier in a title (CVE-YYYY-NNNN+).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _short_date(iso_ts: str) -> str:
    """Render an ISO timestamp (seen_at or published) as a short date string.

    Falls back to the raw string if parsing fails, so the UI never shows blanks.
    """
    if not iso_ts:
        return ""
    # seen_at is full ISO with timezone; published may be an RFC-822 RSS date.
    # Try ISO first (what we write), then the common RSS date formats via fromisoformat
    # after stripping a trailing 'Z'.
    candidate = iso_ts
    try:
        if candidate.endswith("Z"):
            candidate = candidate[:-1]
        dt = datetime.fromisoformat(candidate)
        return dt.strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        pass
    # Last resort: trim to first 16 chars if it looks like a date prefix.
    if len(iso_ts) >= 10 and iso_ts[4:5] == "-":
        return iso_ts[:16]
    return iso_ts


class SecurityNewsTab(QWidget):
    """Security news browser tab.

    Signals:
        refresh_requested -- emitted when the user clicks "Refresh Feeds Now";
                            main.py connects this to rss_feeds.poll_all_feeds()
                            (run off the UI thread) and then calls
                            refresh_articles() + set_last_updated().

    Public methods:
        refresh_articles()         -- reload articles from security_news.jsonl
        set_last_updated(ts_str)    -- update the "Last Updated" label
    """

    refresh_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._articles: list[dict] = []          # full article dicts, newest first
        self._filtered: list[dict] = []          # currently visible subset
        self._current_article: dict | None = None
        self._feed_checks: dict[str, QCheckBox] = {}  # source_id -> checkbox
        self._feed_count_labels: dict[str, QLabel] = {}  # source_id -> count label
        self._feeds_expanded = True

        self._build_ui()
        self._apply_styles()
        # Initial population (safe even if the JSONL is empty/missing).
        try:
            self.refresh_articles()
        except Exception as e:  # never let a startup read failure kill the tab
            log.warning("SecurityNewsTab: initial refresh failed: %s", e)

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # --- Header row ---
        header = QHBoxLayout()
        header.setSpacing(12)

        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        self.title_label = QLabel("Security News")
        self.title_label.setFont(title_font)
        header.addWidget(self.title_label)

        header.addStretch(1)

        self.last_updated_label = QLabel("Last Updated: —")
        self.last_updated_label.setAlignment(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        header.addWidget(self.last_updated_label)

        self.refresh_btn = QPushButton("Refresh Feeds Now")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        header.addWidget(self.refresh_btn)

        root.addLayout(header)

        # --- Search / filter input ---
        search_row = QHBoxLayout()
        search_row.setSpacing(8)
        search_label = QLabel("Filter:")
        search_label.setStyleSheet(f"color: {TEXT_SECONDARY};")
        search_row.addWidget(search_label)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Filter articles by keyword (title + summary)…"
        )
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)
        search_row.addWidget(self.search_input, 1)
        root.addLayout(search_row)

        # --- Main split: article list (left) + detail (right) ---
        split = QHBoxLayout()
        split.setSpacing(12)

        # Left: article list
        self.article_list = QListWidget()
        self.article_list.setUniformItemSizes(False)
        self.article_list.setAlternatingRowColors(False)
        self.article_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.article_list.itemSelectionChanged.connect(self._on_article_selected)
        self.article_list.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.article_list.setMinimumWidth(360)
        split.addWidget(self.article_list, 1)

        # Right: detail view
        detail_col = QVBoxLayout()
        detail_col.setSpacing(8)

        self.detail_view = QTextBrowser()
        self.detail_view.setOpenExternalLinks(False)
        self.detail_view.setOpenLinks(False)
        self.detail_view.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.detail_view.setMinimumWidth(380)
        self.detail_view.setPlaceholderText(
            "Select an article to view its details here."
        )
        detail_col.addWidget(self.detail_view, 1)

        open_row = QHBoxLayout()
        open_row.addStretch(1)
        self.open_browser_btn = QPushButton("Open in Browser")
        self.open_browser_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_browser_btn.setEnabled(False)
        self.open_browser_btn.clicked.connect(self._open_current_in_browser)
        open_row.addWidget(self.open_browser_btn)
        detail_col.addLayout(open_row)

        split.addWidget(self.detail_view, 1)
        root.addLayout(split, 1)

        # --- Bottom: collapsible feed sources ---
        self.feed_header_btn = QToolButton()
        self.feed_header_btn.setText("Feed Sources")
        self.feed_header_btn.setCheckable(True)
        self.feed_header_btn.setChecked(True)
        self.feed_header_btn.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        self.feed_header_btn.setArrowType(Qt.ArrowType.DownArrow)
        self.feed_header_btn.setStyleSheet(
            f"QToolButton {{ color: {TEXT_PRIMARY}; "
            f"background: {BG_CARD}; border: 1px solid {BORDER}; "
            f"border-radius: 6px; padding: 6px 12px; font-weight: bold; }}"
            f"QToolButton:hover {{ border-color: {ACCENT}; }}"
        )
        self.feed_header_btn.toggled.connect(self._on_feed_toggle)
        root.addWidget(self.feed_header_btn)

        self.feed_container = QFrame()
        self.feed_container.setObjectName("FeedContainer")
        feed_layout = QVBoxLayout(self.feed_container)
        feed_layout.setContentsMargins(0, 0, 0, 0)
        feed_layout.setSpacing(6)
        self.feed_grid_layout = feed_layout  # keep a ref for populating counts
        root.addWidget(self.feed_container)

        # "Select all / none" helpers
        sel_row = QHBoxLayout()
        sel_row.setSpacing(10)
        sel_all = QPushButton("Select All")
        sel_all.setCursor(Qt.CursorShape.PointingHandCursor)
        sel_all.clicked.connect(lambda: self._set_all_feeds(True))
        sel_none = QPushButton("Clear All")
        sel_none.setCursor(Qt.CursorShape.PointingHandCursor)
        sel_none.clicked.connect(lambda: self._set_all_feeds(False))
        sel_row.addWidget(sel_all)
        sel_row.addWidget(sel_none)
        sel_row.addStretch(1)
        feed_layout.addLayout(sel_row)

        # Per-feed checkboxes (populated from rss_feeds.FEEDS).
        self._build_feed_checkboxes()

        root.addStretch(0)

    def _build_feed_checkboxes(self) -> None:
        """Create a checkbox + count label for each feed source."""
        feeds = getattr(rss_feeds, "FEEDS", []) or []
        for feed in feeds:
            fid = feed.get("id", "")
            name = feed.get("name", fid)
            covers = feed.get("covers", "")

            row = QHBoxLayout()
            row.setSpacing(8)

            cb = QCheckBox(name)
            cb.setChecked(True)
            cb.setToolTip(covers)
            cb.stateChanged.connect(self._apply_filters)
            self._feed_checks[fid] = cb
            row.addWidget(cb)

            count_lbl = QLabel("(0)")
            count_lbl.setStyleSheet(f"color: {TEXT_SECONDARY};")
            count_lbl.setToolTip("Article count for this feed")
            self._feed_count_labels[fid] = count_lbl
            row.addWidget(count_lbl)

            row.addStretch(1)
            self.feed_grid_layout.addLayout(row)

        # Include CISA KEV if present in the data even though it's not in FEEDS
        # (it is polled separately by rss_feeds.poll_cisa_kev()).
        if "cisa_kev" not in self._feed_checks:
            row = QHBoxLayout()
            row.setSpacing(8)
            cb = QCheckBox("CISA Known Exploited Vulnerabilities (KEV)")
            cb.setChecked(True)
            cb.setToolTip("CISA KEV catalog (polled as JSON, not RSS)")
            cb.stateChanged.connect(self._apply_filters)
            self._feed_checks["cisa_kev"] = cb
            row.addWidget(cb)
            count_lbl = QLabel("(0)")
            count_lbl.setStyleSheet(f"color: {TEXT_SECONDARY};")
            self._feed_count_labels["cisa_kev"] = count_lbl
            row.addWidget(count_lbl)
            row.addStretch(1)
            self.feed_grid_layout.addLayout(row)

    def _apply_styles(self) -> None:
        """Apply widget-level stylesheets using the shared dark theme."""
        self.setStyleSheet(
            f"""
            SecurityNewsTab {{
                background-color: {BG_DARK};
                color: {TEXT_PRIMARY};
            }}
            QLabel {{
                color: {TEXT_PRIMARY};
                background: transparent;
            }}
            QPushButton {{
                background-color: {ACCENT};
                color: white;
                border: 1px solid {ACCENT_HOVER};
                border-radius: 8px;
                padding: 8px 18px;
                font-size: 13px;
                font-weight: bold;
                min-width: 90px;
                min-height: 36px;
            }}
            QPushButton:hover {{
                background-color: {ACCENT_HOVER};
                border-color: {ACCENT};
            }}
            QPushButton:pressed {{
                background-color: {ACCENT_HOVER};
            }}
            QPushButton:disabled {{
                background-color: #455A64;
                color: #888;
                border-color: #37474F;
            }}
            QLineEdit {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 8px 10px;
                color: {TEXT_PRIMARY};
                selection-background-color: {ACCENT};
            }}
            QLineEdit:focus {{
                border-color: {ACCENT};
            }}
            QListWidget {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                color: {TEXT_PRIMARY};
                outline: 0;
            }}
            QListWidget::item {{
                padding: 10px 12px;
                border-bottom: 1px solid {BORDER};
            }}
            QListWidget::item:selected {{
                background-color: {ACCENT};
                color: white;
            }}
            QListWidget::item:hover {{
                background-color: #262626;
            }}
            QTextBrowser {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
                color: {TEXT_PRIMARY};
                padding: 12px;
            }}
            QCheckBox {{
                color: {TEXT_PRIMARY};
                spacing: 8px;
                background: transparent;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {BORDER};
                background-color: {BG_CARD};
            }}
            QCheckBox::indicator:checked {{
                background-color: {ACCENT};
                border-color: {ACCENT};
            }}
            QFrame#FeedContainer {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}
            """
        )

    # ---------------------------------------------------- Public API

    def refresh_articles(self) -> None:
        """Reload articles from security_news.jsonl and repopulate the list.

        Safe to call when the file is missing/empty: shows an empty list.
        """
        try:
            articles = intel_db.read_all(intel_db.NEWS_FILE)
        except Exception as e:
            log.warning("SecurityNewsTab: failed to read news file: %s", e)
            articles = []

        # Sort by seen_at desc (newest first). Missing seen_at sorts last.
        articles.sort(key=lambda r: r.get("seen_at", "") or "", reverse=True)
        self._articles = articles
        self._update_feed_counts()
        self._apply_filters()

    def set_last_updated(self, timestamp_str: str) -> None:
        """Update the 'Last Updated' label. Accepts an ISO timestamp or any string."""
        if not timestamp_str:
            display = "—"
        else:
            display = _short_date(timestamp_str) or timestamp_str
        self.last_updated_label.setText(f"Last Updated: {display}")

    # ---------------------------------------------------- Filtering

    def _apply_filters(self, *_) -> None:
        """Recompute the visible article list from search + feed checkboxes."""
        query = self.search_input.text().strip().lower()
        enabled_sources: set[str] = {
            sid for sid, cb in self._feed_checks.items() if cb.isChecked()
        }

        filtered: list[dict] = []
        for art in self._articles:
            sid = art.get("source_id", "")
            if enabled_sources and sid not in enabled_sources:
                continue
            if query:
                title = (art.get("title", "") or "").lower()
                summary = (art.get("summary", "") or "").lower()
                if query not in title and query not in summary:
                    continue
            filtered.append(art)

        self._filtered = filtered
        self._populate_list(filtered)

    def _populate_list(self, articles: list[dict]) -> None:
        """Fill the QListWidget with the given articles (already filtered/sorted)."""
        prev_id = None
        if self._current_article is not None:
            prev_id = self._current_article.get("id")

        self.article_list.blockSignals(True)
        self.article_list.clear()

        select_row = -1
        for idx, art in enumerate(articles):
            title = art.get("title", "") or "(untitled)"
            source = art.get("source", "") or art.get("source_id", "") or ""
            seen = _short_date(art.get("seen_at", "") or art.get("published", ""))
            badge, badge_color = self._badge_for(art)

            # Rich text item: badge + title on first line, source + date on second.
            item_text = (
                f"<div style='white-space: normal;'>"
                f"<div style='font-weight:600;'>"
                f"<span style='color:{badge_color}; font-size:14px;'>{badge}</span>&nbsp;"
                f"{html.escape(title)}"
                f"</div>"
                f"<div style='color:{TEXT_SECONDARY}; font-size:11px;'>"
                f"{html.escape(source)} &middot; {html.escape(seen)}"
                f"</div>"
                f"</div>"
            )
            item = QListWidgetItem()
            item.setText(item_text)
            # Store the article dict on the item for quick access on selection.
            item.setData(Qt.ItemDataRole.UserRole, art)
            # Give multi-line items enough vertical room.
            item.setSizeHint(item.sizeHint().expandedTo(
                self.article_list.fontMetrics().size(0, "Ay")
            ))
            self.article_list.addItem(item)

            if prev_id is not None and art.get("id") == prev_id:
                select_row = idx

        self.article_list.blockSignals(False)

        # Restore selection if the current article is still visible.
        if select_row >= 0:
            self.article_list.setCurrentRow(select_row)
        else:
            # No selection: clear the detail view + disable Open button.
            self._current_article = None
            self.detail_view.clear()
            self.open_browser_btn.setEnabled(False)

    # ---------------------------------------------------- Helpers

    @staticmethod
    def _badge_for(art: dict) -> tuple[str, str]:
        """Return (badge_text, badge_color) for an article.

        - red ● for flag == "zero_day_candidate"
        - orange ● for CVE-YYYY in the title
        - plain • otherwise (muted)
        """
        if art.get("flag") == "zero_day_candidate":
            return "●", SEV_ZERO_DAY_COLOR
        title = art.get("title", "") or ""
        if _CVE_RE.search(title):
            return "●", SEV_CVE_COLOR
        return "•", SEV_NONE_COLOR

    def _update_feed_counts(self) -> None:
        """Update the per-feed article count labels from the loaded articles."""
        counts: Counter = Counter()
        for art in self._articles:
            sid = art.get("source_id", "")
            if sid:
                counts[sid] += 1

        # Ensure a label exists for any source_id seen in the data but not in FEEDS.
        for sid in list(counts.keys()):
            if sid not in self._feed_checks:
                self._add_dynamic_feed_checkbox(sid, counts[sid])

        for sid, label in self._feed_count_labels.items():
            label.setText(f"({counts.get(sid, 0)})")

    def _add_dynamic_feed_checkbox(self, sid: str, count: int) -> None:
        """Add a checkbox for a source_id that appeared in data but not in FEEDS."""
        # Use the feed name from FEEDS if we can find it, else the source_id.
        display_name = sid
        covers = ""
        for feed in getattr(rss_feeds, "FEEDS", []) or []:
            if feed.get("id") == sid:
                display_name = feed.get("name", sid)
                covers = feed.get("covers", "")
                break
        # Fall back to a friendly name for the CISA KEV special case.
        if sid == "cisa_kev" and display_name == sid:
            display_name = "CISA Known Exploited Vulnerabilities (KEV)"
            covers = "CISA KEV catalog (polled as JSON, not RSS)"

        row = QHBoxLayout()
        row.setSpacing(8)
        cb = QCheckBox(display_name)
        cb.setChecked(True)
        cb.setToolTip(covers or sid)
        cb.stateChanged.connect(self._apply_filters)
        self._feed_checks[sid] = cb
        row.addWidget(cb)

        count_lbl = QLabel(f"({count})")
        count_lbl.setStyleSheet(f"color: {TEXT_SECONDARY};")
        self._feed_count_labels[sid] = count_lbl
        row.addWidget(count_lbl)
        row.addStretch(1)
        self.feed_grid_layout.addLayout(row)

    def _set_all_feeds(self, checked: bool) -> None:
        """Check or uncheck every feed-source checkbox."""
        for cb in self._feed_checks.values():
            cb.setChecked(checked)
        # _apply_filters is triggered by each checkbox's stateChanged signal.

    # ---------------------------------------------------- Event slots

    def _on_article_selected(self) -> None:
        """Show the selected article's details in the right panel."""
        items = self.article_list.selectedItems()
        if not items:
            self._current_article = None
            self.detail_view.clear()
            self.open_browser_btn.setEnabled(False)
            return

        art = items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(art, dict):
            return

        self._current_article = art
        self._render_detail(art)
        self.open_browser_btn.setEnabled(bool(art.get("url")))

    def _render_detail(self, art: dict) -> None:
        """Render an article dict as styled HTML in the detail view."""
        title = art.get("title", "") or "(untitled)"
        source = art.get("source", "") or art.get("source_id", "") or "—"
        seen = _short_date(art.get("seen_at", "") or art.get("published", ""))
        summary = art.get("summary", "") or "(no summary available)"
        url = art.get("url", "") or ""
        badge, badge_color = self._badge_for(art)
        flag_note = ""
        if art.get("flag") == "zero_day_candidate":
            flag_note = (
                f"<div style='color:{SEV_ZERO_DAY_COLOR}; font-weight:bold; "
                f"margin:8px 0;'>⚠ Zero-day candidate — flagged for review.</div>"
            )

        url_html = (
            f"<div style='color:{TEXT_SECONDARY}; font-size:11px; "
            f"word-break:break-all; margin-top:10px;'>"
            f"{html.escape(url)}</div>"
            if url else ""
        )

        html_doc = f"""
        <html><body style='color:{TEXT_PRIMARY}; font-family: sans-serif;'>
          <div style='font-size:11px; color:{TEXT_SECONDARY};'>
            <span style='color:{badge_color}; font-size:14px;'>{badge}</span>
            &nbsp;{html.escape(source)} &middot; {html.escape(seen)}
          </div>
          <div style='font-size:16px; font-weight:bold; margin:8px 0 6px 0;
                      line-height:1.3;'>
            {html.escape(title)}
          </div>
          {flag_note}
          <hr style='border:0; border-top:1px solid {BORDER}; margin:10px 0;'/>
          <div style='font-size:13px; line-height:1.5;'>
            {html.escape(summary).replace(chr(10), "<br>")}
          </div>
          {url_html}
        </body></html>
        """
        self.detail_view.setHtml(html_doc)

    def _open_current_in_browser(self) -> None:
        """Open the currently selected article's URL in the system browser."""
        if not self._current_article:
            return
        url = self._current_article.get("url", "") or ""
        if not url:
            return
        QDesktopServices.openUrl(QUrl(url))

    def _on_feed_toggle(self, checked: bool) -> None:
        """Expand/collapse the feed-sources panel."""
        self._feeds_expanded = checked
        self.feed_container.setVisible(checked)
        self.feed_header_btn.setArrowType(
            Qt.ArrowType.DownArrow if checked else Qt.ArrowType.RightArrow
        )