"""Embed the explorer payload into the single-file HTML template (offline: no network request is ever made by the page)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

TEMPLATE = Path(__file__).with_name("template.html")
PLACEHOLDER = "/*__GHOST_EXPLORER_DATA__*/null"


def embed_json(payload: Dict[str, Any]) -> str:
    """JSON that is safe inside a <script> element: no raw '<', '>' or '&' (so no '</script>' or '<!--' can appear) and ASCII only."""
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(payload: Dict[str, Any], template: Path = TEMPLATE) -> str:
    html = template.read_text(encoding="utf-8").replace("\r\n", "\n")
    if PLACEHOLDER not in html:
        raise ValueError("template has no data placeholder %r" % PLACEHOLDER)
    return html.replace(PLACEHOLDER, embed_json(payload), 1)
