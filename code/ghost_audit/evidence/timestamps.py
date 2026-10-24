"""Timestamp helpers.

The repository uses one timestamp format everywhere: ``YYYY-MM-DDTHH:MM:SSZ``
(verified for every timestamp field in the JSON, SQL and CSV evidence). We keep
the original string in all data structures (so provenance is exact) and only
parse it when a comparison is needed. Fractional seconds are tolerated; any other
shape is reported as unparseable instead of being guessed at.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


def is_iso_utc(value: object) -> bool:
    return isinstance(value, str) and bool(_ISO_Z.match(value))


def parse_iso_utc(value: object) -> Optional[datetime]:
    """Parse ``2026-09-15T12:00:00Z`` into an aware UTC datetime, else ``None``."""
    if not is_iso_utc(value):
        return None
    text = str(value)[:-1]
    fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in text else "%Y-%m-%dT%H:%M:%S"
    try:
        return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
    except ValueError:  # e.g. month 13: shape matched, value impossible
        return None
