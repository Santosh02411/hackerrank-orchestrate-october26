"""Extract identifier-bearing values from a record (no matching, no resolution).

We only *find and label* identifiers. Deciding whether an identifier belongs to
a requester (identity resolution) is a later stage.

Labelling rule: a field name tells us what kind of value to expect, but the
*value's shape* has the last word (``email`` holding ``"[REDACTED]"`` is not an
email). Fields whose kind is not fixed by name (``subject_reference`` can hold a
user ID or an e-mail address) are classified purely by shape.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

from .model import IdentifierItem, Identifiers

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_EMAIL_FULL = re.compile(EMAIL_RE.pattern)
USER_ID_RE = re.compile(r"user_\d+")
HASH_RE = re.compile(r"[0-9a-fA-F]{64}")
PHONE_RE = re.compile(r"\+\d[\d\s().\-]{5,}\d")
REDACTION_RE = re.compile(r"\[?\s*redacted\s*\]?", re.IGNORECASE)

# name -> expected kind
FIXED_KEYS: Dict[str, str] = {
    "email": "email", "owner_email": "email", "customer_email": "email", "requester_email": "email",
    "email_hash": "email_hash",
    "phone": "phone", "owner_phone": "phone", "requester_phone": "phone",
    "user_id": "user_id",
    "full_name": "name", "display_name": "name", "requester_name": "name", "name": "name",
}
# kind decided by value shape only
MIXED_KEYS = frozenset({
    "subject_reference", "subject_selector", "lookup_value", "lookup_key", "customer_reference",
    "uploaded_by", "query", "correlation_key",
})
# free text: e-mail addresses / user IDs inside prose are extracted and marked free_text
FREE_TEXT_KEYS = frozenset({"message_text", "message_excerpt", "details"})


def classify_value(value: str) -> Optional[str]:
    """Shape-based kind of ``value`` (``None`` if it matches no known shape)."""
    v = value.strip()
    if _EMAIL_FULL.fullmatch(v):
        return "email"
    if USER_ID_RE.fullmatch(v):
        return "user_id"
    if HASH_RE.fullmatch(v):
        return "email_hash"
    if PHONE_RE.fullmatch(v):
        return "phone"
    return None


def extract_identifiers(record: Any, *, base_path: str = "") -> Identifiers:
    """Walk ``record`` (dicts/lists, any depth) and collect labelled identifiers."""
    items: List[IdentifierItem] = []
    redacted: List[str] = []
    _walk(record, base_path, items, redacted)
    return Identifiers(items=tuple(items), redacted_paths=tuple(redacted))


def _join(path: str, key: str) -> str:
    return "%s.%s" % (path, key) if path else key


def _walk(node: Any, path: str, items: List[IdentifierItem], redacted: List[str]) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            _visit(str(key), value, _join(path, str(key)), items, redacted)
    elif isinstance(node, (list, tuple)):
        for i, value in enumerate(node):
            _walk(value, "%s[%d]" % (path, i), items, redacted)


def _visit(key: str, value: Any, path: str, items: List[IdentifierItem], redacted: List[str]) -> None:
    if isinstance(value, (Mapping, list, tuple)):
        _walk(value, path, items, redacted)
        return
    if not isinstance(value, str) or value.strip() == "":
        return  # None / numbers / empty strings carry no identifier
    if key in FIXED_KEYS or key in MIXED_KEYS:
        if REDACTION_RE.fullmatch(value.strip()):
            redacted.append(path)
            return
        shape = classify_value(value)
        expected = FIXED_KEYS.get(key)
        if expected == "name":
            items.append(IdentifierItem("name", value, path))
        elif shape is not None and (expected is None or expected == shape):
            items.append(IdentifierItem(shape, value, path))
        else:
            items.append(IdentifierItem("unclassified", value, path))
    elif key in FREE_TEXT_KEYS:
        if REDACTION_RE.fullmatch(value.strip()):
            redacted.append(path)
            return
        for m in EMAIL_RE.finditer(value):
            items.append(IdentifierItem("email", m.group(0), path, free_text=True))
        for m in USER_ID_RE.finditer(value):
            items.append(IdentifierItem("user_id", m.group(0), path, free_text=True))
