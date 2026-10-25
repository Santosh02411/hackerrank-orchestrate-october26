"""Shared row model for text extracted from PDFs and screenshots (Stage 1C).

A document is turned into *rows* of *cells*:

* PDF  - one row per text line of pypdf's layout extraction, cells split on runs of 2+ spaces;
* image - OCR words are regrouped into visual rows by vertical position, and a new cell starts at a
  large horizontal gap (table columns). Each cell keeps its box and the minimum word confidence.

A row becomes an Observation only if it is *anchored*: it contains an e-mail address, a user id, a
resource reference (``backup_9287``), a phone number or an e-mail hash, or an identifier-looking token
that is malformed (``data_flow.1121``). Every other row is kept verbatim in ``metadata`` (never dropped).

Identifiers are reported exactly as read. OCR uncertainty is only ever *labelled* (low word
confidence, or not reproduced by an independent second pass); nothing is corrected, completed or
snapped to a known identifier here. Matching against known people is a later stage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .identifiers import EMAIL_RE, USER_ID_RE
from .model import (
    IdentifierItem,
    Identifiers,
    Observation,
    ObservationKind,
    ParsedFile,
    ParseStatus,
    ScopeKind,
    SnapshotScope,
    TimestampSource,
)
from .ocr import OcrWord

# resource-id prefixes that occur in system_activity.csv (account_, search_, ... audit_record_, legal_hold_ ...)
RESOURCE_PREFIXES = ("account", "analytics", "audit_record", "backup", "cache", "data_flow", "email_delivery",
                     "export", "legal_hold", "marketing", "object", "search", "support", "tombstone")
_P = "|".join(RESOURCE_PREFIXES)
_B0, _B1 = r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])"
RESOURCE_SEARCH = re.compile(_B0 + r"(?:%s)_\d+" % _P + _B1)
MALFORMED_RESOURCE = re.compile(_B0 + r"(?:%s)[^\w\s|/,;:()\[\]@]\d+" % _P + r"(?!\w)")   # e.g. data_flow.1121
USER_SEARCH = re.compile(_B0 + USER_ID_RE.pattern + _B1)
EMAIL_SEARCH = re.compile(_B0 + EMAIL_RE.pattern)
HASH_SEARCH = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
PHONE_SEARCH = re.compile(r"(?<![\w+])\+\d[\d ()\-]{6,}\d")
TIME_KEY = re.compile(r"\b\d{1,2} [A-Z][a-z]{2} \d{4} (\d{1,2})$")
TIME_VALUE = re.compile(r"^(\d{2}) ?UTC$")

OCR_CONFIDENCE_THRESHOLD = 80.0


@dataclass(frozen=True)
class Cell:
    text: str
    conf: Optional[float] = None                       # minimum word confidence (OCR only)
    box: Optional[Tuple[int, int, int, int]] = None    # left, top, width, height in original-image pixels
    spans: Tuple[Tuple[int, int, float], ...] = ()     # (start, end, conf) of each OCR word inside `text`


@dataclass(frozen=True)
class DocRow:
    page: int
    index: int
    cells: Tuple[Cell, ...]
    multi_region: bool = False   # OCR row whose cells are separated by a very wide gap (probably unrelated panels)
    ocr: bool = False            # the text of this row was read by OCR (not taken from a PDF text layer)

    @property
    def text(self) -> str:
        return " ".join(c.text for c in self.cells)


@dataclass(frozen=True)
class Anchor:
    kind: str       # email | user_id | resource_ref | phone | email_hash
    value: str
    cell: int
    start: int
    end: int


def find_anchors(row: DocRow) -> Tuple[List[Anchor], List[Tuple[int, str]]]:
    """(well-formed anchors, malformed identifier-like tokens as (cell, token)) of a row."""
    anchors: List[Anchor] = []
    malformed: List[Tuple[int, str]] = []
    for ci, cell in enumerate(row.cells):
        for kind, rx in (("email", EMAIL_SEARCH), ("user_id", USER_SEARCH), ("resource_ref", RESOURCE_SEARCH),
                         ("email_hash", HASH_SEARCH), ("phone", PHONE_SEARCH)):
            for m in rx.finditer(cell.text):
                anchors.append(Anchor(kind, m.group(0), ci, m.start(), m.end()))
        for m in MALFORMED_RESOURCE.finditer(cell.text):
            malformed.append((ci, m.group(0)))
    return anchors, malformed


def rows_from_text_lines(lines: Sequence[str], page: int) -> List[DocRow]:
    rows: List[DocRow] = []
    for raw in lines:
        if not raw.strip():
            continue
        cells = tuple(Cell(c) for c in re.split(r"\s{2,}", raw.strip()) if c)
        rows.append(DocRow(page, len(rows) + 1, cells))
    return rows


def rows_from_words(words: Sequence[OcrWord], image_width: int, page: int = 1) -> List[DocRow]:
    """Regroup OCR words into visual rows and cells (see module docstring)."""
    groups: List[List[OcrWord]] = []
    centres: List[float] = []
    for w in sorted(words, key=lambda x: (x.top + x.height / 2.0, x.left)):
        cy = w.top + w.height / 2.0
        if groups:
            hs = sorted(g.height for g in groups[-1])
            tol = 0.6 * hs[len(hs) // 2]
            if abs(cy - centres[-1]) <= tol:
                groups[-1].append(w)
                centres[-1] = sum(g.top + g.height / 2.0 for g in groups[-1]) / len(groups[-1])
                continue
        groups.append([w])
        centres.append(cy)
    rows: List[DocRow] = []
    for g in groups:
        g = sorted(g, key=lambda x: x.left)
        hs = sorted(x.height for x in g)
        gap_cell = max(14.0, 1.6 * hs[len(hs) // 2])
        gap_region = 0.12 * max(1, image_width)
        cells: List[List[OcrWord]] = [[g[0]]]
        multi = False
        for prev, cur in zip(g, g[1:]):
            gap = cur.left - (prev.left + prev.width)
            if gap > gap_cell:
                cells.append([cur])
                multi = multi or gap > gap_region
            else:
                cells[-1].append(cur)
        built = []
        for cw in cells:
            text, spans = "", []
            for w in cw:
                if text:
                    text += " "
                spans.append((len(text), len(text) + len(w.text), w.conf))
                text += w.text
            left, top = min(w.left for w in cw), min(w.top for w in cw)
            right, bottom = max(w.left + w.width for w in cw), max(w.top + w.height for w in cw)
            built.append(Cell(text, min(w.conf for w in cw), (left, top, right - left, bottom - top), tuple(spans)))
        rows.append(DocRow(page, len(rows) + 1, tuple(built), multi, True))
    return rows


def _anchor_confidence(cell: Cell, a: Anchor) -> Optional[float]:
    if not cell.spans:
        return None
    hit = [c for (s, e, c) in cell.spans if s < a.end and e > a.start]
    return min(hit) if hit else cell.conf


def split_time_flag(row: DocRow) -> Optional[Dict[str, str]]:
    """Detect ``"... 2026 10"`` | ``"24 UTC"`` (a time whose colon was the key/value separator in the source)."""
    for left, right in zip(row.cells, row.cells[1:]):
        if TIME_KEY.search(left.text) and TIME_VALUE.match(right.text):
            return {"key_cell": left.text, "value_cell": right.text,
                    "note": "the source text contains no colon between hour and minute; it is NOT reconstructed here"}
    return None


def rows_to_observations(
    ctx: Any,
    parsed: ParsedFile,
    rows: Sequence[DocRow],
    *,
    collection: str,
    extraction: Dict[str, Any],
    secondary_values: Optional[Set[Tuple[str, str]]] = None,
    ocr: bool = False,
) -> Dict[str, int]:
    """Append one Observation per anchored row; keep every other row in ``parsed.metadata['unanchored_rows']``.

    ``secondary_values`` is the set of (kind, value) anchors found by an independent OCR pass; an OCR anchor
    missing from it is labelled uncertain. Returns counters used for the file-level diagnostics.
    """
    cov = parsed.coverage
    unanchored: List[Dict[str, Any]] = parsed.metadata.setdefault("unanchored_rows", [])
    counts = {"anchored": 0, "unanchored": 0, "uncertain": 0, "low_confidence": 0, "unstable": 0, "identifiers": 0, "malformed": 0}
    for row in rows:
        cov.records_seen += 1
        cov.records_recognized += 1
        anchors, malformed = find_anchors(row)
        is_ocr = row.ocr or ocr
        if not anchors and not malformed:
            counts["unanchored"] += 1
            entry: Dict[str, Any] = {"page": row.page, "row": row.index, "text": row.text,
                                     "cells": [c.text for c in row.cells],
                                     "conf": min((c.conf for c in row.cells if c.conf is not None), default=None)}
            tsplit = split_time_flag(row)
            if tsplit:
                entry["time_split"] = tsplit
            unanchored.append(entry)
            continue
        counts["anchored"] += 1
        loc = "page=%d;row=%d" % (row.page, row.index)
        items: List[IdentifierItem] = []
        flags: List[str] = ["document_text"] + (["ocr"] if is_ocr else [])
        for a in anchors:
            conf = _anchor_confidence(row.cells[a.cell], a)
            low = conf is not None and conf < OCR_CONFIDENCE_THRESHOLD
            unstable = bool(is_ocr and secondary_values is not None and (a.kind, a.value) not in secondary_values)
            uncertain = low or unstable
            counts["identifiers"] += 1
            counts["low_confidence"] += low
            counts["unstable"] += unstable
            counts["uncertain"] += uncertain
            items.append(IdentifierItem(a.kind, a.value, "cells[%d]" % a.cell, free_text=True,
                                        confidence=conf, uncertain=uncertain))
        if any(i.uncertain for i in items):
            flags.append("ocr_uncertain_identifier")
        if malformed:
            counts["malformed"] += len(malformed)
            flags.append("malformed_identifier_token")
        if row.multi_region:
            flags.append("multi_region_row")
        refs = sorted({i.value for i in items if i.kind == "resource_ref"})
        if len(refs) > 1:
            flags.append("multiple_resource_refs")
        fields: Dict[str, Any] = {
            "text": row.text, "page": row.page, "row": row.index,
            "cells": [{"text": c.text, "conf": c.conf, "box": list(c.box) if c.box else None} for c in row.cells],
            "extraction": extraction,
        }
        if malformed:
            fields["malformed_identifier_tokens"] = [{"cell": ci, "token": tok} for ci, tok in malformed]
        tsplit = split_time_flag(row)
        if tsplit:
            fields["time_split"] = tsplit
            flags.append("time_split_across_cells")
        obs_id, prov = ctx.next_provenance(loc)
        parsed.observations.append(Observation(
            obs_id=obs_id, kind=ObservationKind.RECORD, provenance=prov, system_id=None,
            resource_id=refs[0] if len(refs) == 1 else None, collection=collection,
            identifiers=Identifiers(items=tuple(items)), fields=fields, flags=tuple(flags)))
    return counts


def finalize_document(ctx: Any, parsed: ParsedFile, rows: Sequence[DocRow], extraction: Dict[str, Any], *, collection: str,
                      secondary_values: Optional[Set[Tuple[str, str]]] = None, ocr: bool = False,
                      secondary_only: Sequence[Tuple[str, str]] = ()) -> ParsedFile:
    """Shared tail of the PDF and screenshot parsers: observations, scope, diagnostics, summary warnings, status."""
    cov = parsed.coverage
    cov.containers_seen = 1
    counts = rows_to_observations(ctx, parsed, rows, collection=collection, extraction=extraction,
                                  secondary_values=secondary_values, ocr=ocr)
    cov.containers_recognized = 1 if rows else 0
    extraction = dict(extraction, **{"rows": len(rows)}, **{"row_" + k: v for k, v in counts.items()})
    if ocr or secondary_values is not None:
        extraction["identifiers_only_in_second_pass"] = [{"kind": k, "value": v} for k, v in secondary_only]
    parsed.metadata["extraction"] = extraction
    parsed.scopes.append(SnapshotScope(ScopeKind.DOCUMENT, ctx.ref.file_id if ctx.ref else None, None,
                                       ctx.ref.origin if ctx.ref else None, None, TimestampSource.NONE, len(rows), "file", extra=extraction))
    if counts["uncertain"]:
        ctx.warn("OCR_UNCERTAIN_IDENTIFIER",
                 "%d of %d identifier(s) are uncertain (%d below confidence %.0f, %d not reproduced by the independent second pass); "
                 "they are reported exactly as read, flagged `ocr_uncertain_identifier`, and never corrected"
                 % (counts["uncertain"], counts["identifiers"], counts["low_confidence"], OCR_CONFIDENCE_THRESHOLD, counts["unstable"]))
    if counts["malformed"]:
        ctx.warn("OCR_MALFORMED_IDENTIFIER", "%d identifier-like token(s) have the wrong shape (e.g. a '.' instead of '_'); kept verbatim in fields, not corrected" % counts["malformed"])
    if secondary_only:
        ctx.warn("OCR_PASS_DISAGREEMENT", "%d identifier(s) appear only in the second OCR pass (listed in metadata); they are not observations" % len(secondary_only), level="info")
    ctx.warn("DOCUMENT_TIME_UNSTRUCTURED", "the document carries no machine-readable observation time; effective time falls back to the manifest capture time (labelled manifest_captured)", level="info")
    parsed.warnings = ctx.warnings
    if not rows:
        parsed.status = ParseStatus.FAILED
    return parsed.finalize()
