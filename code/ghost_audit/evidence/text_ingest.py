"""Plain-text handover record -> observations (Stage 1B).

The one ``.txt`` evidence file is a shift-handover note::

    CUSTOMER PLATFORM - SHIFT HANDOVER
    Snapshot: 2026-10-01T12:00:00Z
    <prose>
    - <ts> | <system> | <resource_id> | <record_type> | <result> | <subject>

Each bullet row uses the same vocabulary as the flat JSON ledgers, so it goes through the
same builder (``ledger_observation``): ``lookup_result`` kind, the row's own timestamp as
``record_observed_at``, ``Snapshot:`` as ``snapshot_captured_at``. A row whose subject is the
literal ``no direct identifier`` contributes no identifier (and is flagged), rather than being
mislabelled as an unclassified one. Title/prose lines are not records and are only counted; any
other line that contains ``" | "`` is treated as a malformed record, not as prose.
"""
from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Dict, Optional, Union

from .builders import FileContext, ledger_observation, unrecognized_observation
from .manifest import resolve_inside
from .model import (
    EvidenceFileRef,
    Identifiers,
    ParsedFile,
    ParseStatus,
    ScopeKind,
    SnapshotScope,
    SourceFormat,
    TimestampSource,
)

_SNAPSHOT = re.compile(r"^Snapshot:\s*(\S+)\s*$")
ROW_FIELDS = ("recorded_at", "system", "resource_id", "record_type", "result", "subject_reference")
NO_IDENTIFIER_MARKERS = frozenset({"no direct identifier"})


def parse_text_record(ref: EvidenceFileRef, text: str) -> ParsedFile:
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.TEXT, status=ParseStatus.PARSED, layout="text:shift_handover", ref=ref)
    ctx = FileContext(ref, ref.file_path, SourceFormat.TEXT)
    cov = parsed.coverage
    cov.containers_seen = 1
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    snapshot: Optional[str] = None
    title: Optional[str] = None
    prose = blank = 0
    for i, raw in enumerate(lines, start=1):
        m = _SNAPSHOT.match(raw.strip())
        if m:
            snapshot = ctx.check_ts(m.group(1), "Snapshot", "line=%d" % i)
            break
    if snapshot is None:
        ctx.warn("TXT_SNAPSHOT_MISSING", "no valid 'Snapshot: <timestamp>' header; rows keep their own timestamps and no snapshot time is assumed")
    ctx.file_content_time, ctx.file_content_time_field = snapshot, "snapshot" if snapshot else None

    for i, raw in enumerate(lines, start=1):
        loc = "line=%d" % i
        s = raw.strip()
        if not s:
            blank += 1
            continue
        if s.startswith("- ") or " | " in s:
            cov.records_seen += 1
            parts = [p.strip() for p in (s[2:] if s.startswith("- ") else s).split(" | ")]
            if not s.startswith("- ") or len(parts) != len(ROW_FIELDS):
                ctx.warn("TXT_ROW_MALFORMED", "expected '- ' + %d ' | '-separated fields, found %d" % (len(ROW_FIELDS), len(parts)), loc)
                parsed.observations.append(unrecognized_observation(ctx, {"raw_line": raw, "line": i}, locator=loc, reason="txt_row_malformed"))
                cov.records_unrecognized += 1
                continue
            row: Dict[str, str] = dict(zip(ROW_FIELDS, parts))
            marker = row["subject_reference"].lower() in NO_IDENTIFIER_MARKERS
            obs = ledger_observation(ctx, row, locator=loc, store=ref.origin, collection="handover_row", snapshot_captured_at=snapshot)
            if obs is None:
                ctx.warn("LEDGER_ROW_INCOMPLETE", "row has an empty system/resource_id/record_type/result", loc)
                parsed.observations.append(unrecognized_observation(ctx, dict(row, raw_line=raw), locator=loc, reason="ledger_missing_keys"))
                cov.records_unrecognized += 1
                continue
            if marker:
                obs = replace(obs, identifiers=Identifiers(), flags=obs.flags + ("no_direct_identifier_marker",))
            parsed.observations.append(replace(obs, record_timestamp_field="row_timestamp" if obs.record_observed_at else None))
            cov.records_recognized += 1
        else:
            prose += 1
            if title is None and not _SNAPSHOT.match(s):
                title = s
    cov.containers_recognized = 1 if cov.records_recognized else 0
    if cov.records_seen == 0:
        ctx.warn("TXT_NO_ROWS", "no '- ... | ...' record rows found")
        parsed.status = ParseStatus.FAILED
    elif cov.records_unrecognized:
        parsed.status = ParseStatus.PARTIAL
    parsed.scopes.append(SnapshotScope(ScopeKind.TEXT_SNAPSHOT, ref.file_id, None, ref.origin, snapshot,
                                       TimestampSource.SNAPSHOT_CAPTURED if snapshot else TimestampSource.NONE,
                                       cov.records_seen, "file", extra={"title": title}))
    parsed.metadata.update({"title": title, "prose_or_header_lines": prose, "blank_lines": blank})
    parsed.warnings = ctx.warnings
    return parsed.finalize()


def parse_text_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    try:
        text = resolve_inside(dataset_dir, ref.file_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.TEXT, status=ParseStatus.FAILED, ref=ref)
        ctx = FileContext(ref, ref.file_path, SourceFormat.TEXT)
        ctx.warn("FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_text_record(ref, text)
