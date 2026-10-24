"""``system_activity.csv`` -> CLAIM observations.

The activity stream is a global log of what systems *reported* (``SUCCESS`` /
``FAILED`` / ``PARTIAL``). The problem statement is explicit that such reports
are claims, so every row becomes an :class:`Observation` of kind ``CLAIM`` with
the reported result kept verbatim in ``state_value`` and flagged
``unverified_claim``. It may be cited as evidence by ``activity_id`` but must
never be read as the verified state of a resource.

Two cautions for later stages:

* ``system_id`` is the row's ``target_system`` verbatim. That is NOT always the
  ``system_id`` used in answers (for example ``audit_record_*`` rows target
  ``archive_service``); the mapping is a policy-stage decision.
* The file is not in time order (the ``LINK_RESOURCE_IDENTITY`` rows are
  appended at the end), so order by ``record_observed_at``, never by position
  or by ``activity_id``.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Dict, Union

from .builders import FileContext, unrecognized_observation
from .identifiers import extract_identifiers
from .model import Observation, ObservationKind, ParsedFile, ParseStatus, Provenance, SourceFormat

ACTIVITY_FILE = "system_activity.csv"
ACTIVITY_COLUMNS = ("activity_id", "event_time", "event_type", "source_system", "target_system",
                    "resource_id", "reported_result", "details")


def parse_activity_text(text: str, source: str = ACTIVITY_FILE) -> ParsedFile:
    parsed = ParsedFile(source=source, source_format=SourceFormat.CSV, status=ParseStatus.PARSED, layout="csv:system_activity")
    ctx = FileContext(None, source, SourceFormat.CSV, citable_id="system_activity")
    cov = parsed.coverage
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=False)
    missing = [c for c in ACTIVITY_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        ctx.warn("CSV_COLUMNS", "missing column(s): %s" % ", ".join(missing))
        parsed.status = ParseStatus.FAILED
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    cov.containers_seen = cov.containers_recognized = 1
    seen_ids: Dict[str, int] = {}
    ordinal = 0
    for row in reader:
        line = reader.line_num
        loc = "row=%d" % line
        cov.records_seen += 1
        if None in row or any(row.get(c) is None for c in ACTIVITY_COLUMNS):
            ctx.warn("CSV_ROW_WIDTH", "row does not have exactly %d fields" % len(ACTIVITY_COLUMNS), loc)
            parsed.observations.append(unrecognized_observation(ctx, {k: v for k, v in row.items() if k is not None}, locator=loc, reason="csv_row_width"))
            cov.records_unrecognized += 1
            continue
        aid = row["activity_id"]
        if aid in seen_ids:
            ctx.warn("ACTIVITY_DUPLICATE_ID", "activity_id %s already seen at %s" % (aid, "row=%d" % seen_ids[aid]), loc)
        seen_ids.setdefault(aid, line)
        event_time = ctx.check_ts(row["event_time"], "event_time", loc)
        if event_time is None:
            ctx.warn("RECORD_TIMESTAMP_MISSING", "activity row has no valid event_time", loc)
        prov = Provenance(citable_id=aid, source_format=SourceFormat.CSV, locator=loc, ordinal=ordinal, file_id=None, file_path=source)
        parsed.observations.append(Observation(
            obs_id=aid, kind=ObservationKind.CLAIM, provenance=prov,
            system_id=row["target_system"] or None, resource_id=row["resource_id"] or None,
            event_type=row["event_type"] or None, state_field="reported_result", state_value=row["reported_result"],
            record_observed_at=event_time, record_timestamp_field="event_time" if event_time else None,
            identifiers=extract_identifiers(row), fields=dict(row), flags=("unverified_claim",)))
        ordinal += 1
        cov.records_recognized += 1
    parsed.warnings = ctx.warnings
    if cov.records_unrecognized:
        parsed.status = ParseStatus.PARTIAL
    return parsed.finalize()


def parse_activity_file(dataset_dir: Union[str, Path]) -> ParsedFile:
    path = Path(dataset_dir) / ACTIVITY_FILE
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parsed = ParsedFile(source=ACTIVITY_FILE, source_format=SourceFormat.CSV, status=ParseStatus.FAILED, layout="csv:system_activity")
        ctx = FileContext(None, ACTIVITY_FILE, SourceFormat.CSV)
        ctx.warn("FILE_UNREADABLE", "cannot read %s: %s" % (ACTIVITY_FILE, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_activity_text(text)
