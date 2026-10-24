"""Shared plumbing for the SQL / JSON / CSV parsers.

``FileContext`` owns everything that is per-file: provenance defaults, the
observation counter (so ``obs_id`` is deterministic), and the warning list.
The ``*_observation`` helpers turn an already-decoded record into an
:class:`Observation`; they are shared so that the same collection record yields
the same observation whether it came from a JSON bundle or a SQL ``record_json``
column.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional, Tuple

from .identifiers import extract_identifiers
from .model import (
    EvidenceFileRef,
    Observation,
    ObservationKind,
    ParseWarning,
    Provenance,
    SourceFormat,
)
from .schema_maps import CollectionSpec
from .timestamps import is_iso_utc, parse_iso_utc

LEDGER_REQUIRED = ("system", "resource_id", "record_type", "result")


class FileContext:
    def __init__(
        self,
        ref: Optional[EvidenceFileRef],
        source: str,
        source_format: SourceFormat,
        *,
        citable_id: Optional[str] = None,
        file_content_time: Optional[str] = None,
        file_content_time_field: Optional[str] = None,
    ) -> None:
        self.ref = ref
        self.source = source
        self.source_format = source_format
        self.citable_id = citable_id or (ref.file_id if ref else source)
        self.file_content_time = file_content_time
        self.file_content_time_field = file_content_time_field
        self.warnings: List[ParseWarning] = []
        self._ordinal = 0

    # ---- warnings -----------------------------------------------------------
    def warn(self, code: str, message: str, locator: Optional[str] = None, level: str = "warning") -> None:
        self.warnings.append(ParseWarning(code, message, self.ref.file_id if self.ref else None, locator, level))

    # ---- timestamps ---------------------------------------------------------
    def check_ts(self, value: Any, field_name: str, locator: str) -> Optional[str]:
        """Return ``value`` if it is a valid timestamp string, else warn and return None."""
        if value is None or value == "":
            return None
        if not is_iso_utc(value) or parse_iso_utc(value) is None:
            self.warn("TIMESTAMP_UNPARSEABLE", "%s=%r is not a YYYY-MM-DDTHH:MM:SSZ timestamp; ignored" % (field_name, value), locator)
            return None
        return str(value)

    def record_time(self, value: Any, field_name: str, locator: str) -> Optional[str]:
        """Validate a record's own observation time and flag it if it post-dates the file's capture."""
        ts = self.check_ts(value, field_name, locator)
        cap = self.ref.captured_at if self.ref else None
        if ts and cap and parse_iso_utc(ts) and parse_iso_utc(cap) and parse_iso_utc(ts) > parse_iso_utc(cap):
            self.warn("RECORD_TIMESTAMP_AFTER_FILE_CAPTURE",
                      "%s=%s is later than the file's manifest captured_at=%s; the record's own time is kept" % (field_name, ts, cap),
                      locator)
        return ts

    def after_file_capture(self, ts: Optional[str]) -> bool:
        cap = self.ref.captured_at if self.ref else None
        a, b = parse_iso_utc(ts), parse_iso_utc(cap)
        return bool(a and b and a > b)

    # ---- provenance / ids ---------------------------------------------------
    def next_provenance(self, locator: str) -> Tuple[str, Provenance]:
        ordinal = self._ordinal
        self._ordinal += 1
        prov = Provenance(
            citable_id=self.citable_id,
            source_format=self.source_format,
            locator=locator,
            ordinal=ordinal,
            file_id=self.ref.file_id if self.ref else None,
            file_path=self.ref.file_path if self.ref else self.source,
            origin=self.ref.origin if self.ref else None,
            file_captured_at=self.ref.captured_at if self.ref else None,
            file_content_time=self.file_content_time,
            file_content_time_field=self.file_content_time_field,
        )
        return "%s:%05d" % (self.citable_id, ordinal), prov


def _str_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value != "" else None


def collection_record_observation(
    ctx: FileContext,
    spec: CollectionSpec,
    payload: Mapping[str, Any],
    *,
    locator: str,
    system_id: Optional[str],
    store: str,
    snapshot_captured_at: Optional[str],
    store_role: Optional[str] = None,
    replica_name: Optional[str] = None,
    record_updated_at: Optional[str] = None,
    record_updated_field: Optional[str] = None,
    flags: Tuple[str, ...] = (),
) -> Observation:
    """Observation for a record of a known collection (non-ledger layouts)."""
    resource_id = _str_or_none(payload.get("resource_id"))
    if resource_id is None:
        ctx.warn("RESOURCE_ID_MISSING", "record has no usable resource_id", locator)
    state_value = payload.get(spec.state_field) if spec.state_field else None
    obs_id, prov = ctx.next_provenance(locator)
    return Observation(
        obs_id=obs_id,
        kind=ObservationKind.RECORD,
        provenance=prov,
        system_id=system_id,
        resource_id=resource_id,
        record_type=spec.record_type,
        record_type_source="derived_from_layout",
        collection=spec.collection,
        store=store,
        store_role=store_role,
        replica_name=replica_name,
        state_field=spec.state_field if spec.state_field and spec.state_field in payload else None,
        state_value=state_value,
        snapshot_captured_at=snapshot_captured_at,
        record_updated_at=record_updated_at,
        record_updated_field=record_updated_field,
        identifiers=extract_identifiers(payload),
        fields=dict(payload),
        flags=flags,
    )


def ledger_observation(
    ctx: FileContext,
    row: Mapping[str, Any],
    *,
    locator: str,
    store: str,
    collection: Optional[str],
    snapshot_captured_at: Optional[str],
    flags: Tuple[str, ...] = (),
) -> Optional[Observation]:
    """Observation for a flat-ledger row / ``operational_record_history`` row.

    Returns ``None`` (after the caller records it as unrecognised) when a
    required key is missing. ``recorded_at`` is optional: without it the
    observation falls back to coarser times, and says so.
    """
    if any(not isinstance(row.get(k), str) or row.get(k) == "" for k in LEDGER_REQUIRED):
        return None
    rec_ts = ctx.record_time(row.get("recorded_at"), "recorded_at", locator) if "recorded_at" in row else None
    if rec_ts is None:
        ctx.warn("RECORD_TIMESTAMP_MISSING", "ledger row has no valid recorded_at; effective time falls back to a coarser level", locator)
    extra: List[str] = list(flags)
    if rec_ts and ctx.after_file_capture(rec_ts):
        extra.append("record_time_after_file_capture")
    obs_id, prov = ctx.next_provenance(locator)
    return Observation(
        obs_id=obs_id,
        kind=ObservationKind.LOOKUP_RESULT,
        provenance=prov,
        system_id=row["system"],
        resource_id=row["resource_id"],
        record_type=row["record_type"],
        record_type_source="source",
        collection=collection,
        store=store,
        state_field="result",
        state_value=row["result"],
        record_observed_at=rec_ts,
        record_timestamp_field="recorded_at" if rec_ts else None,
        snapshot_captured_at=snapshot_captured_at,
        identifiers=extract_identifiers(row),
        fields=dict(row),
        flags=tuple(extra),
    )


def unrecognized_observation(
    ctx: FileContext,
    raw: Any,
    *,
    locator: str,
    reason: str,
    store: Optional[str] = None,
    collection: Optional[str] = None,
    system_id: Optional[str] = None,
    snapshot_captured_at: Optional[str] = None,
    store_role: Optional[str] = None,
    replica_name: Optional[str] = None,
    record_updated_at: Optional[str] = None,
    record_updated_field: Optional[str] = None,
) -> Observation:
    """Keep a record whose layout we did not understand (best-effort ids, raw payload)."""
    obs_id, prov = ctx.next_provenance(locator)
    fields = dict(raw) if isinstance(raw, Mapping) else {"_raw": raw}
    resource_id = _str_or_none(fields.get("resource_id"))
    return Observation(
        obs_id=obs_id,
        kind=ObservationKind.UNRECOGNIZED,
        provenance=prov,
        system_id=system_id,
        resource_id=resource_id,
        collection=collection,
        store=store,
        store_role=store_role,
        replica_name=replica_name,
        snapshot_captured_at=snapshot_captured_at,
        record_updated_at=record_updated_at,
        record_updated_field=record_updated_field,
        identifiers=extract_identifiers(fields),
        fields=fields,
        flags=("unrecognized", reason),
    )
