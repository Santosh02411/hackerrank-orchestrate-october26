"""Typed data model for Stage 1A (structured evidence ingestion).

Nothing here interprets evidence. An :class:`Observation` says "this source, at
this location, contained this record / reported this result". Whether that means
a record is deleted, retained or exposed is decided in later stages.

Timestamps are kept at four distinct levels and never merged silently:

=====================  ======================================================
``record_observed_at``  the record's *own* observation/recording/event time
                        (``observed_at``, ``recorded_at``, activity ``event_time``)
``snapshot_captured_at``  capture time of the enclosing snapshot (SQL header or
                        ``snapshot_scope`` row, JSON bundle snapshot, ...)
``provenance.file_content_time``  file-level time stated *inside* the file
                        (``exported_at`` / ``captured_at``)
``provenance.file_captured_at``  ``captured_at`` from ``evidence_files.csv``
=====================  ======================================================

``record_updated_at`` (``updated_at`` / ``indexed_at`` columns) is when the
record was last written, NOT when it was observed, and is never used as an
observation time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Tuple

from .timestamps import parse_iso_utc


class SourceFormat(str, Enum):
    SQL = "sql"
    JSON = "json"
    CSV = "csv"
    LOG = "log"
    PDF = "pdf"
    IMAGE = "image"
    TEXT = "text"
    UNKNOWN = "unknown"


class ObservationKind(str, Enum):
    RECORD = "record"                # a stored row/document present in a snapshot
    LOOKUP_RESULT = "lookup_result"  # explicit result of a lookup/read/query (FOUND, NOT_FOUND, 404, ...)
    CLAIM = "claim"                  # system_activity.csv event: a *claim*, never verified state
    UNRECOGNIZED = "unrecognized"    # kept (with raw fields) but its layout was not understood


class TimestampSource(str, Enum):
    RECORD_OBSERVED = "record_observed"
    EVENT_TIME = "event_time"
    SNAPSHOT_CAPTURED = "snapshot_captured"
    FILE_EXPORTED = "file_exported"
    MANIFEST_CAPTURED = "manifest_captured"
    NONE = "none"


class ParseStatus(str, Enum):
    PARSED = "parsed"      # everything recognised
    PARTIAL = "partial"    # parsed, but some records/containers unrecognised or the script errored part-way
    FAILED = "failed"      # nothing usable could be read
    DEFERRED = "deferred"  # format intentionally not handled in this stage


class ScopeKind(str, Enum):
    SQL_TABLE = "sql_table"
    SQL_ORIGIN_SYSTEM = "sql_origin_system"        # a row of the inventory `snapshot_scope` table
    JSON_SNAPSHOT = "json_snapshot"
    JSON_SERVICE_SECTION = "json_service_section"
    JSON_CONTAINER = "json_container"
    LOG_EXPORT = "log_export"          # one log file: declared vs parsed event counts, window, drops
    TEXT_SNAPSHOT = "text_snapshot"    # the plain-text handover record
    DOCUMENT = "document"              # one PDF or screenshot: extraction diagnostics, row counts


class EffectiveTime(NamedTuple):
    value: Optional[str]
    source: TimestampSource


@dataclass(frozen=True)
class EvidenceFileRef:
    """One row of ``evidence_files.csv`` plus the format implied by its extension."""

    file_id: str
    file_path: str          # relative to the dataset directory, as written in the manifest
    origin: str
    captured_at: str
    source_format: SourceFormat


@dataclass(frozen=True)
class Provenance:
    citable_id: str                      # the value allowed in a step's evidence_id (file_id or activity_id)
    source_format: SourceFormat
    locator: str                         # where inside the source: "table=...;rowid=3", "$.snapshots[2].records[5]", "row=17"
    ordinal: int                         # 0-based position of the observation within its file
    file_id: Optional[str] = None
    file_path: Optional[str] = None
    origin: Optional[str] = None         # manifest `origin`
    file_captured_at: Optional[str] = None       # manifest captured_at
    file_content_time: Optional[str] = None      # time stated inside the file (JSON exported_at/captured_at)
    file_content_time_field: Optional[str] = None


@dataclass(frozen=True)
class IdentifierItem:
    kind: str            # email | email_hash | phone | user_id | resource_ref | name | unclassified
    value: str           # exactly as found (case preserved)
    path: str            # field path inside the record, e.g. "document.email"
    free_text: bool = False  # found by pattern-matching inside a free-text field
    confidence: Optional[float] = None   # OCR word confidence (0-100) when the value was read from an image
    uncertain: bool = False              # OCR value that is low-confidence or not reproduced by an independent pass


@dataclass(frozen=True)
class Identifiers:
    items: Tuple[IdentifierItem, ...] = ()
    redacted_paths: Tuple[str, ...] = ()  # fields holding a redaction marker such as "[REDACTED]"

    def _values(self, kind: str) -> Tuple[str, ...]:
        seen: Dict[str, None] = {}
        for item in self.items:
            if item.kind == kind:
                seen.setdefault(item.value, None)
        return tuple(seen)

    @property
    def emails(self) -> Tuple[str, ...]:
        return self._values("email")

    @property
    def emails_normalized(self) -> Tuple[str, ...]:
        return tuple(dict.fromkeys(e.strip().lower() for e in self.emails))

    @property
    def email_hashes(self) -> Tuple[str, ...]:
        return self._values("email_hash")

    @property
    def phones(self) -> Tuple[str, ...]:
        return self._values("phone")

    @property
    def user_ids(self) -> Tuple[str, ...]:
        return self._values("user_id")

    @property
    def names(self) -> Tuple[str, ...]:
        return self._values("name")

    @property
    def resource_refs(self) -> Tuple[str, ...]:
        return self._values("resource_ref")

    @property
    def unclassified(self) -> Tuple[Tuple[str, str], ...]:
        return tuple((i.path, i.value) for i in self.items if i.kind == "unclassified")

    def is_empty(self) -> bool:
        return not self.items


@dataclass(frozen=True)
class Observation:
    obs_id: str
    kind: ObservationKind
    provenance: Provenance
    system_id: Optional[str] = None
    resource_id: Optional[str] = None
    record_type: Optional[str] = None
    record_type_source: Optional[str] = None     # "source" (written in the record) | "derived_from_layout"
    collection: Optional[str] = None             # JSON collection / service list key / SQL collection_name
    store: Optional[str] = None                  # SQL table, or "<data_store>/<collection>", or "<service>.<list>"
    store_role: Optional[str] = None             # "primary" | "replica" | None
    replica_name: Optional[str] = None           # e.g. "read_replica", "replica_ap_south"
    state_field: Optional[str] = None            # the source's own state/flag field, verbatim name
    state_value: Any = None                      # ... and its verbatim value (1, True, "ACTIVE", 404, "NOT_FOUND")
    event_type: Optional[str] = None             # activity CLAIM rows only
    record_observed_at: Optional[str] = None
    record_timestamp_field: Optional[str] = None
    snapshot_captured_at: Optional[str] = None
    record_updated_at: Optional[str] = None
    record_updated_field: Optional[str] = None
    identifiers: Identifiers = field(default_factory=Identifiers)
    fields: Mapping[str, Any] = field(default_factory=dict)   # original record/payload; treat as read-only
    flags: Tuple[str, ...] = ()

    def effective_time(self) -> EffectiveTime:
        """Best available time for *when this was observed*, with its source labelled.

        Order: record's own time > snapshot capture > time stated in the file >
        manifest capture. A record time is never replaced by a coarser one.
        """
        if self.record_observed_at:
            src = TimestampSource.EVENT_TIME if self.kind is ObservationKind.CLAIM else TimestampSource.RECORD_OBSERVED
            return EffectiveTime(self.record_observed_at, src)
        if self.snapshot_captured_at:
            return EffectiveTime(self.snapshot_captured_at, TimestampSource.SNAPSHOT_CAPTURED)
        if self.provenance.file_content_time:
            return EffectiveTime(self.provenance.file_content_time, TimestampSource.FILE_EXPORTED)
        if self.provenance.file_captured_at:
            return EffectiveTime(self.provenance.file_captured_at, TimestampSource.MANIFEST_CAPTURED)
        return EffectiveTime(None, TimestampSource.NONE)

    def effective_datetime(self):
        return parse_iso_utc(self.effective_time().value)

    def to_dict(self) -> Dict[str, Any]:
        eff = self.effective_time()
        return {
            "obs_id": self.obs_id, "kind": self.kind.value,
            "citable_id": self.provenance.citable_id, "file_id": self.provenance.file_id,
            "file_path": self.provenance.file_path, "source_format": self.provenance.source_format.value,
            "locator": self.provenance.locator, "system_id": self.system_id, "resource_id": self.resource_id,
            "record_type": self.record_type, "record_type_source": self.record_type_source,
            "collection": self.collection, "store": self.store, "store_role": self.store_role,
            "replica_name": self.replica_name, "state_field": self.state_field, "state_value": self.state_value,
            "event_type": self.event_type, "record_observed_at": self.record_observed_at,
            "snapshot_captured_at": self.snapshot_captured_at, "record_updated_at": self.record_updated_at,
            "file_content_time": self.provenance.file_content_time,
            "file_captured_at": self.provenance.file_captured_at,
            "effective_time": eff.value, "effective_time_source": eff.source.value,
            "identifiers": [dict({"kind": i.kind, "value": i.value, "path": i.path, "free_text": i.free_text},
                                 **({"confidence": i.confidence, "uncertain": i.uncertain} if i.confidence is not None or i.uncertain else {}))
                            for i in self.identifiers.items],
            "redacted_paths": list(self.identifiers.redacted_paths),
            "flags": list(self.flags), "fields": dict(self.fields),
        }


@dataclass(frozen=True)
class SnapshotScope:
    """What a source says it covered. Needed later so that 'not present' is only
    read as 'absent' when the source actually covered that system/store."""

    kind: ScopeKind
    file_id: Optional[str]
    system_id: Optional[str]
    store: Optional[str]
    captured_at: Optional[str]
    captured_at_source: TimestampSource
    record_count: Optional[int]
    locator: str
    store_role: Optional[str] = None
    replica_name: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParseWarning:
    code: str
    message: str
    file_id: Optional[str] = None
    locator: Optional[str] = None
    level: str = "warning"   # "warning" | "info"

    def __str__(self) -> str:
        where = " @ %s" % self.locator if self.locator else ""
        return "[%s] %s%s: %s" % (self.level.upper(), self.code, where, self.message)


@dataclass
class Coverage:
    containers_seen: int = 0          # SQL tables, JSON snapshots / service sections / the single ledger
    containers_recognized: int = 0
    records_seen: int = 0             # source-native rows/records (a search query with 2 hits is 1 record)
    records_recognized: int = 0
    records_unrecognized: int = 0
    observations: int = 0
    scopes: int = 0
    warnings: int = 0

    def to_dict(self) -> Dict[str, int]:
        return dict(self.__dict__)


@dataclass
class ParsedFile:
    source: str                                   # path as written in the manifest (or the CSV name)
    source_format: SourceFormat
    status: ParseStatus
    layout: Optional[str] = None
    ref: Optional[EvidenceFileRef] = None
    observations: List[Observation] = field(default_factory=list)
    scopes: List[SnapshotScope] = field(default_factory=list)
    warnings: List[ParseWarning] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def file_id(self) -> Optional[str]:
        return self.ref.file_id if self.ref else None

    def finalize(self) -> "ParsedFile":
        self.coverage.observations = len(self.observations)
        self.coverage.scopes = len(self.scopes)
        self.coverage.warnings = sum(1 for w in self.warnings if w.level == "warning")
        return self


def flag_value(value: Any) -> Optional[bool]:
    """Normalise the boolean-ish values the sources use (SQL 0/1, JSON true/false).

    Returns ``None`` when the value is not a recognisable flag. Provided for
    later stages; the observation itself keeps the verbatim value.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def merge_flags(*groups: Iterable[str]) -> Tuple[str, ...]:
    out: Dict[str, None] = {}
    for group in groups:
        for flag in group:
            out.setdefault(flag, None)
    return tuple(out)
