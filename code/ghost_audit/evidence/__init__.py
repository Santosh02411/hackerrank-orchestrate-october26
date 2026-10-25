"""Stage 1A/1B/1C: evidence ingestion (SQL, JSON, CSV; logs and the TXT record on opt-in; PDFs and screenshots with OCR on opt-in).

Produces typed, provenance-carrying :class:`Observation` objects. It does not
resolve identities, apply policy, decide deletion state or plan remediation.
By default logs, PDFs, images and the plain-text record are reported as deferred;
pass ``formats=EXTENDED_FORMATS`` to parse logs and the TXT record, or ``formats=FULL_FORMATS`` to also read PDFs and
screenshots (needs pypdf, Pillow and Tesseract; a missing tool is a FAILED file, never a silent skip).
"""
from .ingest import EXTENDED_FORMATS, FULL_FORMATS, HANDLED_FORMATS, IngestionResult, ingest_dataset, parse_evidence_file
from .manifest import default_dataset_dir, load_manifest
from .model import (
    Coverage,
    EffectiveTime,
    EvidenceFileRef,
    IdentifierItem,
    Identifiers,
    Observation,
    ObservationKind,
    ParsedFile,
    ParseStatus,
    ParseWarning,
    Provenance,
    ScopeKind,
    SnapshotScope,
    SourceFormat,
    TimestampSource,
    flag_value,
)

__all__ = [
    "EXTENDED_FORMATS",
    "FULL_FORMATS",
    "HANDLED_FORMATS",
    "IngestionResult",
    "ingest_dataset",
    "parse_evidence_file",
    "default_dataset_dir",
    "load_manifest",
    "Coverage",
    "EffectiveTime",
    "EvidenceFileRef",
    "IdentifierItem",
    "Identifiers",
    "Observation",
    "ObservationKind",
    "ParsedFile",
    "ParseStatus",
    "ParseWarning",
    "Provenance",
    "ScopeKind",
    "SnapshotScope",
    "SourceFormat",
    "TimestampSource",
    "flag_value",
]
