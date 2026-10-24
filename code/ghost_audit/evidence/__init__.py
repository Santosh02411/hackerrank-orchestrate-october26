"""Stage 1A: structured evidence ingestion (SQL, JSON, CSV).

Produces typed, provenance-carrying :class:`Observation` objects. It does not
resolve identities, apply policy, decide deletion state or plan remediation.
Logs, PDFs, images and the plain-text record are reported as deferred.
"""
from .ingest import IngestionResult, ingest_dataset, parse_evidence_file
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
