"""Dispatch evidence files to the right parser and aggregate the results.

Formats outside Stage 1A (logs, PDF, images, the plain-text handover record) are
NOT silently skipped: each appears in the result as a ``DEFERRED`` file with an
informational warning, so coverage reports always account for all 94 files.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Union

from .csv_ingest import parse_activity_file
from .json_ingest import parse_json_file
from .manifest import default_dataset_dir, load_manifest
from .model import (
    EvidenceFileRef,
    Observation,
    ObservationKind,
    ParsedFile,
    ParseStatus,
    ParseWarning,
    SnapshotScope,
    SourceFormat,
)
from .sql_ingest import parse_sql_file

HANDLED_FORMATS = (SourceFormat.SQL, SourceFormat.JSON)
_STAGE_FOR_FORMAT = {SourceFormat.LOG: "log parsing", SourceFormat.PDF: "PDF/OCR", SourceFormat.IMAGE: "image/OCR",
                     SourceFormat.TEXT: "plain-text record parsing", SourceFormat.UNKNOWN: "an unknown format handler"}


def parse_evidence_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    if ref.source_format is SourceFormat.SQL:
        return parse_sql_file(ref, dataset_dir)
    if ref.source_format is SourceFormat.JSON:
        return parse_json_file(ref, dataset_dir)
    parsed = ParsedFile(source=ref.file_path, source_format=ref.source_format, status=ParseStatus.DEFERRED, layout="deferred", ref=ref)
    parsed.warnings.append(ParseWarning(
        "FORMAT_DEFERRED", "%s evidence is not handled in Stage 1A (needs %s); no observations produced" % (ref.source_format.value, _STAGE_FOR_FORMAT.get(ref.source_format, "a later stage")),
        ref.file_id, None, "info"))
    return parsed.finalize()


@dataclass
class IngestionResult:
    dataset_dir: Path
    files: List[ParsedFile] = field(default_factory=list)          # evidence files, ordered by file_id
    activity: Optional[ParsedFile] = None                          # system_activity.csv (claims)
    manifest_warnings: List[ParseWarning] = field(default_factory=list)

    def all_parsed(self) -> List[ParsedFile]:
        return self.files + ([self.activity] if self.activity else [])

    def iter_observations(self, kinds: Optional[Iterable[ObservationKind]] = None) -> Iterator[Observation]:
        wanted = set(kinds) if kinds is not None else None
        for parsed in self.all_parsed():
            for obs in parsed.observations:
                if wanted is None or obs.kind in wanted:
                    yield obs

    def iter_scopes(self) -> Iterator[SnapshotScope]:
        for parsed in self.files:
            for scope in parsed.scopes:
                yield scope

    def file(self, file_id: str) -> Optional[ParsedFile]:
        return next((p for p in self.files if p.file_id == file_id), None)


def ingest_dataset(
    dataset_dir: Union[str, Path, None] = None,
    *,
    include_activity: bool = True,
    file_ids: Optional[Sequence[str]] = None,
) -> IngestionResult:
    """Parse every manifest file (and the activity CSV). Read-only and deterministic."""
    root = Path(dataset_dir) if dataset_dir is not None else default_dataset_dir()
    refs, manifest_warnings = load_manifest(root)
    result = IngestionResult(dataset_dir=root, manifest_warnings=manifest_warnings)
    wanted = set(file_ids) if file_ids else None
    for ref in refs:
        if wanted is not None and ref.file_id not in wanted:
            continue
        result.files.append(parse_evidence_file(ref, root))
    if include_activity and wanted is None:
        result.activity = parse_activity_file(root)
    return result
