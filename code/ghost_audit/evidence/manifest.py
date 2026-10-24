"""Load ``evidence_files.csv`` (the only authoritative file_id -> path/capture-time map)."""
from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Union

from .model import EvidenceFileRef, ParseWarning, SourceFormat

MANIFEST_COLUMNS = ("file_id", "file_path", "origin", "captured_at")
_EXT_FORMAT = {
    ".sql": SourceFormat.SQL, ".json": SourceFormat.JSON, ".csv": SourceFormat.CSV,
    ".log": SourceFormat.LOG, ".pdf": SourceFormat.PDF, ".png": SourceFormat.IMAGE,
    ".jpg": SourceFormat.IMAGE, ".jpeg": SourceFormat.IMAGE, ".txt": SourceFormat.TEXT,
}


def format_for_path(path: str) -> SourceFormat:
    return _EXT_FORMAT.get(os.path.splitext(path)[1].lower(), SourceFormat.UNKNOWN)


def default_dataset_dir() -> Path:
    """``<repo root>/dataset`` (this file is code/ghost_audit/evidence/manifest.py)."""
    return Path(__file__).resolve().parents[3] / "dataset"


def _natural(file_id: str) -> Tuple[str, int, str]:
    m = re.fullmatch(r"(\D+)(\d+)", file_id)
    return (m.group(1), int(m.group(2)), file_id) if m else (file_id, 0, file_id)


def load_manifest(dataset_dir: Union[str, Path, None] = None) -> Tuple[List[EvidenceFileRef], List[ParseWarning]]:
    """Return manifest rows (ordered by file_id, naturally) and any manifest warnings.

    The manifest is read-only input. Problems are reported, never fixed:
    duplicate ids/paths, missing columns, listed files that do not exist, and
    files on disk under ``evidence/`` that the manifest does not list.
    """
    root = Path(dataset_dir) if dataset_dir is not None else default_dataset_dir()
    path = root / "evidence_files.csv"
    warnings: List[ParseWarning] = []
    refs: Dict[str, EvidenceFileRef] = {}
    try:
        handle = open(path, "r", encoding="utf-8", newline="")
    except OSError as exc:
        return [], [ParseWarning("MANIFEST_UNREADABLE", "cannot read %s: %s" % (path, exc))]
    with handle:
        reader = csv.DictReader(handle)
        missing = [c for c in MANIFEST_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            return [], [ParseWarning("MANIFEST_COLUMNS", "evidence_files.csv lacks column(s) %s" % ", ".join(missing))]
        seen_paths: Dict[str, str] = {}
        for row in reader:
            fid, fpath = row["file_id"], row["file_path"]
            loc = "row=%d" % reader.line_num
            if fid in refs:
                warnings.append(ParseWarning("MANIFEST_DUPLICATE_FILE_ID", "file_id %s listed twice; keeping the first" % fid, fid, loc))
                continue
            if fpath in seen_paths:
                warnings.append(ParseWarning("MANIFEST_DUPLICATE_PATH", "path %s listed under %s and %s" % (fpath, seen_paths[fpath], fid), fid, loc))
            seen_paths[fpath] = fid
            refs[fid] = EvidenceFileRef(fid, fpath, row["origin"], row["captured_at"], format_for_path(fpath))
            if not (root / fpath).is_file():
                warnings.append(ParseWarning("MANIFEST_FILE_MISSING", "listed path %s does not exist" % fpath, fid, loc))
    evidence_dir = root / "evidence"
    if evidence_dir.is_dir():
        listed = set(seen_paths)
        for dirpath, _dirs, names in os.walk(str(evidence_dir)):
            for name in sorted(names):
                rel = os.path.relpath(os.path.join(dirpath, name), str(root)).replace(os.sep, "/")
                if rel not in listed:
                    warnings.append(ParseWarning("MANIFEST_UNLISTED_FILE", "file %s exists on disk but is not in evidence_files.csv" % rel))
    return sorted(refs.values(), key=lambda r: _natural(r.file_id)), warnings
