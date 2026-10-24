"""Inspect structured evidence ingestion (Stage 1A): counts, coverage, warnings.

Read-only: it parses SQL/JSON evidence (in-memory SQLite) and system_activity.csv,
prints a report, and never writes to the dataset or produces predictions.

    python code/inspect_evidence.py                       # table for every manifest file
    python code/inspect_evidence.py --format sql          # only SQL files
    python code/inspect_evidence.py --file evidence_05 --dump 5
    python code/inspect_evidence.py --json > coverage.json   # machine-readable
    python code/inspect_evidence.py --strict              # exit 1 on failed/partial files

Exit codes: 0 ok, 1 --strict violation, 2 bad usage / unreadable dataset directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost_audit.evidence import (  # noqa: E402
    IngestionResult,
    ParsedFile,
    ParseStatus,
    SourceFormat,
    default_dataset_dir,
    ingest_dataset,
)


def summarize(parsed: ParsedFile) -> Dict[str, Any]:
    c = parsed.coverage
    return {
        "file_id": parsed.file_id or "-", "path": parsed.source, "format": parsed.source_format.value,
        "layout": parsed.layout or "-", "status": parsed.status.value, "coverage": c.to_dict(),
        "warning_codes": dict(Counter(w.code for w in parsed.warnings)),
    }


def build_report(result: IngestionResult) -> Dict[str, Any]:
    files = [summarize(p) for p in result.all_parsed()]
    parsed = result.all_parsed()
    return {
        "dataset": str(result.dataset_dir),
        "files": files,
        "manifest_warnings": [str(w) for w in result.manifest_warnings],
        "totals": {
            "files": len(parsed),
            "by_status": dict(Counter(p.status.value for p in parsed)),
            "by_format": dict(Counter(p.source_format.value for p in parsed)),
            "observations": sum(p.coverage.observations for p in parsed),
            "scopes": sum(p.coverage.scopes for p in parsed),
            "records_seen": sum(p.coverage.records_seen for p in parsed),
            "records_unrecognized": sum(p.coverage.records_unrecognized for p in parsed),
            "warning_codes": dict(Counter(w.code for p in parsed for w in p.warnings)),
        },
    }


def _row(cells: List[str], widths: List[int]) -> str:
    return "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)).rstrip()


def print_table(result: IngestionResult, show_warnings: int, dump: int) -> None:
    header = ["file_id", "fmt", "layout", "status", "containers", "records", "unrec", "obs", "scopes", "warn"]
    rows = []
    for p in result.all_parsed():
        c = p.coverage
        rows.append([p.file_id or "(activity)", p.source_format.value, p.layout or "-", p.status.value,
                     "%d/%d" % (c.containers_recognized, c.containers_seen), "%d/%d" % (c.records_recognized, c.records_seen),
                     str(c.records_unrecognized), str(c.observations), str(c.scopes), str(c.warnings)])
    widths = [max(len(header[i]), *(len(r[i]) for r in rows)) if rows else len(header[i]) for i in range(len(header))]
    print(_row(header, widths))
    print(_row(["-" * w for w in widths], widths))
    for r in rows:
        print(_row(r, widths))
    rep = build_report(result)["totals"]
    print()
    print("Files: %d | status: %s | format: %s" % (rep["files"], rep["by_status"], rep["by_format"]))
    print("Observations: %d | scopes: %d | records seen: %d | unrecognized: %d" % (rep["observations"], rep["scopes"], rep["records_seen"], rep["records_unrecognized"]))
    print("(containers/records are 'recognized/seen'; DEFERRED files are logs, PDFs, images and the TXT record - later stages)")
    print()
    print("Warning codes: %s" % (rep["warning_codes"] or "none"))
    shown = 0
    for p in result.all_parsed():
        for w in p.warnings:
            if w.code == "FORMAT_DEFERRED" or shown >= show_warnings:
                continue
            print("  %s %s" % (p.file_id or "(activity)", w))
            shown += 1
    for w in result.manifest_warnings:
        print("  manifest %s" % w)
    if dump:
        for p in result.all_parsed():
            for obs in p.observations[:dump]:
                eff = obs.effective_time()
                print("\n[%s] %s %s/%s type=%s state=%s=%r\n  time: effective=%s (%s) record=%s snapshot=%s updated=%s file=%s\n  where: %s %s store=%s role=%s\n  ids: %s" % (
                    obs.obs_id, obs.kind.value, obs.system_id, obs.resource_id, obs.record_type, obs.state_field, obs.state_value,
                    eff.value, eff.source.value, obs.record_observed_at, obs.snapshot_captured_at, obs.record_updated_at, obs.provenance.file_captured_at,
                    obs.provenance.file_path, obs.provenance.locator, obs.store, obs.store_role,
                    [(i.kind, i.value, i.path) for i in obs.identifiers.items] or "none"))


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description="Report Stage 1A structured-evidence ingestion coverage (read-only).")
    ap.add_argument("--dataset", default=str(default_dataset_dir()), help="dataset directory (default: <repo>/dataset)")
    ap.add_argument("--file", action="append", dest="files", metavar="FILE_ID", help="only this file_id (repeatable); skips the activity CSV")
    ap.add_argument("--format", choices=[f.value for f in SourceFormat], help="only files of this format")
    ap.add_argument("--no-activity", action="store_true", help="skip system_activity.csv")
    ap.add_argument("--show-warnings", type=int, default=20, help="print at most N individual warnings (default 20)")
    ap.add_argument("--dump", type=int, default=0, metavar="N", help="also print the first N observations of each file")
    ap.add_argument("--json", action="store_true", help="print the coverage report as JSON")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any parsed file is failed/partial or any record unrecognized")
    args = ap.parse_args(argv)

    root = Path(args.dataset)
    if not (root / "evidence_files.csv").is_file():
        print("error: %s does not contain evidence_files.csv" % root, file=sys.stderr)
        return 2
    result = ingest_dataset(root, include_activity=not args.no_activity, file_ids=args.files)
    if args.format:
        result.files = [p for p in result.files if p.source_format.value == args.format]
        if result.activity is not None and args.format != "csv":
            result.activity = None
    if args.files:
        missing = sorted(set(args.files) - {p.file_id for p in result.files})
        if missing:
            print("error: unknown file_id(s): %s" % ", ".join(missing), file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(build_report(result), indent=2, sort_keys=True))
    else:
        print("Dataset: %s" % root)
        print_table(result, args.show_warnings, args.dump)

    if args.strict:
        bad = [p for p in result.all_parsed() if p.status in (ParseStatus.FAILED, ParseStatus.PARTIAL) or p.coverage.records_unrecognized]
        if bad:
            print("\nSTRICT: %d file(s) failed/partial/unrecognized: %s" % (len(bad), ", ".join(p.file_id or "(activity)" for p in bad)), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
