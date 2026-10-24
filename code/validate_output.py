"""Command-line validator for output.csv.

Usage (from the repository root, Windows PowerShell or any shell):

    python code/validate_output.py output.csv --requests dataset/deletion_requests.csv
    python code/validate_output.py dataset/sample_output.csv --requests dataset/sample_deletion_requests.csv

Exit codes: 0 = no errors, 1 = validation errors, 2 = usage or I/O problem.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost_audit.ordering import SortStrategy  # noqa: E402
from ghost_audit.validator import (  # noqa: E402
    Severity,
    ValidatorConfig,
    validate_csv,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_case_ids(path: Path) -> List[str]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "case_id" not in reader.fieldnames:
            raise ValueError("%s has no 'case_id' column" % path)
        return [row["case_id"] for row in reader]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Validate output.csv against the Ghost Data contract (Stage 0).")
    p.add_argument("path", nargs="?", default=str(REPO_ROOT / "output.csv"),
                   help="CSV to validate (default: <repo root>/output.csv)")
    p.add_argument("--requests", help="request CSV whose case_id column lists the exact cases expected "
                                      "(dataset/deletion_requests.csv for the final file); also sets the expected row count")
    p.add_argument("--expect-rows", type=int, help="expected number of data rows (overrides --requests count)")
    sorts = [s.value for s in SortStrategy]
    p.add_argument("--case-order", choices=sorts, default=SortStrategy.EITHER.value,
                   help="row order by case_id (default: either - the repository does not say lexical or natural)")
    p.add_argument("--resource-order", choices=sorts, default=SortStrategy.EITHER.value,
                   help="order of system_id/resource_id inside a phase/operation (default: either)")
    p.add_argument("--pairing", choices=["off", "warning", "error"], default="warning",
                   help="severity of finding<->remediation pairing diagnostics (implied, not stated, by the contract)")
    p.add_argument("--evidence-id-pattern", default=None,
                   help="regex (full match) for citable IDs, or 'none' to disable; default (evidence|activity|audit)_<digits>")
    p.add_argument("--max-issues", type=int, default=50, help="print at most this many issues (default 50)")
    p.add_argument("--fail-on-warning", action="store_true", help="exit 1 when warnings exist")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    config = ValidatorConfig(
        case_id_order=SortStrategy(args.case_order),
        resource_order=SortStrategy(args.resource_order),
        pairing_severity=None if args.pairing == "off" else Severity(args.pairing.upper()),
    )
    if args.evidence_id_pattern is not None:
        if args.evidence_id_pattern.lower() == "none":
            config.evidence_id_pattern = None
        else:
            try:
                config.evidence_id_pattern = re.compile(args.evidence_id_pattern)
            except re.error as exc:
                print("error: invalid --evidence-id-pattern: %s" % exc, file=sys.stderr)
                return 2
    if args.requests:
        try:
            ids = _read_case_ids(Path(args.requests))
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            print("error: cannot read --requests: %s" % exc, file=sys.stderr)
            return 2
        config.expected_case_ids = set(ids)
        config.expected_row_count = len(ids)
    if args.expect_rows is not None:
        config.expected_row_count = args.expect_rows

    path = Path(args.path)
    report = validate_csv(path, config)

    print("Validating: %s" % path)
    print("Rows: %d | Distinct cases: %d" % (report.row_count, report.case_count))
    chosen = {"case_id": args.case_order, "resource_id": args.resource_order}
    for axis in ("case_id", "resource_id"):
        if axis in report.ordering:
            sat = report.ordering[axis]
            if chosen[axis] == SortStrategy.NONE.value:
                text = "not checked (--%s-order none)" % ("case" if axis == "case_id" else "resource")
            elif not sat:
                text = "NOT satisfied (accepted: %s)" % chosen[axis]
            elif len(sat) == 2:
                text = "lexical and natural both satisfied (this file does not discriminate between them)"
            else:
                text = "%s satisfied" % sat[0]
            print("Ordering (%s): %s" % (axis, text))
    shown = 0
    for issue in sorted(report.issues, key=lambda i: {"ERROR": 0, "WARNING": 1, "INFO": 2}[i.severity.value]):
        if shown >= args.max_issues:
            break
        print(issue)
        shown += 1
    if len(report.issues) > shown:
        print("... %d more issue(s) not shown (use --max-issues)" % (len(report.issues) - shown))
    failed = bool(report.errors) or (args.fail_on_warning and bool(report.warnings))
    print("Result: %s - %s" % ("FAIL" if failed else "PASS", report.summary()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
