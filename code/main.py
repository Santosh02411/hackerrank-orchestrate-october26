"""Ghost Data Still Exists - deletion-audit agent. Writes ``output.csv`` at the repository root.

    python code/main.py                       # dataset/ -> output.csv, then validates it
    python code/main.py --diagnostics diag.jsonl

Deterministic and offline (no model or network call). Reading screenshots needs Tesseract + Pillow, PDFs need pypdf
(see code/ghost_audit/evidence/README.md); if a tool is missing the affected files are reported and skipped.
Exit codes: 0 = output written and valid, 1 = written but the validator found errors, 2 = bad usage / unreadable input.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.decide import AuditEngine  # noqa: E402
from ghost_audit.engine.writer import write_output  # noqa: E402
from ghost_audit.ordering import SortStrategy  # noqa: E402
from ghost_audit.validator import ValidatorConfig, validate_csv  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def dependency_status() -> dict:
    """Which optional readers are available? PDFs need pypdf; screenshots need Pillow and the Tesseract program."""
    import importlib.util

    from ghost_audit.evidence.ocr import find_tesseract, pillow_available

    return {"pypdf": importlib.util.find_spec("pypdf") is not None, "Pillow": pillow_available(), "Tesseract": find_tesseract() is not None}


def dependency_message(status: dict) -> str:
    """One line when everything is available; otherwise what is missing, what that breaks and how to fix it."""
    if all(status.values()):
        return "dependencies: pypdf, Pillow and Tesseract found"
    missing = [k for k, v in status.items() if not v]
    return ("DEPENDENCIES MISSING: %s. The PDFs/screenshots they read are skipped, so some cases have nothing provable and are written as empty "
            "INCOMPLETE rows that FAIL validation (they are never guessed). Fix: `pip install -r requirements.txt` and install Tesseract 5.x "
            "(Windows: https://github.com/UB-Mannheim/tesseract/wiki then add it to PATH or set TESSERACT_CMD; Linux: apt install tesseract-ocr; "
            "macOS: brew install tesseract)." % ", ".join(missing))


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dataset", default=str(REPO / "dataset"))
    ap.add_argument("--requests", help="request CSV (default: <dataset>/deletion_requests.csv)")
    ap.add_argument("--output", default=str(REPO / "output.csv"))
    ap.add_argument("--case-order", choices=["lexical", "natural"], default="natural", help="row order by case_id; natural = numeric, the order of dataset/deletion_requests.csv (default)")
    ap.add_argument("--resource-order", choices=["lexical", "natural"], default="lexical", help="order of system_id/resource_id inside a phase/operation")
    ap.add_argument("--cache", help="developer cache of the parsed evidence (written if missing); never changes results")
    ap.add_argument("--diagnostics", help="write one JSON line per case (identity, links, assessments, notes) for review")
    args = ap.parse_args(argv)

    status = dependency_status()
    print(dependency_message(status), file=sys.stdout if all(status.values()) else sys.stderr)
    dataset = Path(args.dataset)
    req_path = Path(args.requests) if args.requests else dataset / "deletion_requests.csv"
    try:
        with open(req_path, encoding="utf-8", newline="") as h:
            requests = list(csv.DictReader(h))
    except OSError as exc:
        print("error: cannot read requests: %s" % exc, file=sys.stderr)
        return 2
    cache = Path(args.cache) if args.cache else None
    if cache and cache.is_file():
        corpus = Corpus.load(dataset, cache=cache)
    else:
        corpus = Corpus.load(dataset)
        if cache:
            corpus.save_cache(cache)
    failed = sorted(k for k, v in getattr(corpus, "parse_status", {}).items() if v in ("failed", "partial"))
    if failed:
        print("warning: evidence files not fully read (missing pypdf/Tesseract/Pillow?): %s" % ", ".join(failed), file=sys.stderr)

    engine = AuditEngine(dataset, corpus=corpus, strategy=SortStrategy(args.resource_order))
    decisions = [engine.decide(r) for r in requests]
    n = write_output(decisions, args.output, SortStrategy(args.case_order))
    print("wrote %d rows to %s" % (n, args.output))
    print("status counts: %s" % dict(sorted(Counter(d.status for d in decisions).items())))

    if args.diagnostics:
        with open(args.diagnostics, "w", encoding="utf-8", newline="\n") as h:
            for d in decisions:
                h.write(json.dumps({
                    "case_id": d.case_id, "status": d.status, "applicable": d.applicability.authorized if d.applicability else None,
                    "user_id": d.resolution.user_id if d.resolution else None, "identity_via": d.resolution.via if d.resolution else None,
                    "resources": {rid: {"methods": sorted(lr.methods), "conflict": lr.conflict, "observations": len(lr.observations)}
                                  for rid, lr in (d.view.resources.items() if d.view else [])},
                    "assessments": [{"resource_id": a.resource_id, "system_id": a.system_id, "category": a.category, "verdict": a.verdict,
                                     "cite": a.cite, "reason": a.reason, "weak_link": a.weak} for a in d.assessments],
                    "notes": d.notes}, sort_keys=True) + "\n")
    ids = {r["case_id"] for r in requests}
    report = validate_csv(args.output, ValidatorConfig(case_id_order=SortStrategy(args.case_order), resource_order=SortStrategy(args.resource_order),
                                                       expected_case_ids=ids, expected_row_count=len(requests)))
    print("validator: %s (%s)" % ("PASS" if report.ok else "FAIL", report.summary()))
    for issue in report.errors[:10]:
        print("  %s" % issue)
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
