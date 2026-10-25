"""Build (and optionally serve) the Ghost Audit Evidence Explorer: a read-only, offline, single-file HTML view of the engine's results.

    python code/build_explorer.py                      # writes explorer/ghost-audit-explorer.html and prints the path
    python code/build_explorer.py --serve              # build, then serve it on http://127.0.0.1:8765 (Ctrl+C to stop)
    python code/build_explorer.py --run-tests          # also run the full test suite and record the REAL result in evaluation/test_results.json

It reuses the existing ingestion, linking and decision code and writes nothing but the HTML (and, with --run-tests, the test record).
It never changes output.csv. Open the HTML file by double-clicking it; no server, network or framework is needed.
"""
from __future__ import annotations

import argparse
import csv
import functools
import http.server
import socketserver
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.decide import AuditEngine  # noqa: E402
from ghost_audit.engine.evaluate import read_output  # noqa: E402
from ghost_audit.explorer.data import build_payload  # noqa: E402
from ghost_audit.explorer.render import render_html  # noqa: E402
from ghost_audit.explorer.testrun import run_test_suite, write_test_results  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def read_rows(path: Path):
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dataset", default=str(REPO / "dataset"))
    ap.add_argument("--output", default=str(REPO / "explorer" / "ghost-audit-explorer.html"))
    ap.add_argument("--cache", help="developer cache of the parsed evidence (written if missing); never changes results")
    ap.add_argument("--run-tests", action="store_true", help="run the full test suite first and record the real result in evaluation/test_results.json")
    ap.add_argument("--serve", action="store_true", help="serve the output folder on 127.0.0.1 after building")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)
    dataset, out = Path(args.dataset), Path(args.output)

    if args.run_tests:
        print("running the full test suite (about 2-3 minutes)...")
        result = run_test_suite(REPO)
        print("tests: %s, %d run, %d failures, %d errors, %d skipped" % (result["status"], result["tests_run"], result["failures"], result["errors"], result["skipped"]))
        write_test_results(REPO, result)

    cache = Path(args.cache) if args.cache else None
    if cache and cache.is_file():
        corpus = Corpus.load(dataset, cache=cache)
    else:
        corpus = Corpus.load(dataset)
        if cache:
            corpus.save_cache(cache)
    engine = AuditEngine(dataset, corpus=corpus)
    main_requests = read_rows(dataset / "deletion_requests.csv")
    sample_path = dataset / "sample_deletion_requests.csv"
    sample_requests = read_rows(sample_path) if sample_path.is_file() else []
    reference = read_output(dataset / "sample_output.csv") if (dataset / "sample_output.csv").is_file() else None
    payload = build_payload(engine, main_requests, sample_requests, repo_root=REPO, dataset_dir=dataset, sample_reference=reference)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_html(payload))
    chk = payload["output_check"]
    print("wrote %s (%.1f MB, %d + %d cases)" % (out, out.stat().st_size / 1e6, len(payload["datasets"]["evaluation"]["cases"]), len(payload["datasets"]["samples"]["cases"])))
    if chk.get("present") and chk.get("readable"):
        print("output.csv vs the engine's current decisions: %s" % ("identical" if chk["matches_all"] else "DIFFERENT in %d case(s): %s" % (len(chk["differing"]), ", ".join(chk["differing"][:10]))))
    if args.serve:
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(out.parent))
        with socketserver.TCPServer(("127.0.0.1", args.port), handler) as httpd:
            print("serving http://127.0.0.1:%d/%s  (Ctrl+C to stop)" % (args.port, out.name))
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
