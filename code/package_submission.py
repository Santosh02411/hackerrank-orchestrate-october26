"""Build and verify ``code.zip`` exactly as the challenge README/AGENTS.md describe (works on Windows, macOS and Linux).

    python code/package_submission.py                 # writes <repo root>/code.zip and verifies it
    python code/package_submission.py --check-only    # verify an existing code.zip without rebuilding

What goes in: ``README.md``, ``requirements.txt``, everything under ``code/`` and ``evaluation/`` (the reports are
required at ``evaluation/`` by AGENTS.md section 6.8 and at ``code/evaluation/`` by README.md, so both exist).
What never goes in: ``dataset/``, ``.git``, virtual environments, dependency or bytecode caches, nested archives,
``.env`` files, ``output.csv`` and ``log.txt`` (those two are uploaded separately), and debug images.

The verification step FAILS (exit 1) if a required file or report section is missing, if an archive contains a nested
archive / dataset / cache / environment file, or if a text file looks like it holds a credential.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterable, List, Sequence

REPO = Path(__file__).resolve().parent.parent
INCLUDE_ROOT_FILES = ("README.md", "requirements.txt")
INCLUDE_DIRS = ("code", "evaluation")
EXCLUDED_DIRS = {"__pycache__", ".git", ".venv", "venv", "env", "node_modules", ".pytest_cache", ".mypy_cache", "dataset"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2", ".xz")
EXCLUDED_SUFFIXES = (".pyc", ".pyo") + ARCHIVE_SUFFIXES
EXCLUDED_NAMES = {".DS_Store", ".env", "output.csv", "log.txt", "diagnostics.jsonl", "ghost-audit-explorer.html"}

REQUIRED_FILES = (
    "README.md", "code/main.py", "code/evaluation/main.py",
    "code/evaluation/evaluation_report.md", "code/evaluation/usage_report.md",
    "evaluation/evaluation_report.md", "evaluation/usage_report.md",
)
# AGENTS.md 6.8: what the two reports must contain (a case-insensitive phrase per requirement)
EVALUATION_REPORT_MUST_MENTION = (
    "case-level", "step-level", "field-level", "sequence accuracy", "additional evaluation cases", "failures found and improvements made",
)
USAGE_REPORT_MUST_MENTION = (
    "model providers", "model names", "model calls", "input tokens", "output tokens", "total tokens", "estimated cost",
)
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']"),
)
# a filled-in explorer page contains this JSON key; the unfilled template (code/ghost_audit/explorer/template.html) does not
EXPLORER_DATA_MARKER = '"datasets":{'
TEXT_SUFFIXES = (".py", ".md", ".txt", ".cfg", ".toml", ".ini", ".yml", ".yaml", ".json", ".sh", ".ps1", ".csv")


def _excluded(rel: Path) -> bool:
    parts = rel.parts
    return (any(p in EXCLUDED_DIRS for p in parts[:-1]) or parts[-1] in EXCLUDED_NAMES or parts[-1].lower().endswith(EXCLUDED_SUFFIXES)
            or parts[-1].startswith("ocr_debug"))


def collect_files(root: Path) -> List[Path]:
    """Repo-relative paths that belong in code.zip, in a deterministic order."""
    out: List[Path] = []
    for name in INCLUDE_ROOT_FILES:
        if (root / name).is_file():
            out.append(Path(name))
    for d in INCLUDE_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(str(base)):
            dirnames[:] = sorted(x for x in dirnames if x not in EXCLUDED_DIRS)
            for fn in sorted(filenames):
                rel = (Path(dirpath) / fn).relative_to(root)
                if not _excluded(rel):
                    out.append(rel)
    return out


def build(root: Path, output: Path) -> List[str]:
    files = collect_files(root)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(str(output), "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            zf.write(str(root / rel), rel.as_posix())              # forward slashes on every platform
    return [r.as_posix() for r in files]


def _text(zf: zipfile.ZipFile, name: str) -> str:
    return zf.read(name).decode("utf-8", errors="replace")


def verify(archive: Path, required: Sequence[str] = REQUIRED_FILES) -> List[str]:
    """Return a list of problems (empty = the archive satisfies the official packaging rules)."""
    problems: List[str] = []
    if not archive.is_file():
        return ["%s does not exist" % archive]
    with zipfile.ZipFile(str(archive)) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        have = set(names)
        for req in required:
            if req not in have:
                problems.append("missing required file: %s" % req)
        for n in names:
            parts = n.split("/")
            base = parts[-1]
            if n.lower().endswith(ARCHIVE_SUFFIXES):
                problems.append("nested archive (submissions with nested archives are rejected): %s" % n)
            if parts[0] == "dataset":
                problems.append("dataset must not be bundled: %s" % n)
            if any(p in EXCLUDED_DIRS - {"dataset"} for p in parts[:-1]) or base.lower().endswith((".pyc", ".pyo")):
                problems.append("cache / environment / VCS file: %s" % n)
            if base == ".env" or base.startswith(".env."):
                problems.append("environment file with possible credentials: %s" % n)
            if base in ("output.csv", "log.txt"):
                problems.append("%s is a separate submission item and does not belong in code.zip: %s" % (base, n))
            if n.lower().endswith(".html") and EXPLORER_DATA_MARKER in _text(zf, n):
                problems.append("a BUILT explorer page embeds dataset-derived records and must not be bundled (the template is fine): %s" % n)
            if n.lower().endswith(TEXT_SUFFIXES):
                body = _text(zf, n)
                for pat in SECRET_PATTERNS:
                    m = pat.search(body)
                    if m:
                        problems.append("possible credential in %s: %r" % (n, m.group(0)[:24] + "..."))
        for report, phrases in (("evaluation_report.md", EVALUATION_REPORT_MUST_MENTION), ("usage_report.md", USAGE_REPORT_MUST_MENTION)):
            for prefix in ("evaluation/", "code/evaluation/"):
                name = prefix + report
                if name in have:
                    low = _text(zf, name).lower()
                    problems += ["%s does not mention %r (required by AGENTS.md 6.8)" % (name, p) for p in phrases if p not in low]
        if "evaluation/evaluation_report.md" in have and "code/evaluation/evaluation_report.md" in have:
            if zf.read("evaluation/evaluation_report.md") != zf.read("code/evaluation/evaluation_report.md"):
                problems.append("the two copies of evaluation_report.md differ; rerun `python code/evaluation/main.py`")
    return problems


def main(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(REPO), help="repository root (default: the folder that contains code/)")
    ap.add_argument("--output", help="archive path (default: <root>/code.zip)")
    ap.add_argument("--check-only", action="store_true", help="only verify an existing archive")
    args = ap.parse_args(list(argv) if argv is not None else None)
    root = Path(args.root).resolve()
    out = Path(args.output).resolve() if args.output else root / "code.zip"
    if not args.check_only:
        names = build(root, out)
        print("wrote %s (%d files, %d bytes)" % (out, len(names), out.stat().st_size))
    problems = verify(out)
    for p in problems:
        print("PROBLEM: %s" % p)
    print("code.zip verification: %s" % ("PASS" if not problems else "FAIL (%d problem(s))" % len(problems)))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
