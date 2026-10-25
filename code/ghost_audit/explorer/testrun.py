"""Run the real test suite and record what happened (the explorer shows this file; it never invents a result)."""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def parse_unittest_output(text: str) -> Dict[str, Any]:
    """Counts from unittest's own summary lines. Raises ValueError if the output has no summary (then nothing is recorded)."""
    ran = re.search(r"^Ran (\d+) tests? in ([\d.]+)s", text, re.M)
    if not ran:
        raise ValueError("no unittest summary found in the output")
    ok = re.search(r"^OK(?: \((.*)\))?\s*$", text, re.M)
    failed = re.search(r"^FAILED \((.*)\)\s*$", text, re.M)
    extra = {}
    for part in ((ok.group(1) if ok and ok.group(1) else "") or (failed.group(1) if failed else "")).split(","):
        m = re.match(r"\s*(\w+)=(\d+)", part)
        if m:
            extra[m.group(1)] = int(m.group(2))
    if not ok and not failed:
        raise ValueError("unittest finished without an OK/FAILED verdict")
    return {"tests_run": int(ran.group(1)), "status": "OK" if ok else "FAILED", "duration_s": float(ran.group(2)),
            "failures": extra.get("failures", 0), "errors": extra.get("errors", 0), "skipped": extra.get("skipped", 0)}


def run_test_suite(repo_root: Path) -> Dict[str, Any]:
    cmd = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "code/tests", "-t", "code"]
    started = time.time()
    proc = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    result = parse_unittest_output(proc.stderr + "\n" + proc.stdout)
    result.update({"command": "python -m unittest discover -s code/tests -t code", "python": platform.python_version(), "platform": platform.system(),
                   "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "wall_clock_s": round(time.time() - started, 1),
                   "exit_code": proc.returncode})
    return result


def write_test_results(repo_root: Path, result: Dict[str, Any]) -> Path:
    path = repo_root / "evaluation" / "test_results.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as h:
        h.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path
