"""Serialise decisions to ``output.csv`` exactly as the contract requires (header, one row per case, sorted, valid JSON)."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Union

from ..contracts import CSV_COLUMNS, STEP_KEYS
from ..ordering import SortStrategy, sort_key
from .decide import CaseDecision


def steps_json(steps: List[Dict[str, object]]) -> str:
    """Compact JSON array; every step has exactly the seven contract keys, in contract order."""
    return json.dumps([{k: s[k] for k in STEP_KEYS} for s in steps], separators=(",", ":"), ensure_ascii=True)


def write_output(decisions: Iterable[CaseDecision], path: Union[str, Path], case_order: SortStrategy = SortStrategy.NATURAL) -> int:
    """Rows are in numeric case order (case_2 before case_10) by default: that is the order of dataset/deletion_requests.csv."""
    strat = case_order if case_order in (SortStrategy.LEXICAL, SortStrategy.NATURAL) else SortStrategy.NATURAL
    rows = sorted(decisions, key=lambda d: sort_key(strat, d.case_id))
    with open(path, "w", encoding="utf-8", newline="") as h:          # UTF-8 without BOM, LF line endings
        w = csv.writer(h, lineterminator="\n")
        w.writerow(CSV_COLUMNS)
        for d in rows:
            w.writerow([d.case_id, d.status, steps_json(d.steps)])
    return len(rows)
