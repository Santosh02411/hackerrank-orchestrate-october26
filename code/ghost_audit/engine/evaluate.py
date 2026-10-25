"""Evaluation metrics required by AGENTS.md 6.8: status accuracy, step-level, field-level and sequence accuracy.

Predictions are compared with a reference file in the same format (``sample_output.csv`` is the only reference that
exists in the participant data; the 518 hidden answers are not available, so no accuracy can be computed for them).
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple, Union

STEP_KEY = ("phase", "operation", "system_id", "resource_id")
FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def read_output(path: Union[str, Path]) -> Dict[str, Tuple[str, List[dict]]]:
    with open(path, encoding="utf-8", newline="") as h:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(h)}


def evaluate(pred: Dict[str, Tuple[str, List[dict]]], ref: Dict[str, Tuple[str, List[dict]]]) -> Dict[str, object]:
    cases = sorted(set(ref) & set(pred))
    status_ok = seq_ok = 0
    tp = fp = fn = 0                      # step identity = (phase, operation, system_id, resource_id)
    tp_ev = 0                             # ... and the cited evidence_id is also right
    field_hits = Counter()
    field_total = Counter()
    by_status: Dict[str, List[int]] = {}
    per_case: Dict[str, Dict[str, object]] = {}
    for cid in cases:
        ps, pst = pred[cid]
        rs, rst = ref[cid]
        status_ok += ps == rs
        by_status.setdefault(rs, [0, 0])
        by_status[rs][0] += ps == rs
        by_status[rs][1] += 1
        seq_ok += ps == rs and pst == rst           # strict: the status AND the whole ordered array must match
        pk = {tuple(s[k] for k in STEP_KEY): s for s in pst}
        rk = {tuple(s[k] for k in STEP_KEY): s for s in rst}
        both = set(pk) & set(rk)
        tp += len(both)
        fp += len(set(pk) - set(rk))
        fn += len(set(rk) - set(pk))
        tp_ev += sum(1 for k in both if pk[k]["evidence_id"] == rk[k]["evidence_id"])
        for k in both:
            for f in FIELDS:
                field_total[f] += 1
                field_hits[f] += pk[k][f] == rk[k][f]
        per_case[cid] = {"status_ok": ps == rs, "missing": sorted(set(rk) - set(pk)), "extra": sorted(set(pk) - set(rk)),
                         "wrong_evidence": sorted(k for k in both if pk[k]["evidence_id"] != rk[k]["evidence_id"]), "sequence_ok": ps == rs and pst == rst}
    n = len(cases) or 1
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {
        "cases": len(cases), "status_accuracy": status_ok / n, "status_by_reference": {k: (v[0], v[1]) for k, v in sorted(by_status.items())},
        "sequence_accuracy": seq_ok / n, "step_precision": prec, "step_recall": rec,
        "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0, "steps_matched": tp, "steps_extra": fp, "steps_missing": fn,
        "evidence_accuracy_on_matched": tp_ev / tp if tp else 1.0,
        "field_accuracy_on_matched": {f: field_hits[f] / field_total[f] for f in FIELDS if field_total[f]},
        "per_case": per_case,
    }
