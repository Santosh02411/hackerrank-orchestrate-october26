"""Tests for the evaluation module: metric arithmetic, the participant-created cases and the generated reports."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
for p in (CODE_DIR, CODE_DIR / "evaluation"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import custom_cases  # noqa: E402
from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.evaluate import evaluate  # noqa: E402
from ghost_audit.evidence.ocr import find_tesseract  # noqa: E402

DATASET = REPO_ROOT / "dataset"
HAVE_FULL = (DATASET / "deletion_requests.csv").exists() and all(importlib.util.find_spec(m) for m in ("pypdf", "PIL")) and find_tesseract() is not None


def step(n, phase, op, system, rid, ev=""):
    states = {"VERIFY_RECORD_ABSENT": "ABSENT", "REPORT_REMAINING_RECORD": "PRESENT", "DELETE_RECORD": "ABSENT"}
    return {"step_no": n, "phase": phase, "system_id": system, "resource_id": rid, "operation": op, "state": states[op], "evidence_id": ev}


class TestMetrics(unittest.TestCase):
    REF = {"c1": ("INCOMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_1", "evidence_1"),
                                 step(2, "REMEDIATION", "DELETE_RECORD", "search_service", "search_1"),
                                 step(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "search_service", "search_1")]),
           "c2": ("NOT_APPLICABLE", [])}

    def test_perfect_prediction(self):
        m = evaluate(self.REF, self.REF)
        self.assertEqual((m["status_accuracy"], m["sequence_accuracy"], m["step_precision"], m["step_recall"], m["evidence_accuracy_on_matched"]), (1.0, 1.0, 1.0, 1.0, 1.0))

    def test_missing_extra_wrong_evidence_and_wrong_status_are_counted_separately(self):
        pred = {"c1": ("INCOMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_1", "evidence_9"),
                                      step(2, "FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_2", "evidence_1"),
                                      step(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "search_service", "search_1")]),
                "c2": ("COMPLETE", [])}
        m = evaluate(pred, self.REF)
        self.assertEqual(m["status_accuracy"], 0.5)
        self.assertEqual((m["steps_matched"], m["steps_extra"], m["steps_missing"]), (2, 1, 1))          # delete step missing, search_2 extra
        self.assertAlmostEqual(m["step_precision"], 2 / 3)
        self.assertAlmostEqual(m["step_recall"], 2 / 3)
        self.assertEqual(m["evidence_accuracy_on_matched"], 0.5)                                          # one of two matched cites the wrong file
        self.assertEqual(m["sequence_accuracy"], 0.0)
        self.assertEqual(m["per_case"]["c1"]["wrong_evidence"], [("FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_1")])

    def test_only_cases_present_in_both_are_scored(self):
        m = evaluate({"c1": self.REF["c1"], "zzz": ("COMPLETE", [])}, self.REF)
        self.assertEqual(m["cases"], 1)


def _load_eval_main():
    spec = importlib.util.spec_from_file_location("ghost_evaluation_main_unit", CODE_DIR / "evaluation" / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestIntegrityAudit(unittest.TestCase):
    """contested_resources() reports a record cited for two DIFFERENT people; it must never change a decision."""

    @staticmethod
    def decision(case_id, user, rid, methods):
        from types import SimpleNamespace as NS
        return NS(case_id=case_id, steps=[{"resource_id": rid}], resolution=NS(user_id=user), view=NS(resources={rid: NS(methods=set(methods))}))

    def test_two_different_people_sharing_a_record_are_reported_with_how_each_was_linked(self):
        ev = _load_eval_main()
        found = ev.contested_resources([self.decision("case_1", "user_1", "analytics_9", ["claim_window"]),
                                        self.decision("case_2", "user_2", "analytics_9", ["claim_window"]),
                                        self.decision("case_3", "user_3", "analytics_8", ["claim_window"])])
        self.assertEqual(list(found), ["analytics_9"])
        self.assertEqual(found["analytics_9"], [("case_1", "user_1", "claim_window"), ("case_2", "user_2", "claim_window")])

    def test_the_same_person_audited_twice_is_not_a_conflict_and_unresolved_cases_are_ignored(self):
        from types import SimpleNamespace as NS
        ev = _load_eval_main()
        again = [self.decision("case_1", "user_1", "export_5", ["identifier"]), self.decision("case_9", "user_1", "export_5", ["identifier"])]
        self.assertEqual(ev.contested_resources(again), {})
        unresolved = NS(case_id="case_7", steps=[{"resource_id": "export_5"}], resolution=None, view=None)
        self.assertEqual(ev.contested_resources(again + [unresolved]), {})


class TestCustomCases(unittest.TestCase):
    def test_at_least_three_distinct_cases_covering_every_status(self):
        cs = custom_cases.cases()
        self.assertGreaterEqual(len(cs), 3)
        self.assertEqual(len({c.name for c in cs}), len(cs))
        self.assertEqual({c.expected_status for c in cs}, {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})

    def test_every_custom_case_passes(self):
        for r in custom_cases.run_custom_cases():
            self.assertTrue(r["ok"], "%s\n expected %s\n got      %s" % (r["name"], r["expected_steps"], r["steps"]))


@unittest.skipUnless(HAVE_FULL and not os.environ.get("GHOST_FAST_TESTS"), "needs dataset + pypdf/Pillow/Tesseract (GHOST_FAST_TESTS=1 skips)")
class TestReports(unittest.TestCase):
    def test_reports_are_generated_from_a_real_run_and_state_their_limits(self):
        spec = importlib.util.spec_from_file_location("ghost_evaluation_main", CODE_DIR / "evaluation" / "main.py")
        ev = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ev)
        r = ev.build(DATASET, None, corpus=Corpus.load_shared(DATASET))
        text = ev.evaluation_report(r)
        for needle in ("development set", "no accuracy is claimed", "Sequence accuracy", "Additional evaluation cases", "Failures found and improvements made", "32/32",
                       "integrity audit", "Weak links can be shared"):
            self.assertIn(needle, text)
        self.assertEqual(r["n_main"], 518)
        self.assertTrue(r["validator"].ok)
        usage = ev.usage_report()
        self.assertIn("Model calls | 0", usage)
        for forbidden in ("sk-", "API_KEY=", "Bearer "):
            self.assertNotIn(forbidden, text + usage)
        self.assertTrue(text.startswith("# Evaluation report"))
        with tempfile.TemporaryDirectory() as tmp:                      # same writer calls main() makes, without a second OCR pass
            with open(Path(tmp) / "evaluation_report.md", "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            with open(Path(tmp) / "evaluation_report.md", encoding="utf-8", newline="") as handle:
                raw = handle.read()
            self.assertIn("## 4.", raw)
            self.assertNotIn("\r", raw)


if __name__ == "__main__":
    unittest.main()
