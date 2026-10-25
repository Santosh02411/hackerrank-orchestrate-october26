"""Tests for the Ghost Audit Evidence Explorer (code/ghost_audit/explorer, code/build_explorer.py).

The explorer is READ-ONLY: these tests pin that (1) it shows exactly what the engine decided, (2) evidence is classified by the same time
rule the engine uses, (3) ambiguous / missing / excluded evidence is reported rather than hidden, (4) the HTML is offline and injection-safe,
and (5) building it never changes a prediction or output.csv.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET = REPO_ROOT / "dataset"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.decide import AuditEngine  # noqa: E402
from ghost_audit.engine.writer import write_output  # noqa: E402
from ghost_audit.evidence.model import ObservationKind, SourceFormat  # noqa: E402
from ghost_audit.explorer import data as X  # noqa: E402
from ghost_audit.explorer import render as R  # noqa: E402
from ghost_audit.explorer import testrun as T  # noqa: E402
from tests.test_decision_engine import AUD_AT, E, REQ_AT, U, case, claim, make_engine, ob  # noqa: E402

HAVE_DATASET = (DATASET / "deletion_requests.csv").exists() and (DATASET / "evidence").is_dir()
HAVE_TOOLS = all(importlib.util.find_spec(m) is not None for m in ("pypdf", "PIL")) and __import__("ghost_audit.evidence.ocr", fromlist=["x"]).find_tesseract() is not None
needs_full = unittest.skipUnless(HAVE_DATASET and HAVE_TOOLS and not os.environ.get("GHOST_FAST_TESTS"),
                                 "dataset/ and pypdf+Pillow+Tesseract are required to parse every evidence format (GHOST_FAST_TESTS=1 skips)")
HAVE_BROWSER = importlib.util.find_spec("playwright") is not None


def rich_world():
    """One person (user_1, request via the OLD address) with every kind of record the explorer must describe."""
    mine = E("old.ana@example.com")
    return [
        ob("evidence_1", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[mine]),                                       # used
        ob("evidence_9", "search_7", cap="2026-09-12T00:00:00Z", at="2026-09-12T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[mine]),   # after audit_at
        ob("evidence_8", "search_7", cap="2026-08-01T00:00:00Z", at="2026-08-01T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[mine]),   # before request
        ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("old.ana@example.com", "trace_context.lookup_key")]),
        ob("evidence_1", "data_flow_3", sf="enabled", sv=True, ids=[U("user_1")]),
        ob("evidence_1", "backup_4", sf="restore_allowed", sv=1, ids=[E("ana.silva@example.com", "customer_email")]),
        ob("evidence_1", "audit_record_5", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1")], fields={"retention_until": "2033-01-01T00:00:00Z"}),
        ob("evidence_1", "tombstone_6", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1"), E("ana.silva@example.com", "email")]),
        ob("evidence_3", "account_9", sf="http_status", sv="404"),                                                                         # a second, identifier-less observation of a linked record
        ob("evidence_1", "support_9", kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, ids=[U("user_1", "customer_reference")], fields={"requester_email": None}),  # linked, compliant, not cited
        claim("activity_1", "ANONYMIZE_RECORD", "analytics_11", "2026-09-02T00:30:00Z", "analytics_platform"),                              # two candidates -> ambiguous
        claim("activity_2", "ANONYMIZE_RECORD", "analytics_12", "2026-09-02T01:00:00Z", "analytics_platform"),
    ]


def decide_rich(email="old.ana@example.com"):
    eng = make_engine(rich_world())
    c = case(email=email)
    d = eng.decide(c)
    return eng, c, d, X.case_json(eng, d, c, {})


# ================================================================================================= eligibility
class TestEvidenceTimeFiltering(unittest.TestCase):
    def test_classification_agrees_with_the_engines_own_eligibility_rule_at_every_boundary(self):
        stamps = ["2026-07-31T23:59:59Z", REQ_AT, "2026-09-05T00:00:00Z", AUD_AT, "2026-09-10T00:00:01Z"]
        for cap in stamps:
            for at in stamps + [None]:
                o = ob("evidence_1", "r", cap=cap, at=at)
                got = X.classify_eligibility(o, REQ_AT, AUD_AT)
                self.assertEqual(got == "eligible", Corpus.eligible(o, AUD_AT, REQ_AT), (cap, at, got))

    def test_the_cutoff_is_inclusive_and_the_three_states_are_distinguished(self):
        self.assertEqual(X.classify_eligibility(ob("e", "r", cap=AUD_AT, at=AUD_AT), REQ_AT, AUD_AT), "eligible")
        self.assertEqual(X.classify_eligibility(ob("e", "r", cap="2026-09-10T00:00:01Z", at=None), REQ_AT, AUD_AT), "after_audit")
        self.assertEqual(X.classify_eligibility(ob("e", "r", cap="2026-09-09T00:00:00Z", at="2026-09-10T00:00:01Z"), REQ_AT, AUD_AT), "after_audit")
        self.assertEqual(X.classify_eligibility(ob("e", "r", cap="2026-08-01T00:00:00Z", at="2026-08-01T00:00:00Z"), REQ_AT, AUD_AT), "before_request")

    def test_case_payload_marks_late_and_early_evidence_instead_of_dropping_it(self):
        _eng, _c, d, p = decide_rich()
        search = next(r for r in p["resources"] if r["id"] == "search_7")
        self.assertEqual(sorted(o["eligibility"] for o in search["observations"]), ["after_audit", "before_request", "eligible"])
        self.assertEqual((p["counts"]["eligible"] > 0, p["counts"]["after_audit"], p["counts"]["before_request"]), (True, 1, 1))
        self.assertIn("after_cutoff", p["flags"])
        # the decision rests only on the eligible observation
        self.assertEqual(next(s for s in p["steps"] if s["resource_id"] == "search_7" and s["phase"] == "FINDING")["evidence_id"], "evidence_1")

    def test_workflow_claims_after_the_cutoff_are_flagged_as_ignored(self):
        w = rich_world() + [claim("activity_9", "DELETE_RECORD", "search_7", "2026-09-11T00:00:00Z", "search_service")]
        eng = make_engine(w)
        c = case(email="old.ana@example.com")
        p = X.case_json(eng, eng.decide(c), c, {})
        claims = next(r for r in p["resources"] if r["id"] == "search_7")["claims"]
        self.assertEqual([(x["activity_id"], x["eligible"]) for x in claims], [("activity_9", False)])
        self.assertEqual(p["counts"]["claims_after_audit"], 1)


# ================================================================================================= ambiguity / integrity
class TestAmbiguityAndIntegrity(unittest.TestCase):
    def test_an_unattributed_ambiguous_link_is_reported_with_its_candidate_count_and_no_resource(self):
        _eng, _c, _d, p = decide_rich()
        self.assertEqual([(a["prefix"], a["candidates"]) for a in p["ambiguous"]], [("analytics_*", 2)])
        self.assertIn("ambiguous", p["flags"])
        self.assertNotIn("analytics_11", {r["id"] for r in p["resources"]})
        self.assertNotIn("analytics_12", {r["id"] for r in p["resources"]})

    def test_weak_claim_window_links_are_labelled_weak_with_the_claim_that_produced_them(self):
        w = [claim("activity_1", "DELETE_RECORD", "account_77", "2026-09-02T00:30:00Z", "account_service")]
        eng = make_engine(w)
        c = case(email="ana.silva@example.com")
        p = X.case_json(eng, eng.decide(c), c, {})
        r = p["resources"][0]
        self.assertEqual((r["id"], r["methods"], r["weak"]), ("account_77", ["claim_window"], True))
        self.assertEqual(r["link_evidence"][0]["items"], [{"activity_id": "activity_1"}])
        self.assertIn("weak_link", p["flags"])
        self.assertIn("WEAK", r["link_evidence"][0]["definition"])

    def test_missing_evidence_is_explicit_for_a_record_with_no_eligible_observation(self):
        w = [claim("activity_1", "DELETE_RECORD", "account_77", "2026-09-02T00:30:00Z", "account_service")]
        eng = make_engine(w)
        c = case(email="ana.silva@example.com")
        p = X.case_json(eng, eng.decide(c), c, {})
        r = p["resources"][0]
        self.assertEqual([o for o in r["observations"] if o["eligibility"] == "eligible"], [])
        self.assertEqual(r["verdict"], "unknown")
        self.assertTrue(r["reason"])

    def test_integrity_sections_come_from_the_existing_assessments(self):
        _eng, _c, _d, p = decide_rich()
        i = p["integrity"]
        self.assertEqual([(x["resource_id"], x["verdict"]) for x in i["flows"]], [("data_flow_3", "violation")])
        self.assertEqual([(x["resource_id"], x["verdict"]) for x in i["restore"]], [("backup_4", "violation")])
        self.assertEqual([(x["resource_id"], x["verdict"]) for x in i["retained"]], [("audit_record_5", "retained")])
        self.assertEqual([(x["resource_id"], x["verdict"]) for x in i["tombstones"]], [("tombstone_6", "violation")])
        self.assertEqual([(x["resource_id"], x["evidence_id"]) for x in i["missing_identifiers"]], [("account_9", "evidence_3")])

    def test_conflicting_ownership_is_reported_not_merged(self):
        w = [ob("evidence_1", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("ana.silva@example.com")]),
             ob("evidence_2", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("bob@example.com")])]
        eng = make_engine(w)
        c = case()
        p = X.case_json(eng, eng.decide(c), c, {})
        self.assertIn("another known user", p["integrity"]["conflicts"][0]["text"])
        self.assertIn("conflict", p["flags"])
        self.assertEqual(p["steps"], [])

    def test_a_contested_record_is_flagged_only_for_cases_that_actually_cite_it(self):
        eng = make_engine(rich_world())
        c = case(email="old.ana@example.com")
        d = eng.decide(c)
        contested = {"search_7": [("case_1", "user_1", "identifier"), ("case_8", "user_9", "claim_window")],
                     "backup_4": [("case_1", "user_1", "identifier"), ("case_8", "user_9", "claim_window")]}
        p = X.case_json(eng, d, c, contested)
        flagged = {x["resource_id"] for x in p["integrity"]["contested"]}
        self.assertEqual(flagged, {"search_7", "backup_4"})                       # both are cited by this case's steps
        uncited = {"support_9": [("case_1", "user_1", "identifier"), ("case_8", "user_9", "claim_window")]}      # linked and compliant, but an INCOMPLETE case does not cite it
        p2 = X.case_json(eng, d, c, uncited)
        self.assertIn("support_9", {r["id"] for r in p2["resources"]})                                  # it IS linked to the case ...
        self.assertEqual(p2["integrity"]["contested"], [])                                              # ... but not cited, so it is not flagged

    def test_unresolved_and_ambiguous_identities_are_shown_as_such_with_nothing_linked(self):
        eng = make_engine(rich_world())
        for email, status in (("shared@example.com", "ambiguous"), ("nobody@example.com", "unresolved")):
            c = case(email=email)
            p = X.case_json(eng, eng.decide(c), c, {})
            self.assertEqual((p["identity"]["status"], p["resources"], p["steps"]), (status, [], []), email)

    def test_not_applicable_requests_have_no_identity_or_steps(self):
        eng = make_engine(rich_world())
        c = case(text="Please send me a copy of my data. Do not delete anything.")
        p = X.case_json(eng, eng.decide(c), c, {})
        self.assertEqual((p["status"], p["identity"], p["steps"], p["resources"]), ("NOT_APPLICABLE", None, [], []))
        self.assertFalse(p["applicability"]["authorized"])


# ================================================================================================= lineage
class TestLineageUsesOnlyRecordedFields(unittest.TestCase):
    def test_link_evidence_points_at_real_observations_that_really_match_the_person(self):
        _eng, _c, _d, p = decide_rich()
        for r in p["resources"]:
            by_id = {o["obs_id"]: o for o in r["observations"]}
            for le in r["link_evidence"]:
                self.assertIn(le["method"], X.METHOD_DEFINITIONS)
                self.assertEqual(le["definition"], X.METHOD_DEFINITIONS[le["method"]])
                for it in le["items"]:
                    if "obs_id" in it:
                        o = by_id[it["obs_id"]]
                        self.assertEqual(o["eligibility"], "eligible")
                        if "kind" in it:
                            self.assertTrue(any(i["kind"] == it["kind"] and i["path"] == it["path"] and i["matches_person"] for i in o["identifiers"]))
                    else:
                        self.assertIn(it["activity_id"], {c["activity_id"] for c in r["claims"]})

    def test_the_historical_address_is_resolved_and_the_matched_identifier_is_marked(self):
        _eng, _c, _d, p = decide_rich()
        self.assertEqual((p["identity"]["via"], p["identity"]["user_id"]), ("historical", "user_1"))
        o = next(x for r in p["resources"] if r["id"] == "search_7" for x in r["observations"] if x["eligibility"] == "eligible")
        self.assertEqual([(i["value"], i["matches_person"]) for i in o["identifiers"]], [("old.ana@example.com", True)])

    def test_trace_and_identifier_methods_are_told_apart(self):
        _eng, _c, _d, p = decide_rich()
        self.assertEqual(next(r for r in p["resources"] if r["id"] == "account_9")["methods"], ["trace"])
        self.assertEqual(next(r for r in p["resources"] if r["id"] == "search_7")["methods"], ["identifier"])

    def test_ocr_uncertain_identifiers_are_listed_and_never_counted_as_matches(self):
        weak = ob("evidence_1", "export_5", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[("email", "ana.silva@example.com", "cells[1]", True)])
        strong = ob("evidence_1", "backup_5", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[("email", "ana.silva@example.com", "cells[1]", False), ("email", "ana.silva@example.com.br", "cells[2]", True)])
        eng = make_engine([weak, strong])
        c = case()
        p = X.case_json(eng, eng.decide(c), c, {})
        self.assertEqual([r["id"] for r in p["resources"]], ["backup_5"])               # the uncertain-only record is not linked at all
        self.assertEqual([u["value"] for u in p["integrity"]["uncertain_ocr"]], ["ana.silva@example.com.br"])
        self.assertIn("document_evidence", p["flags"])

    def test_every_step_resource_has_a_lineage_entry_and_every_cited_id_is_an_observation_or_snapshot(self):
        _eng, _c, _d, p = decide_rich()
        ids = {r["id"] for r in p["resources"]}
        for s in p["steps"]:
            self.assertIn(s["resource_id"], ids)
        cited = {r["cited_evidence"] for r in p["resources"] if r["cited_evidence"]}
        seen = {o["evidence_id"] for r in p["resources"] for o in r["observations"]} | {r["absence_proof"] for r in p["resources"] if r["absence_proof"]}
        self.assertTrue(cited <= seen, cited - seen)


# ================================================================================================= prediction integrity
class TestNeverChangesPredictions(unittest.TestCase):
    def test_payload_steps_are_exactly_the_engines_steps(self):
        eng, c, d, p = decide_rich()
        self.assertEqual(p["steps"], d.steps)
        self.assertEqual(p["status"], d.status)
        again = eng.decide(c)
        self.assertEqual((again.status, again.steps), (d.status, d.steps))               # building the payload left the engine's answer untouched

    def test_building_the_payload_does_not_mutate_the_corpus_or_decisions(self):
        eng = make_engine(rich_world())
        c = case(email="old.ana@example.com")
        before = [(o.obs_id, o.flags, dict(o.fields)) for o in eng.corpus.observations]
        first = eng.decide(c)
        snapshot = (first.status, json.dumps(first.steps, sort_keys=True))
        X.case_json(eng, first, c, {})
        X.case_json(eng, first, c, {"search_7": [("a", "u1", "x"), ("b", "u2", "y")]})
        self.assertEqual(before, [(o.obs_id, o.flags, dict(o.fields)) for o in eng.corpus.observations])
        self.assertEqual(snapshot, (first.status, json.dumps(first.steps, sort_keys=True)))

    def test_output_file_check_reports_match_difference_and_unreadable_files(self):
        eng = make_engine(rich_world())
        decisions = {"case_1": eng.decide(case(cid="case_1", email="old.ana@example.com")), "case_2": eng.decide(case(cid="case_2", text="Please correct my surname. Do not delete anything."))}
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "output.csv"
            write_output(decisions.values(), good)
            self.assertTrue(X.output_file_check(good, decisions)["matches_all"])
            with open(good, encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            rows[1][2] = "[]"
            bad = Path(tmp) / "bad.csv"
            with open(bad, "w", encoding="utf-8", newline="") as h:
                csv.writer(h, lineterminator="\n").writerows(rows)
            chk = X.output_file_check(bad, decisions)
            self.assertEqual((chk["matches_all"], chk["differing"]), (False, ["case_1"]))
            junk = Path(tmp) / "junk.csv"
            junk.write_text("case_id,deletion_status,steps_json\ncase_1,COMPLETE,not json\n", encoding="utf-8")
            self.assertFalse(X.output_file_check(junk, decisions)["readable"])
            self.assertEqual(X.output_file_check(Path(tmp) / "none.csv", decisions), {"present": False})


# ================================================================================================= reference / explanation
class TestExplanationsAreFactsOnly(unittest.TestCase):
    def test_an_unlinked_missing_step_says_it_is_unlinked_and_names_the_ambiguity(self):
        case_p = {"resources": [], "ambiguous": [{"prefix": "account_*", "candidates": 6, "text": ""}]}
        facts = X.explain_missing(("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_6440"), case_p)
        self.assertEqual(len(facts), 2)
        self.assertIn("not linked", facts[0])
        self.assertIn("6 candidate account_*", facts[1])

    def test_a_linked_missing_step_reports_counts_and_the_late_files_by_id(self):
        _eng, _c, _d, p = decide_rich()
        facts = X.explain_missing(("FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_7"), p)
        self.assertTrue(any("1 eligible observation(s), 1 excluded as after audit_at" in f for f in facts), facts)
        self.assertTrue(any("evidence_9 captured 2026-09-12T00:00:00Z, after audit_at" in f for f in facts), facts)

    def test_reference_comparison_buckets_matched_missing_extra_and_wrong_evidence(self):
        step = lambda n, op, rid, ev: {"step_no": n, "phase": "VERIFICATION", "system_id": "s", "resource_id": rid, "operation": op, "state": "ABSENT", "evidence_id": ev}  # noqa: E731
        case_p = {"status": "COMPLETE", "steps": [step(1, "VERIFY_RECORD_ABSENT", "a", "e1"), step(2, "VERIFY_RECORD_ABSENT", "b", "e1"), step(3, "VERIFY_RECORD_ABSENT", "x", "e1")],
                  "resources": [], "ambiguous": []}
        ref = ("COMPLETE", [step(1, "VERIFY_RECORD_ABSENT", "a", "e1"), step(2, "VERIFY_RECORD_ABSENT", "b", "e2"), step(3, "VERIFY_RECORD_ABSENT", "gone", "e1")])
        c = X.reference_comparison(case_p, ref)
        self.assertEqual(([m[3] for m in c["matched"]], [m["step"]["resource_id"] for m in c["missing"]], [e[3] for e in c["extra"]], [w[3] for w in c["wrong_evidence"]]),
                         (["a", "b"], ["gone"], ["x"], ["b"]))

    def test_featured_cases_are_generic_deterministic_and_never_not_applicable(self):
        _eng, _c, _d, rich = decide_rich()
        plain = dict(rich, id="case_2", status="COMPLETE", counts={}, ambiguous=[], flags=[], integrity=dict(rich["integrity"], uncertain_ocr=[]), identity=dict(rich["identity"], via="current"),
                     resources=[dict(r, methods=["identifier"]) for r in rich["resources"]])
        na = dict(rich, id="case_3", status="NOT_APPLICABLE")
        out = X.featured_cases([plain, rich, na], n=2)
        self.assertEqual([f["case_id"] for f in out], ["case_1", "case_2"])
        self.assertEqual(out, X.featured_cases([na, rich, plain], n=2))
        self.assertTrue(all(isinstance(r, str) for f in out for r in f["reasons"]))


# ================================================================================================= report/test-record readers
class TestRecordedResults(unittest.TestCase):
    def test_limitations_are_taken_verbatim_from_the_report_with_markdown_markers_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "evaluation_report.md"
            p.write_text("# R\n\n## 5. Other\n* not this\n\n## 6. Assumptions and limitations\n\n* **Sort order.** Rows are `numeric`.\n* **Names** are corroboration only.\n", encoding="utf-8")
            self.assertEqual(X.limitations_from_report(p), ["Sort order. Rows are numeric.", "Names are corroboration only."])
            self.assertEqual(X.limitations_from_report(Path(tmp) / "none.md"), [])

    def test_usage_table_is_read_without_the_header_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "usage_report.md"
            p.write_text("| Item | Value |\n|---|---|\n| Model calls | 0 |\n| Estimated cost | USD 0.00 |\n", encoding="utf-8")
            self.assertEqual(X.usage_from_report(p), {"Model calls": "0", "Estimated cost": "USD 0.00"})

    def test_unittest_summary_parsing(self):
        ok = T.parse_unittest_output("....\n----\nRan 433 tests in 113.2s\n\nOK (skipped=2)\n")
        self.assertEqual((ok["tests_run"], ok["status"], ok["skipped"], ok["failures"], ok["errors"], ok["duration_s"]), (433, "OK", 2, 0, 0, 113.2))
        bad = T.parse_unittest_output("Ran 10 tests in 0.5s\n\nFAILED (failures=2, errors=1)\n")
        self.assertEqual((bad["status"], bad["failures"], bad["errors"]), ("FAILED", 2, 1))
        for junk in ("", "Traceback\nboom", "Ran 5 tests in 1s\n"):
            with self.assertRaises(ValueError):
                T.parse_unittest_output(junk)

    def test_test_record_is_only_trusted_when_well_formed(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad, junk = Path(tmp) / "g.json", Path(tmp) / "b.json", Path(tmp) / "j.json"
            good.write_text(json.dumps({"tests_run": 5, "status": "OK"}), encoding="utf-8")
            bad.write_text(json.dumps({"hello": 1}), encoding="utf-8")
            junk.write_text("{not json", encoding="utf-8")
            self.assertEqual(X.load_test_results(good)["tests_run"], 5)
            self.assertIsNone(X.load_test_results(bad))
            self.assertIsNone(X.load_test_results(junk))
            self.assertIsNone(X.load_test_results(Path(tmp) / "missing.json"))


# ================================================================================================= HTML safety / offline
class TestHtmlIsOfflineAndInjectionSafe(unittest.TestCase):
    TEMPLATE = R.TEMPLATE.read_text(encoding="utf-8")

    def test_embedded_json_cannot_break_out_of_the_script_element(self):
        nasty = {"text": "</script><script>alert(1)</script><!-- & \u2028 \u2029 \"quoted\" \\ back"}
        out = R.embed_json(nasty)
        self.assertNotRegex(out, r"[<>&\u2028\u2029]")
        self.assertEqual(json.loads(out)["text"], nasty["text"])

    def test_rendering_requires_the_placeholder_and_fills_it_exactly_once(self):
        html = R.render_html({"k": 1})
        self.assertNotIn(R.PLACEHOLDER, html)
        self.assertEqual(html.count('id="ghost-data"'), 1)
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "t.html"
            empty.write_text("<html></html>", encoding="utf-8")
            with self.assertRaises(ValueError):
                R.render_html({}, empty)

    def test_template_makes_no_network_requests_and_never_writes_html_from_data(self):
        for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import(", "eval(", "new Function", "document.write", "innerHTML", "outerHTML", "insertAdjacentHTML", "<iframe", "<link ", "@import"):
            self.assertFalse(forbidden in self.TEMPLATE, "template contains forbidden: " + forbidden)
        urls = set(re.findall(r"https?://[^\s\"')]+", self.TEMPLATE))
        self.assertEqual(urls, {"http://www.w3.org/2000/svg"})                              # the SVG namespace constant is the only URL
        self.assertNotRegex(self.TEMPLATE, r"(src|href)=[\"']https?:")

    def test_template_has_the_accessibility_basics(self):
        for needle in ('<html lang="en">', 'name="viewport"', 'class="skip"', 'role="tablist"', 'role: "tab"', "aria-selected", "aria-live", "aria-label", ":focus-visible",
                       "prefers-color-scheme:dark", "prefers-reduced-motion", 'scope: "col"', "<main"):
            self.assertTrue(needle in self.TEMPLATE, "template is missing: " + needle)

    def test_the_unfilled_template_degrades_to_an_explanation_not_a_blank_page(self):
        self.assertIn("This is the unfilled template", self.TEMPLATE)


# ================================================================================================= full payload (synthetic)
class TestPayloadShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.eng = make_engine(rich_world())
        cls.requests = [case(cid="case_1", email="old.ana@example.com"), case(cid="case_2", text="Please correct my surname. Do not delete anything."), case(cid="case_3", email="nobody@example.com")]
        with tempfile.TemporaryDirectory() as tmp:
            cls.payload = X.build_payload(cls.eng, cls.requests, [], repo_root=REPO_ROOT, dataset_dir=Path(tmp))

    def test_payload_is_strict_json_with_the_documented_top_level_keys(self):
        text = json.dumps(self.payload, allow_nan=False)
        self.assertEqual(json.loads(text)["version"], X.PAYLOAD_VERSION)
        for k in ("meta", "files", "datasets", "evaluation", "output_check", "contested", "featured"):
            self.assertIn(k, self.payload)
        self.assertEqual(set(self.payload["datasets"]), {"evaluation", "samples"})

    def test_summary_counts_equal_what_the_cases_contain(self):
        s = self.payload["datasets"]["evaluation"]["summary"]
        cases = self.payload["datasets"]["evaluation"]["cases"]
        self.assertEqual((s["cases"], sum(s["statuses"].values()), s["steps"]), (3, 3, sum(len(c["steps"]) for c in cases)))
        self.assertEqual(s["unresolved_identities"], 1)
        self.assertEqual(s["statuses"]["NOT_APPLICABLE"], 1)

    def test_the_two_datasets_carry_their_honesty_labels(self):
        labels = self.payload["evaluation"]["labels"]
        self.assertIn("DEVELOPMENT SET", labels["samples"])
        self.assertIn("NO available ground truth", labels["evaluation"])
        self.assertIn("518", self.payload["datasets"]["evaluation"]["label"])
        self.assertIn("development", self.payload["datasets"]["samples"]["label"].lower())

    def test_custom_cases_are_reported_with_their_real_pass_state(self):
        custom = self.payload["evaluation"]["custom_cases"]
        self.assertGreaterEqual(len(custom), 3)
        self.assertTrue(all(isinstance(c["ok"], bool) for c in custom))

    def test_a_reference_answer_is_never_attached_to_an_evaluation_case_even_with_a_matching_id(self):
        ref = {"case_1": ("COMPLETE", [])}                       # same id as an evaluation case: it must still not appear there
        with tempfile.TemporaryDirectory() as tmp:
            p = X.build_payload(self.eng, self.requests, [], repo_root=REPO_ROOT, dataset_dir=Path(tmp), sample_reference=ref)
        self.assertFalse(any("reference" in c for c in p["datasets"]["evaluation"]["cases"]))
        with tempfile.TemporaryDirectory() as tmp:
            q = X.build_payload(self.eng, self.requests[:1], self.requests[:1], repo_root=REPO_ROOT, dataset_dir=Path(tmp), sample_reference={"case_1": ("COMPLETE", [])})
        self.assertTrue(all("reference" in c for c in q["datasets"]["samples"]["cases"]))          # the sample copy does carry it
        self.assertFalse(any("reference" in c for c in q["datasets"]["evaluation"]["cases"]))

    def test_no_sample_metrics_are_invented_when_no_reference_is_supplied(self):
        self.assertIsNone(self.payload["evaluation"]["samples"])


# ================================================================================================= real data

def read_rows(path) -> list:
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


@lru_cache(maxsize=1)
def real_build():
    from ghost_audit.engine.evaluate import read_output
    engine = AuditEngine(DATASET, corpus=Corpus.load_shared(DATASET))
    main, samples = read_rows(DATASET / "deletion_requests.csv"), read_rows(DATASET / "sample_deletion_requests.csv")
    before = {r["case_id"]: engine.decide(r) for r in main}
    payload = X.build_payload(engine, main, samples, repo_root=REPO_ROOT, dataset_dir=DATASET, sample_reference=read_output(DATASET / "sample_output.csv"))
    return engine, main, samples, before, payload


@needs_full
class TestRealDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.main, cls.samples, cls.before, cls.payload = real_build()
        cls.cases = cls.payload["datasets"]["evaluation"]["cases"]

    def test_every_case_is_present_once_in_input_order_and_shows_the_engines_exact_steps(self):
        self.assertEqual([c["id"] for c in self.cases], [r["case_id"] for r in self.main])
        self.assertEqual(len(self.cases), 518)
        for c in self.cases:
            d = self.before[c["id"]]
            self.assertEqual((c["status"], c["steps"]), (d.status, d.steps), c["id"])

    def test_building_the_explorer_leaves_predictions_and_output_bytes_identical(self):
        after = {r["case_id"]: self.engine.decide(r) for r in self.main}
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "before.csv", Path(tmp) / "after.csv"
            write_output(self.before.values(), a)
            write_output(after.values(), b)
            self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_summary_numbers_are_recomputed_from_the_cases_not_typed_in(self):
        s = self.payload["datasets"]["evaluation"]["summary"]
        self.assertEqual(sum(s["statuses"].values()), 518)
        self.assertEqual(s["steps"], sum(len(c["steps"]) for c in self.cases))
        self.assertEqual(s["statuses"].get("NOT_APPLICABLE", 0), 10)
        self.assertEqual(s["unresolved_identities"], 0)

    def test_sample_metrics_equal_a_fresh_evaluation_and_are_labelled_development(self):
        from ghost_audit.engine.evaluate import evaluate, read_output
        pred = {r["case_id"]: (lambda d: (d.status, d.steps))(self.engine.decide(r)) for r in self.samples}
        fresh = evaluate(pred, read_output(DATASET / "sample_output.csv"))
        shown = self.payload["evaluation"]["samples"]
        for k in ("status_accuracy", "step_precision", "step_recall", "step_f1", "sequence_accuracy", "steps_matched", "steps_missing", "steps_extra", "evidence_accuracy_on_matched"):
            self.assertEqual(shown[k], fresh[k], k)
        self.assertIn("DEVELOPMENT SET", self.payload["evaluation"]["labels"]["samples"])
        self.assertIn("NO available ground truth", self.payload["evaluation"]["labels"]["evaluation"])
        self.assertTrue(all("reference" in c for c in self.payload["datasets"]["samples"]["cases"]))
        self.assertFalse(any("reference" in c for c in self.cases), "the 518 evaluation cases must never carry a reference answer")

    def test_every_cited_evidence_id_is_a_manifest_file_and_every_step_has_a_lineage_entry(self):
        files = self.payload["files"]
        for c in self.cases:
            ids = {r["id"] for r in c["resources"]}
            for s in c["steps"]:
                self.assertIn(s["resource_id"], ids, c["id"])
                if s["evidence_id"]:
                    self.assertIn(s["evidence_id"], files, c["id"])

    def test_evidence_classification_matches_the_engines_eligibility_rule_on_every_observation(self):
        corpus = self.engine.corpus
        by_obs = {}
        for o in corpus.observations:
            by_obs[o.obs_id] = o
        checked = 0
        for r in self.main[::7]:
            c = next(x for x in self.cases if x["id"] == r["case_id"])
            for res in c["resources"]:
                for o in res["observations"]:
                    src = by_obs[o["obs_id"]]
                    self.assertEqual(o["eligibility"] == "eligible", Corpus.eligible(src, r["audit_at"], r["requested_at"]), (c["id"], o["obs_id"]))
                    checked += 1
        self.assertGreater(checked, 100)

    def test_contested_records_really_are_cited_for_more_than_one_person(self):
        owners: Dict[str, set] = {}
        for ds in self.payload["datasets"].values():
            for c in ds["cases"]:
                for s in c["steps"]:
                    owners.setdefault(s["resource_id"], set()).add(c["identity"]["user_id"] if c["identity"] else None)
        for x in self.payload["contested"]:
            self.assertGreaterEqual(len(owners[x["resource_id"]] - {None}), 2, x["resource_id"])

    def test_the_submission_file_check_reflects_the_real_output_csv(self):
        chk = self.payload["output_check"]
        self.assertEqual(chk["present"], (REPO_ROOT / "output.csv").is_file())
        if chk["present"] and chk.get("readable"):
            self.assertEqual(chk["rows"], 518)
            self.assertTrue(chk["header_ok"])
            self.assertEqual(chk["matches_all"], not chk["differing"] and not chk["missing_from_file"] and not chk["unknown_in_file"])

    def test_payload_is_strict_json_and_a_reasonable_size_and_renders(self):
        text = json.dumps(self.payload, allow_nan=False)
        self.assertLess(len(text), 12_000_000)
        html = R.render_html(self.payload)
        self.assertIn('id="ghost-data"', html)
        self.assertNotIn("</script><", html.split('id="ghost-data"', 1)[1].split("</script>", 1)[0])

    def test_the_walkthrough_in_the_documentation_describes_what_the_data_really_shows(self):
        """Documentation drift guard: the concrete claims made about case_376, case_45 and sample case_21 in explorer/README.md."""
        c376 = next(c for c in self.cases if c["id"] == "case_376")
        self.assertEqual((c376["status"], c376["identity"]["user_id"], c376["identity"]["via"]), ("INCOMPLETE", "user_374", "historical"))
        acct = next(r for r in c376["resources"] if r["id"] == "account_5454")
        self.assertEqual((acct["methods"], acct["weak"], acct["absence_proof"]), (["claim_window"], True, "evidence_69"))
        self.assertIn({"activity_id": "activity_1110"}, acct["link_evidence"][0]["items"])
        by_ev = {o["evidence_id"]: o["eligibility"] for r in c376["resources"] for o in r["observations"]}
        self.assertEqual((by_ev["evidence_70"], by_ev["evidence_35"]), ("eligible", "after_audit"))
        self.assertTrue(any(a["prefix"] == "analytics_*" for a in c376["ambiguous"]))
        c45 = next(c for c in self.cases if c["id"] == "case_45")
        self.assertEqual(c45["status"], "COMPLETE")
        self.assertTrue(any(o["evidence_id"] == "evidence_37" and o["format"] == "image" for r in c45["resources"] for o in r["observations"]))
        c21 = next(c for c in self.payload["datasets"]["samples"]["cases"] if c["id"] == "case_21")
        missing = [m for m in c21["reference"]["missing"] if m["step"]["resource_id"] == "account_6440"]
        self.assertEqual(len(missing), 1)
        self.assertTrue(any("6 candidate account_*" in f for f in missing[0]["facts"]), missing[0]["facts"])

    def test_featured_cases_exist_and_are_real_cases(self):
        ids = {c["id"] for c in self.cases}
        self.assertTrue(self.payload["featured"])
        self.assertTrue(all(f["case_id"] in ids and f["reasons"] for f in self.payload["featured"]))


# ================================================================================================= browser smoke test
@unittest.skipUnless(HAVE_BROWSER, "playwright is not installed (optional): pip install playwright && playwright install chromium")
class TestBrowserSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:  # no browser binary installed
            cls._pw.stop()
            raise unittest.SkipTest("Chromium is not available: %s" % str(exc)[:80])
        eng = make_engine(rich_world())
        evil = "<img src=x onerror=window.__pwned=1><script>window.__pwned=2</script>"
        reqs = [case(cid="case_1", email="old.ana@example.com", text="Please delete my account. " + evil), case(cid="case_2", text="Please correct my surname. Do not delete anything."),
                case(cid="case_3", email="nobody@example.com")]
        with tempfile.TemporaryDirectory() as tmp:
            payload = X.build_payload(eng, reqs, [], repo_root=REPO_ROOT, dataset_dir=Path(tmp))
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "explorer.html"
        cls.path.write_text(R.render_html(payload), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._pw.stop()
        cls.tmp.cleanup()

    def open(self, hash_=""):
        page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        self.errors, self.requests = [], []
        page.on("pageerror", lambda e: self.errors.append(str(e)))
        page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        page.on("request", lambda r: self.requests.append(r.url) if not r.url.startswith(("file:", "data:")) else None)
        page.goto(self.path.as_uri() + hash_)
        page.wait_for_function("window.__ghostExplorerReady === true")
        self.addCleanup(page.close)
        return page

    def test_loads_filters_and_opens_a_case_without_errors_or_network_requests(self):
        page = self.open()
        self.assertEqual(page.locator("#case-list .item").count(), 3)
        page.fill("#case-search", "case_2")
        self.assertEqual(page.locator("#case-list .item").count(), 1)
        self.assertEqual(page.inner_text("#result-count").strip(), "1 of 3 cases")
        page.fill("#case-search", "zzz-no-such-case")
        self.assertIn("No cases match", page.inner_text("#case-list"))
        page.fill("#case-search", "")
        page.locator("#case-list .item").first.click()
        self.assertIn("case_1", page.inner_text(".detailcol h2"))
        for tab in ("Steps", "Evidence lineage", "Timeline", "Integrity"):
            page.locator(".dtab", has_text=tab).first.click()
            self.assertGreater(len(page.inner_text(".detailcol")), 40, tab)
        self.assertEqual((self.errors, self.requests), ([], []))

    def test_status_filter_and_dataset_switch_and_deep_links_work(self):
        page = self.open()
        page.locator(".chip", has_text="NOT APPLICABLE").first.click()
        self.assertEqual(page.locator("#case-list .item").count(), 1)
        page.locator(".seg button", has_text="Samples").click()
        self.assertIn("DEVELOPMENT", page.inner_text("#notice"))
        deep = self.open("#/case/case_1/lineage")
        self.assertIn("Evidence lineage", deep.inner_text(".dtab[aria-selected=true]"))
        self.assertIn("1. identity", deep.inner_text(".detailcol").lower())          # inner_text returns the CSS-uppercased heading

    def test_untrusted_request_text_is_shown_as_text_and_never_executed(self):
        page = self.open("#/case/case_1/overview")
        self.assertIn("<img src=x", page.inner_text(".detailcol"))                 # visible as literal text
        self.assertEqual(page.locator(".detailcol img").count(), 0)
        self.assertIsNone(page.evaluate("window.__pwned === undefined ? null : window.__pwned"))

    def test_evaluation_and_integrity_pages_render_with_their_honesty_labels(self):
        page = self.open("#/evaluation")
        self.assertIn("NO available ground truth", page.inner_text("main"))
        self.assertIn("No reference answers found", page.inner_text("main"))        # nothing is invented when no reference exists
        page2 = self.open("#/integrity")
        self.assertIn("Submission file vs the engine", page2.inner_text("main"))
        self.assertEqual(self.errors, [])

    def test_small_screens_do_not_scroll_sideways(self):
        page = self.browser.new_page(viewport={"width": 390, "height": 844})
        self.addCleanup(page.close)
        page.goto(self.path.as_uri() + "#/case/case_1/lineage")
        page.wait_for_function("window.__ghostExplorerReady === true")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth"), 0)


if __name__ == "__main__":
    unittest.main()
