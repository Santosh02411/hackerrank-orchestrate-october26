"""Stage 0 tests: output contract + validator.

Run from the repository root (Windows PowerShell or any shell):

    python -m unittest discover -s code/tests -t code -v

Design rules for this file:
  * The original dataset files are NEVER written. Mutations happen on in-memory
    copies or on files created inside a temporary directory, and
    ``tearDownModule`` re-hashes the dataset files to prove they are unchanged.
  * No case ID, label or individual answer is hard-coded. Mutation targets are
    chosen by *structure* ("an INCOMPLETE case with two remediation steps").
  * Tests that read the repository's Markdown/CSV files are skipped (not
    failed) when those files are absent, e.g. inside an unpacked code.zip.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit import contracts as C  # noqa: E402
from ghost_audit.ordering import SortStrategy, lexical_key, natural_key  # noqa: E402
from ghost_audit.validator import (  # noqa: E402
    OutputRow,
    Rule,
    Severity,
    ValidatorConfig,
    validate_csv,
    validate_rows,
    validate_steps_json,
)

DATASET = REPO_ROOT / "dataset"
SAMPLE_OUTPUT = DATASET / "sample_output.csv"
SAMPLE_REQUESTS = DATASET / "sample_deletion_requests.csv"
PROBLEM_STATEMENT = REPO_ROOT / "problem_statement.md"
AGENTS_MD = REPO_ROOT / "AGENTS.md"
README_MD = REPO_ROOT / "README.md"
HAVE_SAMPLE = SAMPLE_OUTPUT.exists() and SAMPLE_REQUESTS.exists()

_PROTECTED = [
    DATASET / "sample_output.csv",
    DATASET / "sample_deletion_requests.csv",
    DATASET / "deletion_requests.csv",
    DATASET / "output.csv",
]
_HASHES_BEFORE: Dict[Path, Optional[str]] = {}


def _sha(path: Path) -> Optional[str]:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def setUpModule() -> None:
    for p in _PROTECTED:
        _HASHES_BEFORE[p] = _sha(p)


def tearDownModule() -> None:
    for p in _PROTECTED:
        if _HASHES_BEFORE.get(p) != _sha(p):
            raise AssertionError("test run modified protected dataset file %s" % p)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
Case = Dict[str, object]  # {"case_id", "status", "steps": list[dict]}


def load_sample_cases() -> List[Case]:
    cases: List[Case] = []
    with open(SAMPLE_OUTPUT, "r", encoding="utf-8", newline="") as handle:
        for rec in csv.DictReader(handle):
            cases.append({"case_id": rec["case_id"], "status": rec["deletion_status"],
                          "steps": json.loads(rec["steps_json"])})
    return cases


def dump(steps: list) -> str:
    return json.dumps(steps, separators=(",", ":"))


def renumber(steps: list) -> list:
    for i, s in enumerate(steps, start=1):
        s["step_no"] = i
    return steps


def to_rows(cases: List[Case]) -> List[OutputRow]:
    return [OutputRow(str(c["case_id"]), str(c["status"]), dump(c["steps"]), line=i + 2)  # type: ignore[arg-type]
            for i, c in enumerate(cases)]


def make_step(n: int, operation: str, system_id: str, resource_id: str, evidence_id: str) -> dict:
    spec = C.OPERATION_SPEC_BY_NAME[operation]
    return {"step_no": n, "phase": spec.phase, "system_id": system_id, "resource_id": resource_id,
            "operation": operation, "state": spec.state, "evidence_id": evidence_id}


def find_case(cases: List[Case], status: str, predicate: Callable[[list], bool] = lambda s: True) -> Case:
    for c in cases:
        if c["status"] == status and predicate(c["steps"]):  # type: ignore[arg-type]
            return copy.deepcopy(c)
    raise unittest.SkipTest("sample has no %s case matching the structural predicate" % status)


def phase_steps(steps: list, phase: str) -> list:
    return [s for s in steps if s["phase"] == phase]


def run_case(case: Case, **config) -> "object":
    return validate_rows(to_rows([case]), ValidatorConfig(**config))


def errors_of(report) -> set:
    return report.codes(Severity.ERROR)


class ContractTestCase(unittest.TestCase):
    def assertErrors(self, report, expected: set, msg: str = "") -> None:
        self.assertEqual(errors_of(report), set(expected),
                         "%s\nissues:\n%s" % (msg, "\n".join(str(i) for i in report.issues)))


# --------------------------------------------------------------------------- #
# 1. The contract module agrees with the repository's own documents
# --------------------------------------------------------------------------- #
class TestContractInternals(ContractTestCase):
    def test_operation_table_shape(self):
        self.assertEqual(len(C.OPERATION_SPECS), 15)
        self.assertEqual(len(C.OPERATION_SPEC_BY_NAME), 15, "operation names must be unique")
        counts = {p: sum(1 for s in C.OPERATION_SPECS if s.phase == p) for p in C.PHASES}
        self.assertEqual(counts, {"FINDING": 4, "REMEDIATION": 5, "VERIFICATION": 6})

    def test_table_is_grouped_by_phase_in_phase_order(self):
        ranks = [C.PHASE_RANK[s.phase] for s in C.OPERATION_SPECS]
        self.assertEqual(ranks, sorted(ranks))

    def test_every_remediation_state_has_exactly_one_verification(self):
        rem = [s.state for s in C.OPERATION_SPECS if s.phase == C.PHASE_REMEDIATION]
        ver = [s.state for s in C.OPERATION_SPECS if s.phase == C.PHASE_VERIFICATION]
        for state in rem:
            self.assertEqual(ver.count(state), 1, state)

    def test_finding_pairs_reference_real_remediations(self):
        for finding, remediations in C.FINDING_REMEDIATION_PAIRS.items():
            self.assertEqual(C.OPERATION_SPEC_BY_NAME[finding].phase, C.PHASE_FINDING)
            for r in remediations:
                self.assertEqual(C.OPERATION_SPEC_BY_NAME[r].phase, C.PHASE_REMEDIATION)

    def test_defaults_do_not_silently_pick_lexical_or_natural(self):
        cfg = ValidatorConfig()
        self.assertIs(cfg.case_id_order, SortStrategy.EITHER)
        self.assertIs(cfg.resource_order, SortStrategy.EITHER)


@unittest.skipUnless(PROBLEM_STATEMENT.exists() and AGENTS_MD.exists(), "repository Markdown not present")
class TestContractMatchesRepositoryDocs(ContractTestCase):
    def test_problem_statement_operation_table_matches_in_order(self):
        text = PROBLEM_STATEMENT.read_text(encoding="utf-8")
        rows = re.findall(r"^\|\s*`(FINDING|REMEDIATION|VERIFICATION)`\s*\|\s*`(\w+)`\s*\|\s*`(\w+)`\s*\|",
                          text, flags=re.M)
        self.assertEqual(len(rows), 15, "could not parse the Allowed Operations table")
        self.assertEqual([tuple(r) for r in rows], [tuple(s) for s in C.OPERATION_SPECS])

    def test_agents_section_6_4_matches_in_order(self):
        text = AGENTS_MD.read_text(encoding="utf-8")
        section = text[text.index("### 6.4"):text.index("### 6.5")]
        parsed = []
        phase = None
        for line in section.splitlines():
            head = re.match(r"^(Findings|Remediation|Verification):\s*$", line)
            if head:
                phase = head.group(1).upper().replace("FINDINGS", "FINDING")
                continue
            m = re.match(r"^\|\s*`(\w+)`\s*\|\s*`(\w+)`\s*\|", line)
            if m and phase:
                parsed.append((phase, m.group(1), m.group(2)))
        self.assertEqual(parsed, [tuple(s) for s in C.OPERATION_SPECS])

    def test_step_schema_matches_problem_statement_example(self):
        text = PROBLEM_STATEMENT.read_text(encoding="utf-8")
        blocks = re.findall(r"```json\n(.*?)```", text, flags=re.S)
        example = next(json.loads(b) for b in blocks if '"step_no"' in b)
        self.assertEqual(set(example), set(C.STEP_KEYS))
        self.assertEqual(len(C.STEP_KEYS), 7)

    def test_csv_header_matches_readme(self):
        self.assertIn(",".join(C.CSV_COLUMNS), README_MD.read_text(encoding="utf-8"))

    def test_all_statuses_and_phases_are_named_in_problem_statement(self):
        text = PROBLEM_STATEMENT.read_text(encoding="utf-8")
        for token in list(C.DELETION_STATUSES) + list(C.PHASES):
            self.assertIn("`%s`" % token, text)

    @unittest.skipUnless((DATASET / "evidence_files.csv").exists(), "dataset not present")
    def test_evidence_id_pattern_matches_every_id_column_in_dataset(self):
        for fname, col in (("evidence_files.csv", "file_id"), ("system_activity.csv", "activity_id"),
                           ("user_audit_log.csv", "audit_id")):
            with open(DATASET / fname, "r", encoding="utf-8", newline="") as handle:
                ids = [r[col] for r in csv.DictReader(handle)]
            self.assertTrue(ids)
            bad = [i for i in ids if not C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(i)]
            self.assertEqual(bad, [], "%s.%s has IDs outside the pattern" % (fname, col))


# --------------------------------------------------------------------------- #
# 2. The public sample is accepted
# --------------------------------------------------------------------------- #
@unittest.skipUnless(HAVE_SAMPLE, "dataset sample files not present")
class TestSampleAccepted(ContractTestCase):
    @classmethod
    def setUpClass(cls):
        with open(SAMPLE_REQUESTS, "r", encoding="utf-8", newline="") as handle:
            cls.sample_ids = [r["case_id"] for r in csv.DictReader(handle)]

    def test_sample_output_is_accepted_with_no_errors_or_warnings(self):
        cfg = ValidatorConfig(expected_case_ids=self.sample_ids, expected_row_count=len(self.sample_ids))
        report = validate_csv(SAMPLE_OUTPUT, cfg)
        self.assertEqual([str(i) for i in report.issues], [])
        self.assertEqual((report.row_count, report.case_count), (32, 32))

    def test_sample_is_accepted_under_every_sort_strategy(self):
        for case_order in SortStrategy:
            for resource_order in SortStrategy:
                with self.subTest(case=case_order.value, resource=resource_order.value):
                    report = validate_csv(SAMPLE_OUTPUT, ValidatorConfig(
                        case_id_order=case_order, resource_order=resource_order))
                    self.assertTrue(report.ok, [str(i) for i in report.errors])

    def test_sample_is_accepted_with_pairing_diagnostics_promoted_to_errors(self):
        report = validate_csv(SAMPLE_OUTPUT, ValidatorConfig(pairing_severity=Severity.ERROR))
        self.assertTrue(report.ok, [str(i) for i in report.errors])

    def test_sample_does_not_discriminate_between_sort_strategies(self):
        report = validate_csv(SAMPLE_OUTPUT)
        self.assertEqual(report.ordering["case_id"], ("lexical", "natural"))
        self.assertEqual(report.ordering["resource_id"], ("lexical", "natural"))

    def test_wrong_expected_row_count_is_rejected(self):
        report = validate_csv(SAMPLE_OUTPUT, ValidatorConfig(expected_row_count=518))
        self.assertErrors(report, {Rule.ROW_COUNT})

    def test_expected_case_set_mismatch_is_rejected(self):
        ids = set(self.sample_ids)
        gone = sorted(ids)[0]
        report = validate_csv(SAMPLE_OUTPUT, ValidatorConfig(expected_case_ids=(ids - {gone}) | {"case_does_not_exist"}))
        self.assertErrors(report, {Rule.CASE_ID_MISSING, Rule.CASE_ID_UNEXPECTED})

    def test_sample_contains_the_complete_and_incomplete_cases_the_mutation_tests_use(self):
        # The public sample has no NOT_APPLICABLE row (verified in recon), which is why
        # NOT_APPLICABLE behaviour is tested with synthetic rows below.
        statuses = {c["status"] for c in load_sample_cases()}
        self.assertTrue({"COMPLETE", "INCOMPLETE"} <= statuses)


# --------------------------------------------------------------------------- #
# 3. Mutations of valid cases must be rejected for the intended rule only
# --------------------------------------------------------------------------- #
@unittest.skipUnless(HAVE_SAMPLE, "dataset sample files not present")
class TestMutationsRejected(ContractTestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = load_sample_cases()

    def incomplete(self, predicate=lambda s: True) -> Case:
        return find_case(self.cases, "INCOMPLETE", predicate)

    def complete(self, predicate=lambda s: True) -> Case:
        return find_case(self.cases, "COMPLETE", predicate)

    # ---- baseline: untouched copies are clean --------------------------------
    def test_unmutated_copies_are_clean(self):
        for status in ("COMPLETE", "INCOMPLETE"):
            report = run_case(find_case(self.cases, status))
            self.assertEqual([str(i) for i in report.issues], [], status)

    # ---- invalid operation/state/phase combinations ----------------------------
    def test_state_not_matching_operation_is_rejected_with_step_number(self):
        case = self.incomplete()
        steps = case["steps"]
        steps[0]["state"] = "ABSENT" if steps[0]["state"] != "ABSENT" else "PRESENT"
        report = run_case(case)
        self.assertErrors(report, {Rule.STEP_COMBINATION})
        issue = report.errors[0]
        self.assertEqual(issue.case_id, case["case_id"])
        self.assertEqual(issue.step, 1)
        text = str(issue)
        self.assertIn("case_id=%s" % case["case_id"], text)
        self.assertIn("step 1", text)
        self.assertIn(Rule.STEP_COMBINATION, text)

    def test_operation_in_the_wrong_phase_is_rejected(self):
        case = self.complete()
        case["steps"][0]["phase"] = "FINDING"  # a verify operation labelled FINDING
        report = run_case(case)
        self.assertIn(Rule.STEP_COMBINATION, errors_of(report))

    def test_unknown_operation_is_rejected(self):
        case = self.complete()
        case["steps"][0]["operation"] = "DELETE_EVERYTHING"
        self.assertErrors(run_case(case), {Rule.STEP_OPERATION_INVALID})

    def test_unknown_phase_is_rejected(self):
        case = self.complete()
        case["steps"][0]["phase"] = "REVIEW"
        self.assertIn(Rule.STEP_PHASE_INVALID, errors_of(run_case(case)))

    def test_unknown_state_is_rejected(self):
        case = self.complete()
        case["steps"][0]["state"] = "GONE"
        self.assertIn(Rule.STEP_STATE_INVALID, errors_of(run_case(case)))

    def test_lowercase_enum_values_are_rejected(self):
        case = self.complete()
        case["steps"][0]["phase"] = case["steps"][0]["phase"].lower()
        self.assertIn(Rule.STEP_PHASE_INVALID, errors_of(run_case(case)))

    # ---- step numbering ------------------------------------------------------------
    def test_gap_in_step_numbers_is_rejected(self):
        case = self.incomplete(lambda s: len(s) >= 3)
        case["steps"][2]["step_no"] = 4
        report = run_case(case)
        self.assertErrors(report, {Rule.STEP_NO_SEQUENCE})
        self.assertEqual(report.errors[0].step, 3)

    def test_numbering_starting_at_zero_is_rejected(self):
        case = self.incomplete()
        for i, s in enumerate(case["steps"]):
            s["step_no"] = i
        self.assertErrors(run_case(case), {Rule.STEP_NO_SEQUENCE})

    def test_duplicate_step_numbers_are_rejected(self):
        case = self.incomplete(lambda s: len(s) >= 2)
        case["steps"][1]["step_no"] = 1
        self.assertErrors(run_case(case), {Rule.STEP_NO_SEQUENCE})

    def test_step_numbers_as_strings_floats_or_booleans_are_rejected(self):
        for bad in ("1", 1.0, True):
            with self.subTest(value=repr(bad)):
                case = self.complete()
                case["steps"][0]["step_no"] = bad
                self.assertIn(Rule.STEP_FIELD_TYPE, errors_of(run_case(case)))

    # ---- ordering -----------------------------------------------------------------------
    def test_verification_before_finding_is_rejected(self):
        case = self.incomplete()
        steps = case["steps"]
        last = steps.pop()  # a VERIFICATION step
        steps.insert(0, last)
        renumber(steps)
        self.assertErrors(run_case(case), {Rule.STEP_ORDER_PHASE})

    def test_remediation_before_finding_is_rejected(self):
        case = self.incomplete()
        steps = case["steps"]
        first_remediation = next(i for i, s in enumerate(steps) if s["phase"] == "REMEDIATION")
        steps.insert(0, steps.pop(first_remediation))
        renumber(steps)
        self.assertErrors(run_case(case), {Rule.STEP_ORDER_PHASE})

    @staticmethod
    def _adjacent_pair(steps: list, same_operation: bool) -> Optional[int]:
        for i in range(len(steps) - 1):
            a, b = steps[i], steps[i + 1]
            if a["phase"] != b["phase"]:
                continue
            if same_operation and a["operation"] == b["operation"] and \
                    (a["system_id"], a["resource_id"]) != (b["system_id"], b["resource_id"]):
                return i
            if not same_operation and a["operation"] != b["operation"]:
                return i
        return None

    def test_operations_out_of_table_order_inside_a_phase_are_rejected(self):
        case = self.incomplete(lambda s: TestMutationsRejected._adjacent_pair(s, False) is not None)
        steps = case["steps"]
        i = self._adjacent_pair(steps, False)
        steps[i], steps[i + 1] = steps[i + 1], steps[i]
        renumber(steps)
        self.assertErrors(run_case(case), {Rule.STEP_ORDER_OPERATION})

    def test_resources_out_of_order_inside_one_operation_are_rejected(self):
        case = self.incomplete(lambda s: TestMutationsRejected._adjacent_pair(s, True) is not None)
        steps = case["steps"]
        i = self._adjacent_pair(steps, True)
        steps[i], steps[i + 1] = steps[i + 1], steps[i]
        renumber(steps)
        report = run_case(case)
        self.assertErrors(report, {Rule.STEP_ORDER_ID})
        report = run_case(case, resource_order=SortStrategy.NONE)
        self.assertTrue(report.ok, "resource order must be skippable with SortStrategy.NONE")

    # ---- JSON / schema --------------------------------------------------------------------------
    def _raw(self, case: Case, text: str):
        return validate_rows([OutputRow(str(case["case_id"]), str(case["status"]), text, line=2)])

    def test_malformed_json_is_rejected(self):
        case = self.complete()
        good = dump(case["steps"])
        for label, text in (("truncated", good[:-1]), ("trailing comma", good[:-1] + ",]"),
                            ("single quotes", good.replace('"', "'")), ("empty string", ""),
                            ("bare word", "none"), ("NaN constant", "[NaN]")):
            with self.subTest(label):
                self.assertIn(Rule.JSON_MALFORMED, errors_of(self._raw(case, text)))

    def test_json_that_is_not_an_array_is_rejected(self):
        case = self.complete()
        for text in ('{"step_no":1}', '"[]"', "null", "5"):
            with self.subTest(text):
                self.assertErrors(self._raw(case, text), {Rule.JSON_NOT_ARRAY})

    def test_step_that_is_not_an_object_is_rejected(self):
        self.assertErrors(self._raw(self.complete(), '[1]'), {Rule.STEP_NOT_OBJECT})

    def test_extra_key_is_rejected(self):
        case = self.complete()
        case["steps"][0]["note"] = "x"
        self.assertErrors(run_case(case), {Rule.STEP_KEYS})

    def test_missing_key_is_rejected(self):
        case = self.complete()
        del case["steps"][0]["evidence_id"]
        self.assertErrors(run_case(case), {Rule.STEP_KEYS})

    def test_renamed_key_is_rejected_as_missing_plus_extra(self):
        case = self.complete()
        case["steps"][0]["evidence"] = case["steps"][0].pop("evidence_id")
        report = run_case(case)
        self.assertErrors(report, {Rule.STEP_KEYS})
        self.assertIn("evidence_id", report.errors[0].message)

    def test_duplicate_json_keys_are_rejected(self):
        case = self.complete()
        text = dump(case["steps"])
        text = text.replace('"step_no":1', '"step_no":1,"step_no":1', 1)
        self.assertIn(Rule.JSON_DUPLICATE_KEY, errors_of(self._raw(case, text)))

    def test_non_string_fields_are_rejected(self):
        for key in C.STEP_STRING_KEYS:
            with self.subTest(key):
                case = self.complete()
                case["steps"][0][key] = None
                self.assertIn(Rule.STEP_FIELD_TYPE, errors_of(run_case(case)))

    def test_empty_or_padded_ids_are_rejected(self):
        for key in ("system_id", "resource_id"):
            for bad in ("", " padded"):
                with self.subTest(key=key, value=bad):
                    case = self.complete()
                    case["steps"][0][key] = bad
                    self.assertIn(Rule.STEP_FIELD_VALUE, errors_of(run_case(case)))

    # ---- evidence_id usage ------------------------------------------------------------------------------
    def test_remediation_with_evidence_id_is_rejected(self):
        case = self.incomplete()
        step = phase_steps(case["steps"], "REMEDIATION")[0]
        step["evidence_id"] = "evidence_01"
        report = run_case(case)
        self.assertErrors(report, {Rule.EVIDENCE_MUST_BE_EMPTY})
        self.assertEqual(report.errors[0].step, step["step_no"])

    def test_future_verification_in_incomplete_with_evidence_id_is_rejected(self):
        case = self.incomplete()
        phase_steps(case["steps"], "VERIFICATION")[0]["evidence_id"] = "evidence_01"
        self.assertErrors(run_case(case), {Rule.EVIDENCE_MUST_BE_EMPTY})

    def test_finding_without_evidence_id_is_rejected(self):
        case = self.incomplete()
        phase_steps(case["steps"], "FINDING")[0]["evidence_id"] = ""
        self.assertErrors(run_case(case), {Rule.EVIDENCE_REQUIRED})

    def test_complete_verification_without_evidence_id_is_rejected(self):
        case = self.complete()
        case["steps"][0]["evidence_id"] = ""
        self.assertErrors(run_case(case), {Rule.EVIDENCE_REQUIRED})

    def test_evidence_id_shape_is_checked_and_can_be_disabled(self):
        for bad in ("ev-12", "Evidence_01", "evidence_01 ", "evidence_", "file_3", "01"):
            with self.subTest(bad):
                case = self.complete()
                case["steps"][0]["evidence_id"] = bad
                self.assertErrors(run_case(case), {Rule.EVIDENCE_FORMAT})
        case = self.complete()
        case["steps"][0]["evidence_id"] = "ev-12"
        self.assertTrue(run_case(case, evidence_id_pattern=None).ok)

    def test_activity_and_audit_ids_are_accepted_as_citations(self):
        for good in ("activity_17", "audit_3", "evidence_001"):
            with self.subTest(good):
                case = self.complete()
                case["steps"][0]["evidence_id"] = good
                self.assertTrue(run_case(case).ok)

    # ---- status-specific constraints -----------------------------------------------------------------
    def test_invalid_status_values_are_rejected(self):
        for bad in ("Complete", "DONE", "", "COMPLETE "):
            with self.subTest(bad):
                case = self.complete()
                case["status"] = bad
                self.assertIn(Rule.STATUS_INVALID, errors_of(run_case(case)))

    def test_complete_with_a_finding_step_is_rejected(self):
        case = self.incomplete()
        finding = phase_steps(case["steps"], "FINDING")[0]
        complete = self.complete()
        complete["steps"].insert(0, copy.deepcopy(finding))
        renumber(complete["steps"])
        report = run_case(complete)
        self.assertIn(Rule.STATUS_PHASE_NOT_ALLOWED, errors_of(report))
        self.assertEqual(report.errors[0].step, 1)

    def test_complete_with_remediation_step_is_rejected(self):
        complete = self.complete()
        complete["steps"].insert(0, make_step(1, "DELETE_RECORD", "account_service", "account_1", ""))
        renumber(complete["steps"])
        self.assertIn(Rule.STATUS_PHASE_NOT_ALLOWED, errors_of(run_case(complete)))

    def test_complete_with_empty_array_is_rejected(self):
        complete = self.complete()
        complete["steps"] = []
        self.assertErrors(run_case(complete), {Rule.STATUS_COMPLETE_EMPTY})

    def test_not_applicable_with_empty_array_is_accepted(self):
        report = validate_rows([OutputRow("case_x", "NOT_APPLICABLE", "[]", 2)])
        self.assertEqual([str(i) for i in report.issues], [])

    def test_not_applicable_accepts_whitespace_variants_of_empty_array(self):
        for text in ("[]", "[ ]", "[\n]"):
            self.assertTrue(validate_rows([OutputRow("case_x", "NOT_APPLICABLE", text, 2)]).ok, repr(text))

    def test_not_applicable_with_steps_is_rejected(self):
        case = self.complete()
        case["status"] = "NOT_APPLICABLE"
        self.assertErrors(run_case(case), {Rule.STATUS_NOT_APPLICABLE_NONEMPTY})

    def test_not_applicable_with_null_or_object_is_rejected(self):
        for text in ("null", "{}", '""'):
            self.assertErrors(validate_rows([OutputRow("case_x", "NOT_APPLICABLE", text, 2)]), {Rule.JSON_NOT_ARRAY})

    def test_incomplete_missing_a_phase_is_rejected(self):
        for phase in C.PHASES:
            with self.subTest(phase):
                case = self.incomplete()
                case["steps"] = renumber([s for s in case["steps"] if s["phase"] != phase])
                self.assertIn(Rule.STATUS_INCOMPLETE_MISSING_PHASE, errors_of(run_case(case)))

    # ---- finding / remediation / verification relationships ---------------------------------------------------
    def test_remediation_without_matching_verification_is_rejected(self):
        # >=2 verification steps so that deleting one leaves the VERIFICATION phase non-empty
        case = self.incomplete(lambda s: len(phase_steps(s, "REMEDIATION")) >= 1
                               and len(phase_steps(s, "VERIFICATION")) >= 2)
        steps = case["steps"]
        rem = phase_steps(steps, "REMEDIATION")[0]
        want = C.OPERATION_SPEC_BY_NAME[rem["operation"]].state
        steps[:] = renumber([s for s in steps if not (s["phase"] == "VERIFICATION" and s["state"] == want
                                                      and s["system_id"] == rem["system_id"]
                                                      and s["resource_id"] == rem["resource_id"])])
        report = run_case(case)
        self.assertErrors(report, {Rule.REL_VERIFY_MISSING})
        self.assertEqual(report.errors[0].step, steps.index(rem) + 1)

    def test_verification_on_wrong_resource_does_not_satisfy_the_remediation(self):
        case = self.incomplete(lambda s: len(phase_steps(s, "REMEDIATION")) >= 1)
        rem = phase_steps(case["steps"], "REMEDIATION")[0]
        want = C.OPERATION_SPEC_BY_NAME[rem["operation"]].state
        for s in phase_steps(case["steps"], "VERIFICATION"):
            if s["state"] == want and s["resource_id"] == rem["resource_id"]:
                s["resource_id"] = rem["resource_id"] + "9"
        self.assertIn(Rule.REL_VERIFY_MISSING, errors_of(run_case(case)))

    def _drop_remediation_and_its_verification(self, case: Case) -> None:
        steps = case["steps"]
        rem = phase_steps(steps, "REMEDIATION")[0]
        want = C.OPERATION_SPEC_BY_NAME[rem["operation"]].state
        steps[:] = renumber([s for s in steps if s is not rem and not (
            s["phase"] == "VERIFICATION" and s["state"] == want and s["system_id"] == rem["system_id"]
            and s["resource_id"] == rem["resource_id"])])

    def test_finding_without_remediation_is_a_warning_by_default(self):
        case = self.incomplete(lambda s: len(phase_steps(s, "REMEDIATION")) >= 2)
        self._drop_remediation_and_its_verification(case)
        report = run_case(case)
        self.assertTrue(report.ok, [str(i) for i in report.errors])
        self.assertIn(Rule.REL_FINDING_UNREMEDIATED, report.codes(Severity.WARNING))

    def test_pairing_severity_is_configurable(self):
        case = self.incomplete(lambda s: len(phase_steps(s, "REMEDIATION")) >= 2)
        self._drop_remediation_and_its_verification(case)
        self.assertErrors(run_case(case, pairing_severity=Severity.ERROR), {Rule.REL_FINDING_UNREMEDIATED})
        self.assertEqual(run_case(case, pairing_severity=None).issues, [])

    def test_remediation_without_finding_is_a_warning_by_default(self):
        case = self.incomplete(lambda s: len(phase_steps(s, "FINDING")) >= 2)
        steps = case["steps"]
        removed = phase_steps(steps, "FINDING")[0]
        steps[:] = renumber([s for s in steps if s is not removed])
        report = run_case(case)
        self.assertTrue(report.ok, [str(i) for i in report.errors])
        self.assertIn(Rule.REL_REMEDIATION_UNEXPLAINED, report.codes(Severity.WARNING))

    def test_incomplete_with_only_retained_record_verification_is_still_allowed(self):
        # Verification-only extras (e.g. "record present") need no finding/remediation.
        case = self.incomplete()
        n = len(case["steps"]) + 1
        case["steps"].append(make_step(n, "VERIFY_RECORD_PRESENT", "zz_service", "zz_1", ""))
        report = run_case(case)
        self.assertTrue(report.ok, [str(i) for i in report.errors])

    def test_duplicate_step_is_a_warning(self):
        case = self.complete()
        dup = copy.deepcopy(case["steps"][0])
        case["steps"].insert(1, dup)
        renumber(case["steps"])
        report = run_case(case)
        self.assertTrue(report.ok)
        self.assertIn(Rule.STEP_DUPLICATE, report.codes(Severity.WARNING))

    def test_single_case_api_matches_row_api(self):
        case = self.complete()
        case["steps"][0]["evidence_id"] = ""
        report = validate_steps_json(str(case["case_id"]), "COMPLETE", dump(case["steps"]))
        self.assertErrors(report, {Rule.EVIDENCE_REQUIRED})


# --------------------------------------------------------------------------- #
# 4. CSV container structure (all files written to a temp dir)
# --------------------------------------------------------------------------- #
class TestCsvStructure(ContractTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, text: str = "", raw: Optional[bytes] = None, name: str = "out.csv") -> Path:
        path = self.dir / name
        path.write_bytes(raw if raw is not None else text.encode("utf-8"))
        return path

    GOOD_HEADER = "case_id,deletion_status,steps_json\n"

    def test_minimal_valid_file_with_not_applicable_row(self):
        report = validate_csv(self.write(self.GOOD_HEADER + "case_1,NOT_APPLICABLE,[]\n"))
        self.assertEqual([str(i) for i in report.issues], [])

    def test_missing_trailing_newline_and_crlf_are_tolerated(self):
        self.assertTrue(validate_csv(self.write(self.GOOD_HEADER + "case_1,NOT_APPLICABLE,[]")).ok)
        self.assertTrue(validate_csv(self.write("case_id,deletion_status,steps_json\r\ncase_1,NOT_APPLICABLE,[]\r\n")).ok)

    def test_header_variants_are_rejected(self):
        for header in ("case_id,status,steps_json", "deletion_status,case_id,steps_json",
                       "case_id,deletion_status", "case_id,deletion_status,steps_json,extra",
                       "Case_ID,deletion_status,steps_json", " case_id,deletion_status,steps_json"):
            with self.subTest(header):
                report = validate_csv(self.write(header + "\ncase_1,NOT_APPLICABLE,[]\n"))
                self.assertErrors(report, {Rule.CSV_HEADER})

    def test_utf8_bom_is_reported_explicitly(self):
        report = validate_csv(self.write(raw=b"\xef\xbb\xbf" + (self.GOOD_HEADER + "case_1,NOT_APPLICABLE,[]\n").encode()))
        self.assertErrors(report, {Rule.CSV_HEADER})
        self.assertIn("byte-order mark", report.errors[0].message)

    def test_empty_file_is_rejected(self):
        self.assertErrors(validate_csv(self.write("")), {Rule.CSV_HEADER})

    def test_header_only_file_parses_but_fails_expected_counts(self):
        report = validate_csv(self.write(self.GOOD_HEADER), ValidatorConfig(expected_row_count=1))
        self.assertErrors(report, {Rule.ROW_COUNT})

    def test_row_with_wrong_field_count_is_rejected_and_counted(self):
        report = validate_csv(self.write(self.GOOD_HEADER + "case_1,NOT_APPLICABLE\ncase_2,NOT_APPLICABLE,[]\n"),
                              ValidatorConfig(expected_row_count=2))
        self.assertErrors(report, {Rule.CSV_ROW_WIDTH})
        self.assertEqual(report.row_count, 2)
        self.assertEqual(report.errors[0].line, 2)

    def test_unquoted_comma_inside_steps_json_is_rejected(self):
        report = validate_csv(self.write(self.GOOD_HEADER + 'case_1,COMPLETE,[{"a":1},{"b":2}]\n'))
        self.assertIn(Rule.CSV_ROW_WIDTH, errors_of(report))

    def test_blank_line_inside_file_is_rejected(self):
        report = validate_csv(self.write(self.GOOD_HEADER + "case_1,NOT_APPLICABLE,[]\n\ncase_2,NOT_APPLICABLE,[]\n"))
        self.assertErrors(report, {Rule.CSV_BLANK_ROW})

    def test_duplicate_case_id_is_rejected(self):
        report = validate_csv(self.write(self.GOOD_HEADER + "case_1,NOT_APPLICABLE,[]\ncase_1,NOT_APPLICABLE,[]\n"))
        self.assertErrors(report, {Rule.CASE_ID_DUPLICATE})
        self.assertEqual(report.errors[0].case_id, "case_1")

    def test_blank_or_spaced_case_id_is_rejected(self):
        for cid in ("", " case_1", "case 1"):
            with self.subTest(repr(cid)):
                report = validate_csv(self.write(self.GOOD_HEADER + '"%s",NOT_APPLICABLE,[]\n' % cid))
                self.assertIn(Rule.CASE_ID_INVALID, errors_of(report))

    def test_non_utf8_bytes_are_rejected(self):
        report = validate_csv(self.write(raw=self.GOOD_HEADER.encode() + b"case_1,NOT_APPLICABLE,[\xff]\n"))
        self.assertErrors(report, {Rule.FILE_ENCODING})

    def test_missing_file_is_reported(self):
        self.assertErrors(validate_csv(self.dir / "nope.csv"), {Rule.FILE_UNREADABLE})

    def test_stray_quote_is_reported_as_malformed_csv(self):
        report = validate_csv(self.write(self.GOOD_HEADER + 'case_1,"NOT_APPLICABLE,[]\n'))
        self.assertTrue(errors_of(report) & {Rule.CSV_MALFORMED, Rule.CSV_ROW_WIDTH})

    def test_quoted_json_with_embedded_quotes_round_trips(self):
        step = make_step(1, "VERIFY_RECORD_ABSENT", "account_service", "account_1", "evidence_01")
        path = self.dir / "rt.csv"
        with open(path, "w", encoding="utf-8", newline="") as handle:
            w = csv.writer(handle, lineterminator="\n")
            w.writerow(C.CSV_COLUMNS)
            w.writerow(["case_1", "COMPLETE", dump([step])])
        report = validate_csv(path)
        self.assertEqual([str(i) for i in report.issues], [])


# --------------------------------------------------------------------------- #
# 5. Sorting strategies are explicit and configurable
# --------------------------------------------------------------------------- #
class TestSortingConfiguration(ContractTestCase):
    @staticmethod
    def na_rows(ids: List[str]) -> List[OutputRow]:
        return [OutputRow(cid, "NOT_APPLICABLE", "[]", line=i + 2) for i, cid in enumerate(ids)]

    IDS = ["case_9", "case_10", "case_33", "case_100"]

    def lexical_ids(self):
        return sorted(self.IDS)

    def natural_ids(self):
        return sorted(self.IDS, key=natural_key)

    def test_the_two_orders_really_differ_for_this_id_set(self):
        self.assertNotEqual(self.lexical_ids(), self.natural_ids())
        self.assertEqual(self.natural_ids(), ["case_9", "case_10", "case_33", "case_100"])
        self.assertEqual(self.lexical_ids(), ["case_10", "case_100", "case_33", "case_9"])

    def test_lexically_sorted_file(self):
        rows = self.na_rows(self.lexical_ids())
        self.assertTrue(validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.LEXICAL)).ok)
        self.assertErrors(validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.NATURAL)), {Rule.CASE_ORDER})
        either = validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.EITHER))
        self.assertTrue(either.ok)
        self.assertEqual(either.ordering["case_id"], ("lexical",))
        self.assertIn(Rule.ORDER_AMBIGUITY, either.codes(Severity.INFO))

    def test_naturally_sorted_file(self):
        rows = self.na_rows(self.natural_ids())
        self.assertTrue(validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.NATURAL)).ok)
        self.assertErrors(validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.LEXICAL)), {Rule.CASE_ORDER})
        either = validate_rows(rows)
        self.assertTrue(either.ok)
        self.assertEqual(either.ordering["case_id"], ("natural",))

    def test_unsorted_file_fails_unless_ordering_is_disabled(self):
        rows = self.na_rows(["case_33", "case_9", "case_100", "case_10"])
        for strategy in (SortStrategy.LEXICAL, SortStrategy.NATURAL, SortStrategy.EITHER):
            with self.subTest(strategy.value):
                self.assertErrors(validate_rows(rows, ValidatorConfig(case_id_order=strategy)), {Rule.CASE_ORDER})
        self.assertTrue(validate_rows(rows, ValidatorConfig(case_id_order=SortStrategy.NONE)).ok)

    def test_either_does_not_accept_a_file_that_mixes_both_orders(self):
        # lexical-correct start, natural-correct end: no single strategy holds.
        rows = self.na_rows(["case_10", "case_100", "case_9", "case_10x"])
        report = validate_rows(rows)
        self.assertIn(Rule.CASE_ORDER, errors_of(report))

    def test_error_message_names_the_case_and_the_strategy(self):
        report = validate_rows(self.na_rows(["case_10", "case_9"]), ValidatorConfig(case_id_order=SortStrategy.NATURAL))
        issue = report.errors[0]
        self.assertEqual(issue.case_id, "case_9")
        self.assertIn("natural", issue.message)
        self.assertIn("case_10", issue.message)

    # ---- resource ids -------------------------------------------------------------------------
    @staticmethod
    def complete_row(resources: List[str], system: str = "account_service", cid: str = "case_1") -> OutputRow:
        steps = [make_step(i, "VERIFY_RECORD_ABSENT", system, r, "evidence_01") for i, r in enumerate(resources, 1)]
        return OutputRow(cid, "COMPLETE", dump(steps), line=2)

    def test_resource_order_strategies(self):
        natural = self.complete_row(["account_9", "account_10"])
        lexical = self.complete_row(["account_10", "account_9"])
        cases = [
            (natural, SortStrategy.NATURAL, True), (natural, SortStrategy.LEXICAL, False),
            (lexical, SortStrategy.LEXICAL, True), (lexical, SortStrategy.NATURAL, False),
            (natural, SortStrategy.EITHER, True), (lexical, SortStrategy.EITHER, True),
            (natural, SortStrategy.NONE, True), (lexical, SortStrategy.NONE, True),
        ]
        for row, strategy, ok in cases:
            with self.subTest(order=[json.loads(row.steps_json)[0]["resource_id"]], strategy=strategy.value):
                report = validate_rows([row], ValidatorConfig(resource_order=strategy))
                self.assertEqual(report.ok, ok, [str(i) for i in report.issues])

    def test_resource_order_is_file_wide_for_either(self):
        # case A only satisfies natural, case B only satisfies lexical => no single strategy.
        rows = [self.complete_row(["account_9", "account_10"], cid="case_1"),
                self.complete_row(["account_10", "account_9"], cid="case_2")]
        report = validate_rows(rows)
        self.assertIn(Rule.STEP_ORDER_ID, errors_of(report))

    def test_system_id_is_the_primary_key_before_resource_id(self):
        row = OutputRow("case_1", "COMPLETE", dump([
            make_step(1, "VERIFY_RECORD_ABSENT", "search_service", "a_1", "evidence_01"),
            make_step(2, "VERIFY_RECORD_ABSENT", "account_service", "z_1", "evidence_01")]), 2)
        self.assertErrors(validate_rows([row]), {Rule.STEP_ORDER_ID})

    def test_operation_order_outranks_resource_order(self):
        # ABSENT sorts before PRESENT in the table even though 'z' > 'a'.
        row = OutputRow("case_1", "COMPLETE", dump([
            make_step(1, "VERIFY_RECORD_ABSENT", "s", "z_1", "evidence_01"),
            make_step(2, "VERIFY_RECORD_PRESENT", "s", "a_1", "evidence_01")]), 2)
        self.assertTrue(validate_rows([row]).ok)

    def test_sort_keys(self):
        self.assertLess(natural_key("case_9"), natural_key("case_10"))
        self.assertGreater(lexical_key("case_9"), lexical_key("case_10"))
        self.assertNotEqual(natural_key("a_05"), natural_key("a_5"))  # deterministic tie-break
        self.assertEqual(sorted(["a_5", "a_05"], key=natural_key), sorted(["a_05", "a_5"], key=natural_key))


# --------------------------------------------------------------------------- #
# 6. Command line
# --------------------------------------------------------------------------- #
class TestCommandLine(ContractTestCase):
    SCRIPT = CODE_DIR / "validate_output.py"

    def run_cli(self, *args: str, cwd: Optional[Path] = None):
        return subprocess.run([sys.executable, str(self.SCRIPT), *args], capture_output=True, text=True,
                              cwd=str(cwd) if cwd else None)

    @unittest.skipUnless(HAVE_SAMPLE, "dataset sample files not present")
    def test_sample_passes_from_a_different_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cli(str(SAMPLE_OUTPUT), "--requests", str(SAMPLE_REQUESTS), cwd=Path(tmp))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Result: PASS", proc.stdout)
        self.assertIn("Rows: 32", proc.stdout)

    def test_invalid_file_exits_1_and_names_case_rule_and_step(self):
        step = make_step(1, "VERIFY_RECORD_ABSENT", "account_service", "account_1", "")  # evidence missing
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.csv"
            with open(path, "w", encoding="utf-8", newline="") as handle:
                w = csv.writer(handle, lineterminator="\n")
                w.writerow(C.CSV_COLUMNS)
                w.writerow(["case_77", "COMPLETE", dump([step])])
            proc = self.run_cli(str(path))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("case_id=case_77", proc.stdout)
        self.assertIn("step 1", proc.stdout)
        self.assertIn(Rule.EVIDENCE_REQUIRED, proc.stdout)
        self.assertIn("Result: FAIL", proc.stdout)

    def test_missing_requests_file_is_a_usage_error(self):
        proc = self.run_cli("--requests", str(Path(tempfile.gettempdir()) / "definitely_missing_requests.csv"))
        self.assertEqual(proc.returncode, 2)

    def test_pinning_one_strategy_changes_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lex.csv"
            path.write_text("case_id,deletion_status,steps_json\ncase_10,NOT_APPLICABLE,[]\ncase_9,NOT_APPLICABLE,[]\n",
                            encoding="utf-8")
            self.assertEqual(self.run_cli(str(path), "--case-order", "lexical").returncode, 0)
            self.assertEqual(self.run_cli(str(path), "--case-order", "natural").returncode, 1)
            either = self.run_cli(str(path))
        self.assertEqual(either.returncode, 0)
        self.assertIn("Ordering (case_id): lexical satisfied", either.stdout)
        self.assertIn("ORDER_AMBIGUITY", either.stdout)


if __name__ == "__main__":
    unittest.main()
