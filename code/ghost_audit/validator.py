"""Strict, evidence-free validator for ``output.csv`` (Stage 0).

What this module checks: the *shape* of the submission as specified by
``problem_statement.md``, ``AGENTS.md`` section 6.3-6.6 and ``README.md``.
What it cannot check (needs evidence, later stages): whether a cited ID exists,
whether evidence was captured at or before ``audit_at``, whether a resource
belongs to the subject, whether the status itself is correct, or whether the
findings are complete. See ``ghost_audit/README.md``.

Every issue carries a stable rule code, the case_id, the step position when
relevant, and the CSV line, so failures can be located without re-reading code.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Collection,
    Dict,
    FrozenSet,
    List,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
    Union,
)

from . import contracts as C
from .ordering import (
    CONCRETE_STRATEGIES,
    DEFAULT_CASE_ID_ORDER,
    DEFAULT_RESOURCE_ORDER,
    SortStrategy,
    concrete_strategies,
    sort_key,
)


# --------------------------------------------------------------------------- #
# Issues and reports
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    ERROR = "ERROR"      # the submission violates the contract
    WARNING = "WARNING"  # suspicious / implied-but-unstated; does not fail
    INFO = "INFO"        # something worth knowing, e.g. ordering ambiguity


class Rule:
    """Stable rule codes (documented in ghost_audit/README.md)."""

    # file / CSV structure
    FILE_UNREADABLE = "FILE_UNREADABLE"
    FILE_ENCODING = "FILE_ENCODING"
    CSV_MALFORMED = "CSV_MALFORMED"
    CSV_HEADER = "CSV_HEADER"
    CSV_ROW_WIDTH = "CSV_ROW_WIDTH"
    CSV_BLANK_ROW = "CSV_BLANK_ROW"
    # case rows
    CASE_ID_INVALID = "CASE_ID_INVALID"
    CASE_ID_DUPLICATE = "CASE_ID_DUPLICATE"
    CASE_ID_MISSING = "CASE_ID_MISSING"
    CASE_ID_UNEXPECTED = "CASE_ID_UNEXPECTED"
    ROW_COUNT = "ROW_COUNT"
    CASE_ORDER = "CASE_ORDER"
    STATUS_INVALID = "STATUS_INVALID"
    # steps_json parsing and step schema
    JSON_MALFORMED = "JSON_MALFORMED"
    JSON_NOT_ARRAY = "JSON_NOT_ARRAY"
    JSON_DUPLICATE_KEY = "JSON_DUPLICATE_KEY"
    STEP_NOT_OBJECT = "STEP_NOT_OBJECT"
    STEP_KEYS = "STEP_KEYS"
    STEP_FIELD_TYPE = "STEP_FIELD_TYPE"
    STEP_FIELD_VALUE = "STEP_FIELD_VALUE"
    STEP_NO_SEQUENCE = "STEP_NO_SEQUENCE"
    STEP_PHASE_INVALID = "STEP_PHASE_INVALID"
    STEP_OPERATION_INVALID = "STEP_OPERATION_INVALID"
    STEP_STATE_INVALID = "STEP_STATE_INVALID"
    STEP_COMBINATION = "STEP_COMBINATION"
    STEP_DUPLICATE = "STEP_DUPLICATE"
    # ordering
    STEP_ORDER_PHASE = "STEP_ORDER_PHASE"
    STEP_ORDER_OPERATION = "STEP_ORDER_OPERATION"
    STEP_ORDER_ID = "STEP_ORDER_ID"
    ORDER_AMBIGUITY = "ORDER_AMBIGUITY"
    # status-specific
    STATUS_NOT_APPLICABLE_NONEMPTY = "STATUS_NOT_APPLICABLE_NONEMPTY"
    STATUS_COMPLETE_EMPTY = "STATUS_COMPLETE_EMPTY"
    STATUS_PHASE_NOT_ALLOWED = "STATUS_PHASE_NOT_ALLOWED"
    STATUS_INCOMPLETE_MISSING_PHASE = "STATUS_INCOMPLETE_MISSING_PHASE"
    # evidence_id
    EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
    EVIDENCE_MUST_BE_EMPTY = "EVIDENCE_MUST_BE_EMPTY"
    EVIDENCE_FORMAT = "EVIDENCE_FORMAT"
    # relationships (INCOMPLETE)
    REL_VERIFY_MISSING = "REL_VERIFY_MISSING"
    REL_FINDING_UNREMEDIATED = "REL_FINDING_UNREMEDIATED"
    REL_REMEDIATION_UNEXPLAINED = "REL_REMEDIATION_UNEXPLAINED"


def _q(value: Any) -> str:
    """Quote a value for a message. ``ascii`` keeps Windows consoles safe."""
    return ascii(value)


@dataclass(frozen=True)
class Issue:
    severity: Severity
    code: str
    message: str
    case_id: Optional[str] = None
    step: Optional[int] = None  # 1-based position in the steps_json array
    line: Optional[int] = None  # line in the CSV file (when read from a file)

    def __str__(self) -> str:
        where = []
        if self.case_id is not None:
            where.append("case_id=%s" % self.case_id)
        if self.step is not None:
            where.append("step %d" % self.step)
        if self.line is not None:
            where.append("line %d" % self.line)
        loc = " (%s)" % ", ".join(where) if where else ""
        return "[%s] %s%s: %s" % (self.severity.value, self.code, loc, self.message)


@dataclass
class ValidationReport:
    issues: List[Issue] = field(default_factory=list)
    row_count: int = 0
    case_count: int = 0
    # axis name -> concrete strategies the file satisfied ("case_id", "resource_id")
    ordering: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    @property
    def errors(self) -> List[Issue]:
        return [i for i in self.issues if i.severity is Severity.ERROR]

    @property
    def warnings(self) -> List[Issue]:
        return [i for i in self.issues if i.severity is Severity.WARNING]

    @property
    def infos(self) -> List[Issue]:
        return [i for i in self.issues if i.severity is Severity.INFO]

    @property
    def ok(self) -> bool:
        return not self.errors

    def codes(self, severity: Optional[Severity] = None) -> Set[str]:
        return {i.code for i in self.issues if severity is None or i.severity is severity}

    def summary(self) -> str:
        return "%d errors, %d warnings, %d notices" % (
            len(self.errors),
            len(self.warnings),
            len(self.infos),
        )


# --------------------------------------------------------------------------- #
# Configuration and input rows
# --------------------------------------------------------------------------- #
@dataclass
class ValidatorConfig:
    """Knobs. Defaults implement exactly what the repository states."""

    # Sorting is NOT settled by the repository -> explicit, defaulting to EITHER.
    case_id_order: SortStrategy = DEFAULT_CASE_ID_ORDER
    resource_order: SortStrategy = DEFAULT_RESOURCE_ORDER
    # Shape of citable IDs; None disables the shape check.
    evidence_id_pattern: Optional[Pattern[str]] = C.DEFAULT_EVIDENCE_ID_PATTERN
    # Severity of finding<->remediation pairing diagnostics (implied, not
    # stated, by the contract). None switches them off.
    pairing_severity: Optional[Severity] = Severity.WARNING
    # If given, the file must contain exactly these case_ids (no more, no less).
    expected_case_ids: Optional[Collection[str]] = None
    # If given, the number of data rows must equal this (518 for the real run).
    expected_row_count: Optional[int] = None


@dataclass(frozen=True)
class OutputRow:
    case_id: str
    deletion_status: str
    steps_json: str
    line: Optional[int] = None


# --------------------------------------------------------------------------- #
# Ordering bookkeeping (resolved once per file so EITHER can be file-wide)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _OrderObs:
    """One adjacent pair that violates at least one concrete strategy."""

    axis: str                      # "case_id" or "resource_id"
    case_id: Optional[str]
    step: Optional[int]
    line: Optional[int]
    left: str
    right: str
    violates: FrozenSet[SortStrategy]


def _pair_violations(left: str, right: str) -> FrozenSet[SortStrategy]:
    return frozenset(
        s for s in CONCRETE_STRATEGIES if sort_key(s, left) > sort_key(s, right)
    )


def _tuple_violations(
    left: Tuple[str, str], right: Tuple[str, str]
) -> FrozenSet[SortStrategy]:
    out = set()
    for s in CONCRETE_STRATEGIES:
        lk = (sort_key(s, left[0]), sort_key(s, left[1]))
        rk = (sort_key(s, right[0]), sort_key(s, right[1]))
        if lk > rk:
            out.add(s)
    return frozenset(out)


def _resolve_order(
    observations: Sequence[_OrderObs],
    configured: SortStrategy,
    axis: str,
    rule_code: str,
    describe: Any,
) -> Tuple[List[Issue], Tuple[str, ...]]:
    """Turn raw pair observations into issues for one axis.

    A concrete strategy is *satisfied* if no observation violates it. The axis
    passes if at least one accepted strategy is satisfied.
    """
    accepted = concrete_strategies(configured)
    if not accepted:  # NONE: axis not checked
        return [], ()
    satisfied = tuple(s for s in accepted if not any(s in o.violates for o in observations))
    issues: List[Issue] = []
    if not satisfied:
        names = "/".join(s.value for s in accepted)
        for o in observations:
            hit = [s.value for s in accepted if s in o.violates]
            if not hit:
                continue
            tail = (
                " No single strategy (%s) is satisfied by the whole file; pick one and "
                "apply it consistently." % names
                if configured is SortStrategy.EITHER
                else ""
            )
            issues.append(
                Issue(
                    Severity.ERROR,
                    rule_code,
                    "%s follows %s but sorts before it under %s ordering.%s"
                    % (describe(o.right), describe(o.left), " and ".join(hit), tail),
                    o.case_id,
                    o.step,
                    o.line,
                )
            )
    elif configured is SortStrategy.EITHER and len(satisfied) == 1:
        other = [s.value for s in accepted if s not in satisfied][0]
        example = next((o for o in observations if satisfied[0] not in o.violates), None)
        detail = (
            " (e.g. %s then %s breaks %s order)" % (describe(example.left), describe(example.right), other)
            if example
            else ""
        )
        issues.append(
            Issue(
                Severity.INFO,
                Rule.ORDER_AMBIGUITY,
                "%s ordering: the file satisfies only %s ordering%s. The repository does not say "
                "which is intended; pin one with --%s-order." % (axis, satisfied[0].value, detail,
                                                                  "case" if axis == "case_id" else "resource"),
            )
        )
    return issues, tuple(s.value for s in satisfied)


# --------------------------------------------------------------------------- #
# steps_json parsing
# --------------------------------------------------------------------------- #
class _JsonError(Exception):
    pass


def _parse_steps_json(text: str) -> Tuple[Optional[list], List[str], Optional[str]]:
    """Parse ``text``. Returns (value, duplicate_keys, error_message)."""
    duplicates: List[str] = []

    def hook(pairs):
        obj: Dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                duplicates.append(key)
            obj[key] = value
        return obj

    def reject_constant(name):
        raise _JsonError("non-standard JSON constant %s is not allowed" % name)

    try:
        value = json.loads(text, object_pairs_hook=hook, parse_constant=reject_constant)
    except _JsonError as exc:
        return None, duplicates, str(exc)
    except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
        return None, duplicates, str(exc)
    return value, duplicates, None


@dataclass(frozen=True)
class _Step:
    pos: int  # 1-based position in the array
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


# --------------------------------------------------------------------------- #
# Per-case validation
# --------------------------------------------------------------------------- #
def _check_case(
    row: OutputRow, config: ValidatorConfig
) -> Tuple[List[Issue], List[_OrderObs]]:
    issues: List[Issue] = []
    obs: List[_OrderObs] = []
    cid, line = row.case_id, row.line

    def add(sev: Severity, code: str, msg: str, step: Optional[int] = None) -> None:
        issues.append(Issue(sev, code, msg, cid, step, line))

    status = row.deletion_status
    status_ok = status in C.DELETION_STATUSES
    if not status_ok:
        add(
            Severity.ERROR,
            Rule.STATUS_INVALID,
            "deletion_status %s is not one of %s (exact, upper-case match)."
            % (_q(status), ", ".join(C.DELETION_STATUSES)),
        )

    # ---- parse steps_json -------------------------------------------------
    value, duplicates, err = _parse_steps_json(row.steps_json)
    for key in dict.fromkeys(duplicates):
        add(Severity.ERROR, Rule.JSON_DUPLICATE_KEY,
            "a JSON object in steps_json repeats the key %s; keys must be unique." % _q(key))
    if err is not None:
        add(Severity.ERROR, Rule.JSON_MALFORMED, "steps_json is not valid JSON: %s" % err)
        return issues, obs
    if not isinstance(value, list):
        add(Severity.ERROR, Rule.JSON_NOT_ARRAY,
            "steps_json must be a JSON array, found %s." % type(value).__name__)
        return issues, obs

    # ---- per-step schema --------------------------------------------------
    steps: List[Optional[_Step]] = []
    declared_numbers: List[Tuple[int, Any]] = []  # (pos, step_no) for int step_no
    for idx, raw in enumerate(value):
        pos = idx + 1
        if not isinstance(raw, dict):
            add(Severity.ERROR, Rule.STEP_NOT_OBJECT,
                "step must be a JSON object, found %s." % type(raw).__name__, pos)
            steps.append(None)
            continue
        if isinstance(raw.get("step_no"), int) and not isinstance(raw.get("step_no"), bool):
            declared_numbers.append((pos, raw["step_no"]))
        keys = set(raw)
        missing = [k for k in C.STEP_KEYS if k not in keys]
        extra = sorted(keys - set(C.STEP_KEYS))
        if missing or extra:
            parts = []
            if missing:
                parts.append("missing %s" % ", ".join(missing))
            if extra:
                parts.append("unexpected %s" % ", ".join(_q(k) for k in extra))
            add(Severity.ERROR, Rule.STEP_KEYS,
                "step must have exactly the keys %s; %s." % (", ".join(C.STEP_KEYS), "; ".join(parts)),
                pos)
        type_ok = True
        sn = raw.get("step_no")
        if "step_no" in raw and (not isinstance(sn, int) or isinstance(sn, bool)):
            add(Severity.ERROR, Rule.STEP_FIELD_TYPE,
                "step_no must be an integer, found %s %s." % (type(sn).__name__, _q(sn)), pos)
            type_ok = False
        for key in C.STEP_STRING_KEYS:
            if key in raw and not isinstance(raw[key], str):
                add(Severity.ERROR, Rule.STEP_FIELD_TYPE,
                    "%s must be a string, found %s %s." % (key, type(raw[key]).__name__, _q(raw[key])), pos)
                type_ok = False
        if missing or extra or not type_ok:
            steps.append(None)
            continue
        for key in ("system_id", "resource_id"):
            v = raw[key]
            if v == "" or v != v.strip():
                add(Severity.ERROR, Rule.STEP_FIELD_VALUE,
                    "%s must be a non-empty string without leading/trailing whitespace, found %s."
                    % (key, _q(v)), pos)
        steps.append(_Step(pos, raw["step_no"], raw["phase"], raw["system_id"], raw["resource_id"],
                           raw["operation"], raw["state"], raw["evidence_id"]))

    typed = [s for s in steps if s is not None]

    # ---- step_no must be 1..n ---------------------------------------------
    bad = [(pos, n) for pos, n in declared_numbers if n != pos]
    if bad:
        pos, n = bad[0]
        more = " (%d more step(s) also out of sequence)" % (len(bad) - 1) if len(bad) > 1 else ""
        add(Severity.ERROR, Rule.STEP_NO_SEQUENCE,
            "step_no is %d but must be %d: numbers start at 1 and increase by 1 in array order%s."
            % (n, pos, more), pos)

    # ---- phase / operation / state ----------------------------------------
    usable: List[_Step] = []  # steps with a known phase AND a known operation
    for s in typed:
        phase_ok = s.phase in C.PHASE_RANK
        op_ok = s.operation in C.OPERATION_SPEC_BY_NAME
        state_ok = s.state in C.ALL_STATES
        if not phase_ok:
            add(Severity.ERROR, Rule.STEP_PHASE_INVALID,
                "phase %s is not one of %s." % (_q(s.phase), ", ".join(C.PHASES)), s.pos)
        if not op_ok:
            add(Severity.ERROR, Rule.STEP_OPERATION_INVALID,
                "operation %s is not an allowed operation." % _q(s.operation), s.pos)
        if not state_ok:
            add(Severity.ERROR, Rule.STEP_STATE_INVALID,
                "state %s is not an allowed state (%s)." % (_q(s.state), ", ".join(sorted(C.ALL_STATES))), s.pos)
        if op_ok:
            spec = C.OPERATION_SPEC_BY_NAME[s.operation]
            wrong_phase = phase_ok and s.phase != spec.phase
            wrong_state = state_ok and s.state != spec.state
            if wrong_phase or wrong_state:
                add(Severity.ERROR, Rule.STEP_COMBINATION,
                    "invalid phase/operation/state combination phase=%s operation=%s state=%s; "
                    "the contract allows only phase=%s operation=%s state=%s."
                    % (s.phase, s.operation, s.state, spec.phase, spec.operation, spec.state), s.pos)
        if phase_ok and op_ok:
            usable.append(s)

    # ---- ordering: phase, operation, then system_id/resource_id ------------
    for prev, cur in zip(usable, usable[1:]):
        if C.PHASE_RANK[cur.phase] < C.PHASE_RANK[prev.phase]:
            add(Severity.ERROR, Rule.STEP_ORDER_PHASE,
                "phase %s appears after %s (step %d); the order is %s."
                % (cur.phase, prev.phase, prev.pos, " -> ".join(C.PHASES)), cur.pos)
            continue
        if cur.phase != prev.phase:
            continue
        rp, rc = C.OPERATION_RANK[prev.operation], C.OPERATION_RANK[cur.operation]
        if rc < rp:
            add(Severity.ERROR, Rule.STEP_ORDER_OPERATION,
                "operation %s appears after %s (step %d) but precedes it in the contract's "
                "operation table." % (cur.operation, prev.operation, prev.pos), cur.pos)
        elif rc == rp:
            violates = _tuple_violations((prev.system_id, prev.resource_id), (cur.system_id, cur.resource_id))
            if violates:
                obs.append(_OrderObs("resource_id", cid, cur.pos, line,
                                     "%s/%s" % (prev.system_id, prev.resource_id),
                                     "%s/%s" % (cur.system_id, cur.resource_id), violates))
    seen: Dict[Tuple[str, str, str, str], int] = {}
    for s in usable:
        key = (s.phase, s.operation, s.system_id, s.resource_id)
        if key in seen:
            add(Severity.WARNING, Rule.STEP_DUPLICATE,
                "same phase/operation/system_id/resource_id as step %d; the contract does not say "
                "whether duplicates are allowed." % seen[key], s.pos)
        else:
            seen[key] = s.pos

    # ---- status-specific structure -----------------------------------------
    if status_ok:
        if status == C.STATUS_NOT_APPLICABLE:
            if value:
                add(Severity.ERROR, Rule.STATUS_NOT_APPLICABLE_NONEMPTY,
                    "NOT_APPLICABLE requires steps_json to be an empty array [], found %d step(s)." % len(value))
        elif status == C.STATUS_COMPLETE:
            if not value:
                add(Severity.ERROR, Rule.STATUS_COMPLETE_EMPTY,
                    "COMPLETE must include verification steps proving the current state; steps_json is empty.")
            for s in typed:
                if s.phase in C.PHASE_RANK and s.phase not in C.STATUS_ALLOWED_PHASES[status]:
                    add(Severity.ERROR, Rule.STATUS_PHASE_NOT_ALLOWED,
                        "COMPLETE allows only VERIFICATION steps, found phase %s." % s.phase, s.pos)
        else:  # INCOMPLETE
            present = {s.phase for s in typed}
            for phase in C.PHASES:
                if phase not in present:
                    add(Severity.ERROR, Rule.STATUS_INCOMPLETE_MISSING_PHASE,
                        "INCOMPLETE must include findings, a remediation plan and verification checks; "
                        "no %s step found." % phase)

    # ---- evidence_id -------------------------------------------------------
    if status_ok:
        for s in typed:
            rule = C.EVIDENCE_RULES.get((status, s.phase))
            if rule is C.EvidenceRule.EMPTY and s.evidence_id != "":
                add(Severity.ERROR, Rule.EVIDENCE_MUST_BE_EMPTY,
                    "%s %s step in an INCOMPLETE case is future work and must use evidence_id \"\", found %s."
                    % (s.phase, s.operation, _q(s.evidence_id)), s.pos)
            elif rule is C.EvidenceRule.REQUIRED:
                if s.evidence_id == "":
                    add(Severity.ERROR, Rule.EVIDENCE_REQUIRED,
                        "%s step in a %s case must cite a file_id, activity_id or audit_id; evidence_id is empty."
                        % (s.phase, status), s.pos)
                elif config.evidence_id_pattern is not None and not config.evidence_id_pattern.fullmatch(s.evidence_id):
                    add(Severity.ERROR, Rule.EVIDENCE_FORMAT,
                        "evidence_id %s does not look like a file_id/activity_id/audit_id (pattern %s)."
                        % (_q(s.evidence_id), config.evidence_id_pattern.pattern), s.pos)

    # ---- INCOMPLETE relationships -------------------------------------------
    if status == C.STATUS_INCOMPLETE:
        _check_relationships(usable, config, add)

    return issues, obs


def _check_relationships(usable: Sequence[_Step], config: ValidatorConfig, add) -> None:
    findings = [s for s in usable if s.phase == C.PHASE_FINDING]
    remediations = [s for s in usable if s.phase == C.PHASE_REMEDIATION]
    verifications = [s for s in usable if s.phase == C.PHASE_VERIFICATION]

    # EXPLICIT (AGENTS.md 6.5): every remediated record/process is verified in
    # its required final state. Remediation state == verification state.
    verified = {(v.system_id, v.resource_id, v.state) for v in verifications}
    for r in remediations:
        want = C.OPERATION_SPEC_BY_NAME[r.operation].state
        if (r.system_id, r.resource_id, want) not in verified:
            add(Severity.ERROR, Rule.REL_VERIFY_MISSING,
                "remediation %s on %s/%s has no VERIFICATION step with state %s on the same "
                "system_id/resource_id (AGENTS.md 6.5: verification must cover the required final state)."
                % (r.operation, r.system_id, r.resource_id, want), r.pos)

    # IMPLIED (not stated): pair findings with remediations. Severity is configurable.
    sev = config.pairing_severity
    if sev is None:
        return
    for f in findings:
        allowed = C.FINDING_REMEDIATION_PAIRS[f.operation]
        if not any(r.system_id == f.system_id and r.resource_id == f.resource_id
                   and r.operation in allowed for r in remediations):
            add(sev, Rule.REL_FINDING_UNREMEDIATED,
                "finding %s on %s/%s has no matching remediation (%s) on the same resource."
                % (f.operation, f.system_id, f.resource_id, " or ".join(sorted(allowed))), f.pos)
    for r in remediations:
        if not any(f.system_id == r.system_id and f.resource_id == r.resource_id
                   and r.operation in C.FINDING_REMEDIATION_PAIRS[f.operation] for f in findings):
            add(sev, Rule.REL_REMEDIATION_UNEXPLAINED,
                "remediation %s on %s/%s has no matching finding on the same resource."
                % (r.operation, r.system_id, r.resource_id), r.pos)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def validate_rows(
    rows: Sequence[OutputRow],
    config: Optional[ValidatorConfig] = None,
    total_data_rows: Optional[int] = None,
) -> ValidationReport:
    """Validate already-parsed rows (header/width checks are done by validate_csv).

    ``total_data_rows`` lets validate_csv report rows it had to skip; by default
    it is ``len(rows)``.
    """
    config = config or ValidatorConfig()
    total = len(rows) if total_data_rows is None else total_data_rows
    report = ValidationReport(row_count=total)
    case_obs: List[_OrderObs] = []
    step_obs: List[_OrderObs] = []
    first_line: Dict[str, Optional[int]] = {}
    ordered_ids: List[OutputRow] = []

    for row in rows:
        cid = row.case_id
        if cid == "" or cid != cid.strip() or any(ch.isspace() for ch in cid):
            report.issues.append(Issue(Severity.ERROR, Rule.CASE_ID_INVALID,
                                       "case_id %s must be non-empty and contain no whitespace." % _q(cid),
                                       cid or None, None, row.line))
        elif cid in first_line:
            report.issues.append(Issue(Severity.ERROR, Rule.CASE_ID_DUPLICATE,
                                       "case_id appears more than once (first at line %s); exactly one row per case."
                                       % first_line[cid], cid, None, row.line))
        else:
            first_line[cid] = row.line
            ordered_ids.append(row)
        issues, obs = _check_case(row, config)
        report.issues.extend(issues)
        step_obs.extend(obs)
    report.case_count = len(first_line)

    # expected cases / row count
    if config.expected_case_ids is not None:
        expected = set(config.expected_case_ids)
        missing = sorted(expected - set(first_line))
        extra = sorted(set(first_line) - expected)
        if missing:
            report.issues.append(Issue(Severity.ERROR, Rule.CASE_ID_MISSING,
                "%d expected case_id(s) have no row, e.g. %s." % (len(missing), ", ".join(missing[:5]))))
        if extra:
            report.issues.append(Issue(Severity.ERROR, Rule.CASE_ID_UNEXPECTED,
                "%d row(s) have a case_id not in the request file, e.g. %s." % (len(extra), ", ".join(extra[:5]))))
    if config.expected_row_count is not None and total != config.expected_row_count:
        report.issues.append(Issue(Severity.ERROR, Rule.ROW_COUNT,
            "expected %d data rows but found %d." % (config.expected_row_count, total)))

    # case_id order (file-wide)
    for prev, cur in zip(ordered_ids, ordered_ids[1:]):
        v = _pair_violations(prev.case_id, cur.case_id)
        if v:
            case_obs.append(_OrderObs("case_id", cur.case_id, None, cur.line, prev.case_id, cur.case_id, v))
    desc = lambda x: _q(x)  # noqa: E731
    issues, satisfied = _resolve_order(case_obs, config.case_id_order, "case_id", Rule.CASE_ORDER, desc)
    report.issues.extend(issues)
    report.ordering["case_id"] = satisfied

    # resource_id order (file-wide)
    issues, satisfied = _resolve_order(step_obs, config.resource_order, "resource_id", Rule.STEP_ORDER_ID, desc)
    report.issues.extend(issues)
    report.ordering["resource_id"] = satisfied
    return report


def validate_steps_json(
    case_id: str,
    deletion_status: str,
    steps_json: str,
    config: Optional[ValidatorConfig] = None,
) -> ValidationReport:
    """Validate a single case (no file-level checks other than resource order)."""
    config = config or ValidatorConfig()
    issues, obs = _check_case(OutputRow(case_id, deletion_status, steps_json), config)
    report = ValidationReport(issues=issues, row_count=1, case_count=1)
    more, satisfied = _resolve_order(obs, config.resource_order, "resource_id", Rule.STEP_ORDER_ID, _q)
    report.issues.extend(more)
    report.ordering["resource_id"] = satisfied
    return report


def read_csv_rows(path: Union[str, Path]) -> Tuple[List[OutputRow], List[Issue], int]:
    """Parse the CSV container.

    Returns (well-formed rows, structural issues, number of data rows seen). The
    last number also counts rows skipped for a bad width or blank line.
    """
    issues: List[Issue] = []
    rows: List[OutputRow] = []
    seen = 0
    try:
        # utf-8 (not utf-8-sig) on purpose: a BOM must show up and be reported.
        with open(path, "r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            header: Optional[List[str]] = None
            try:
                for record in reader:
                    line = reader.line_num
                    if header is None:
                        header = record
                        if record and record[0].startswith("\ufeff"):
                            issues.append(Issue(Severity.ERROR, Rule.CSV_HEADER,
                                "file starts with a UTF-8 byte-order mark; write plain UTF-8 so the first "
                                "column is exactly 'case_id'.", None, None, line))
                        elif record != list(C.CSV_COLUMNS):
                            issues.append(Issue(Severity.ERROR, Rule.CSV_HEADER,
                                "header must be exactly %s in that order, found %s."
                                % (",".join(C.CSV_COLUMNS), ",".join(_q(c) for c in record)), None, None, line))
                        if issues:
                            return rows, issues, seen
                        continue
                    seen += 1
                    if not record:
                        issues.append(Issue(Severity.ERROR, Rule.CSV_BLANK_ROW,
                            "blank line inside the file; every row must be case_id,deletion_status,steps_json.",
                            None, None, line))
                        continue
                    if len(record) != len(C.CSV_COLUMNS):
                        issues.append(Issue(Severity.ERROR, Rule.CSV_ROW_WIDTH,
                            "row has %d field(s), expected %d (unquoted comma inside steps_json?)."
                            % (len(record), len(C.CSV_COLUMNS)), record[0] or None, None, line))
                        continue
                    rows.append(OutputRow(record[0], record[1], record[2], line))
            except csv.Error as exc:
                issues.append(Issue(Severity.ERROR, Rule.CSV_MALFORMED,
                                    "CSV could not be parsed: %s" % exc, None, None, reader.line_num))
                return rows, issues, seen
            if header is None:
                issues.append(Issue(Severity.ERROR, Rule.CSV_HEADER,
                                    "file is empty; expected header %s." % ",".join(C.CSV_COLUMNS)))
    except UnicodeDecodeError as exc:
        issues.append(Issue(Severity.ERROR, Rule.FILE_ENCODING, "file is not valid UTF-8: %s" % exc))
    except OSError as exc:
        issues.append(Issue(Severity.ERROR, Rule.FILE_UNREADABLE, "cannot read file: %s" % exc))
    return rows, issues, seen


def validate_csv(path: Union[str, Path], config: Optional[ValidatorConfig] = None) -> ValidationReport:
    """Validate ``output.csv`` (or any file in the same format)."""
    rows, structural, seen = read_csv_rows(path)
    fatal = (Rule.FILE_UNREADABLE, Rule.FILE_ENCODING, Rule.CSV_HEADER, Rule.CSV_MALFORMED)
    if any(i.code in fatal for i in structural):
        return ValidationReport(issues=structural, row_count=seen)
    report = validate_rows(rows, config, total_data_rows=seen)
    report.issues[0:0] = structural
    return report
