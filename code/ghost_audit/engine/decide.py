"""Case decision: applicability -> identity -> linked evidence -> assessments -> status and ordered steps.

Status policy (AGENTS.md 6.5):
* ``NOT_APPLICABLE`` (``[]``) when the request text does not authorize deletion;
* ``INCOMPLETE`` when at least one supported violation exists (remaining record, exposed PII, active data flow,
  unsafe restore path): findings cite their evidence, remediation and the matching verification are future work
  (empty ``evidence_id``);
* ``COMPLETE`` only when no violation is supported and at least one required final state is PROVEN by cited evidence;
* a case with neither a violation nor any proof is reported as ``unproven`` (see ``fallback``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..contracts import OPERATION_RANK, OPERATION_SPEC_BY_NAME, PHASE_RANK
from ..ordering import SortStrategy, sort_key
from .applicability import Applicability, classify_request
from .assess import Assessment, assess_resource
from .corpus import Corpus
from .identity import IdentityDirectory, Resolution
from .linking import SubjectView, link_subject
from .policy import Rules

FALLBACK_NOTE = "unproven: no violation and no proof could be established from eligible, linked evidence"


@dataclass
class CaseDecision:
    case_id: str
    status: str
    steps: List[Dict[str, object]] = field(default_factory=list)
    applicability: Optional[Applicability] = None
    resolution: Optional[Resolution] = None
    view: Optional[SubjectView] = None
    assessments: List[Assessment] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _step(phase: str, op: str, system: str, resource: str, evidence: str) -> Dict[str, object]:
    spec = OPERATION_SPEC_BY_NAME[op]
    assert spec.phase == phase
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource, "operation": op, "state": spec.state, "evidence_id": evidence}


def order_steps(steps: List[Dict[str, object]], strategy: SortStrategy = SortStrategy.LEXICAL) -> List[Dict[str, object]]:
    """Contract order: phase, operation table order, then system_id and resource_id; step_no renumbered from 1."""
    strat = SortStrategy.LEXICAL if strategy not in (SortStrategy.LEXICAL, SortStrategy.NATURAL) else strategy
    seen, uniq = set(), []
    for s in steps:                                   # one step per (phase, operation, system, resource)
        k = (s["phase"], s["operation"], s["system_id"], s["resource_id"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    uniq.sort(key=lambda s: (PHASE_RANK[s["phase"]], OPERATION_RANK[s["operation"]], sort_key(strat, str(s["system_id"])), sort_key(strat, str(s["resource_id"]))))
    for i, s in enumerate(uniq, 1):
        s["step_no"] = i
    return uniq


def build_steps(assessments: List[Assessment], status: str, strategy: SortStrategy = SortStrategy.LEXICAL) -> List[Dict[str, object]]:
    steps: List[Dict[str, object]] = []
    if status == "INCOMPLETE":
        for a in assessments:
            if a.verdict == "violation":
                steps.append(_step("FINDING", a.finding_op, a.system_id, a.resource_id, a.cite))
                steps.append(_step("REMEDIATION", a.remediation_op, a.system_id, a.resource_id, ""))
                steps.append(_step("VERIFICATION", a.verify_op, a.system_id, a.resource_id, ""))
            elif a.verdict == "retained":
                steps.append(_step("VERIFICATION", a.verify_op, a.system_id, a.resource_id, ""))
            elif a.verdict == "compliant" and a.category == "USER_PROFILE":      # the account must stay gone after remediation
                steps.append(_step("VERIFICATION", a.verify_op, a.system_id, a.resource_id, ""))
    elif status == "COMPLETE":
        for a in assessments:
            if a.verdict in ("compliant", "retained") and a.cite:
                steps.append(_step("VERIFICATION", a.verify_op, a.system_id, a.resource_id, a.cite))
    return order_steps(steps, strategy)


class AuditEngine:
    def __init__(self, dataset_dir, corpus: Optional[Corpus] = None, cache=None,
                 strategy: SortStrategy = SortStrategy.LEXICAL) -> None:
        self.dataset_dir = dataset_dir
        self.directory = IdentityDirectory.from_dataset(dataset_dir)
        self.rules = Rules.load(dataset_dir)
        self.corpus = corpus or Corpus.load(dataset_dir, cache=cache)
        self.strategy = strategy
        self.file_text = getattr(self.corpus, "file_text", {})

    def decide(self, case: Dict[str, str]) -> CaseDecision:
        d = CaseDecision(case["case_id"], "NOT_APPLICABLE")
        d.applicability = classify_request(case["request_text"])
        if not d.applicability.authorized:
            d.notes.append(d.applicability.reason)
            return d
        d.resolution = self.directory.resolve(case["email"], case["audit_at"])
        if d.resolution.status != "resolved":
            d.status = "INCOMPLETE"
            d.notes.append("identity %s: %s" % (d.resolution.status, d.resolution.candidates))
            return self._fallback(d, case)
        d.view = link_subject(self.corpus, self.directory, d.resolution, case)
        d.notes.extend(d.view.notes)
        for lr in d.view.usable():
            a = assess_resource(lr, self.rules, case["audit_at"], self.file_text, self.corpus, case["requested_at"])
            if a is not None and a.verdict != "unknown":
                d.assessments.append(a)
        violations = [a for a in d.assessments if a.verdict == "violation"]
        proofs = [a for a in d.assessments if a.verdict in ("compliant", "retained") and a.cite]
        if violations:
            d.status = "INCOMPLETE"
        elif proofs:
            d.status = "COMPLETE"
        else:
            d.status = "INCOMPLETE"
            d.notes.append(FALLBACK_NOTE)
            return self._fallback(d, case)
        d.steps = build_steps(d.assessments, d.status, self.strategy)
        return d

    def _fallback(self, d: CaseDecision, case: Dict[str, str]) -> CaseDecision:
        """Nothing provable. The contract still needs a valid row; see decide.py docstring and the README limitation."""
        d.steps = []
        return d
