"""Per-resource assessment: what is the state at ``audit_at`` and what does ``deletion_rules.csv`` require?

Verdicts: ``violation`` (finding + remediation + verification), ``compliant`` (a proof the required final state holds),
``retained`` (a policy-required record that is present), ``unknown`` (no usable evidence: nothing is claimed).

State is read from the MOST RECENT eligible file that speaks about the resource, OR-ed across the stores/systems inside
that file (so a ghost row in a replica still counts, but an old snapshot cannot override a later lookup). Workflow claims
(activity rows, ``reported_status``) are never used as state.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections import Counter
from typing import Callable, Dict, List, Optional, Tuple

from ..evidence.model import Observation, ObservationKind, SourceFormat, flag_value
from .linking import LinkedResource
from .policy import ACTION_OPS, DATA_FLOW_OPS, PREFIX_CATEGORY, PREFIX_SYSTEM, RESTORE_OPS, RETAIN_VERIFY, Rules, prefix_of

Signal = Callable[[Observation], Optional[bool]]
_NOT_ABOUT_PRESENCE = {"deletion_marker_check", "thumbnail_failed", "contact_query_completed", "message_read"}


@dataclass
class Assessment:
    resource_id: str
    system_id: str
    category: str
    rule_id: Optional[str]
    verdict: str
    finding_op: Optional[str] = None
    remediation_op: Optional[str] = None
    verify_op: Optional[str] = None
    proof: Optional[Observation] = None
    proof_id: str = ""            # set when the proof is a snapshot in which the record is ABSENT (no observation to point at)
    reason: str = ""
    weak: bool = False

    @property
    def cite(self) -> str:
        return self.proof_id or (self.proof.provenance.citable_id if self.proof is not None else "")


# ---------------------------------------------------------------------------------------------- signals
def _t(o: Observation) -> str:
    return o.effective_time().value or ""


def presence(o: Observation) -> Optional[bool]:
    """Does this observation say the record exists (True) or does not exist (False)?"""
    if o.kind is ObservationKind.CLAIM or "unrecognized" in o.flags:
        return None
    sf, sv = o.state_field, o.state_value
    if sf in ("http_status", "status_code"):
        s = str(sv)
        return True if s.startswith("2") else False if s == "404" else None
    if sf == "result":
        return False if sv in ("NOT_FOUND", "miss") else True
    if sf == "hits.total":
        try:
            return int(sv) > 0
        except (TypeError, ValueError):
            return None
    if sf == "rows":
        return None if sv in (None, "") else str(sv) not in ("0",)
    if o.provenance.source_format in (SourceFormat.PDF, SourceFormat.IMAGE):
        return True
    if o.kind is ObservationKind.RECORD:
        return True
    rows = o.fields.get("rows")
    if rows not in (None, ""):                              # a read that reports how many rows it returned
        return str(rows) != "0"
    if o.provenance.source_format is SourceFormat.LOG and o.kind is ObservationKind.LOOKUP_RESULT and o.collection not in _NOT_ABOUT_PRESENCE:
        return True                                         # the service read the record
    return None


def _identifying(o: Observation, kinds=("email", "email_hash", "phone", "name", "user_id")) -> bool:
    """Does the record itself still carry a direct identifier (the lookup key that found it does not count)?"""
    return any(i.kind in kinds and not i.path.startswith("trace_context") and not i.uncertain for i in o.identifiers.items)


_DOC = (SourceFormat.PDF, SourceFormat.IMAGE)
_FLOW_ON = re.compile(r"\b(?:continuous|enabled|running|active|syncing|live)\b", re.I)
_FLOW_OFF = re.compile(r"\b(?:disabled|paused|stopped|inactive|suspended|off)\b", re.I)


def _doc_identifying(o: Observation, name: Optional[str] = None) -> Optional[bool]:
    """Documents give POSITIVE evidence only: a row that shows the subject's identifier (or name) exposes it; silence proves nothing."""
    if _identifying(o, ("email", "email_hash", "phone")):
        return True
    return True if name and name.lower() in str(o.fields.get("text", "")).lower() else None


def attributable(o: Observation, name: Optional[str] = None) -> Optional[bool]:      # ANALYTICS_PROFILE: "still attributable to a user"
    if o.kind is ObservationKind.CLAIM:
        return None
    if o.provenance.source_format in _DOC:
        return _doc_identifying(o, name)
    sf, sv = o.state_field, o.state_value
    if sf == "result":
        return sv == "IDENTIFIABLE" if sv in ("IDENTIFIABLE", "ANONYMIZED") else None
    if sf == "direct_identifiers":
        return str(sv) != "0"
    return _identifying(o)


def support_exposed(o: Observation, name: Optional[str] = None) -> Optional[bool]:   # SUPPORT_MESSAGE: personal details inside the record
    if o.kind is ObservationKind.CLAIM:
        return None
    if o.provenance.source_format in _DOC:
        return _doc_identifying(o, name)
    sf, sv = o.state_field, o.state_value
    if sf == "result":
        return sv == "IDENTIFIABLE" if sv in ("IDENTIFIABLE", "ANONYMIZED", "REDACTED", "FOUND", "NOT_FOUND") else None
    if o.collection in ("message_pii_scan",):
        return str(o.fields.get("detector")) == "direct_identifier"
    if o.collection in ("deletion_marker_check", "contact_query_completed", "thumbnail_failed"):
        return None
    return _identifying(o, ("email", "email_hash", "phone", "name"))


def tombstone_exposed(o: Observation, name: Optional[str] = None) -> Optional[bool]:  # ACCOUNT_TOMBSTONE: only the stable user_id may remain
    if o.kind is ObservationKind.CLAIM:
        return None
    if o.provenance.source_format in _DOC:
        return _doc_identifying(o, name)
    if o.state_field == "result":
        return None if o.state_value not in ("IDENTIFIABLE", "REDACTED", "ANONYMIZED") else o.state_value == "IDENTIFIABLE"
    return _identifying(o, ("email", "email_hash", "phone", "name"))


def replica_copy(o: Observation) -> Optional[bool]:
    """A legacy/replica read of a support record: a row came back, or the deletion marker is missing -> the copy still exists."""
    if o.collection == "contact_query_completed":
        return None if o.state_value in (None, "") else str(o.state_value) != "0"
    if o.collection == "deletion_marker_check":
        marker = flag_value(o.state_value)
        return None if marker is None else (not marker)
    return None


def flow_active(o: Observation) -> Optional[bool]:
    if o.provenance.source_format in _DOC:                    # console row: the mode/status word printed next to the connector
        text = str(o.fields.get("text", ""))
        return False if _FLOW_OFF.search(text) else True if _FLOW_ON.search(text) else None
    sf, sv = o.state_field, o.state_value
    if sf == "enabled":
        return flag_value(sv)
    if sf == "result":
        return True if sv == "ACTIVE" else False if sv in ("DISABLED", "BLOCKED") else None
    return None


def restore_risk(o: Observation) -> Optional[bool]:
    if o.provenance.source_format in _DOC:                    # an archive listed in a recovery/restore console with no "blocked" marker
        text = str(o.fields.get("text", "")).lower()
        return False if "blocked" in text else None
    sf, sv = o.state_field, o.state_value
    if sf == "restore_allowed":
        return flag_value(sv)
    if sf == "eligible":
        elig = flag_value(sv)
        block = flag_value(o.fields.get("deletion_block"))
        return None if elig is None else bool(elig and not block)
    if sf == "decision":
        return True if sv == "allow" else False if sv == "deny" else None
    if sf == "result":
        return True if sv == "ACTIVE" else False if sv == "BLOCKED" else None
    return None


# ---------------------------------------------------------------------------------------- state resolution
def resolve(obs: List[Observation], signal: Signal) -> Tuple[Optional[bool], Optional[Observation]]:
    """(state, deciding observation): latest file, latest observation per (system, store, collection), OR-ed."""
    cand = [(o, signal(o)) for o in obs]
    cand = [(o, v) for o, v in cand if v is not None]
    if not cand:
        return None, None
    top = max(cand, key=lambda c: (_t(c[0]), c[0].provenance.file_captured_at or "", c[0].provenance.ordinal))[0]
    in_file = [(o, v) for o, v in cand if o.provenance.citable_id == top.provenance.citable_id]
    groups: Dict[Tuple, Tuple[Observation, bool]] = {}
    for o, v in sorted(in_file, key=lambda c: (_t(c[0]), c[0].provenance.ordinal)):
        groups[(o.system_id, o.store, o.collection)] = (o, v)
    finals = list(groups.values())
    positives = [o for o, v in finals if v]
    if positives:
        return True, max(positives, key=lambda o: (_t(o), o.provenance.ordinal))
    return False, max((o for o, _v in finals), key=lambda o: (_t(o), o.provenance.ordinal))


def _category(lr: LinkedResource, file_text: Dict[str, str]) -> str:
    """Record type: what the evidence says it is; the id prefix only when the evidence is silent or agrees.
    (``analytics_9914`` seen through ``contact_lookup_completed`` is a MARKETING_PROFILE hosted by the analytics platform.)"""
    cat = PREFIX_CATEGORY.get(prefix_of(lr.resource_id), "")
    counted = Counter(o.record_type for o in lr.observations if o.record_type)
    if counted and cat not in counted and not (cat == "SUPPORT_MESSAGE" and "SUPPORT_ATTACHMENT" in counted):
        cat = counted.most_common(1)[0][0]
    types = set(counted)
    if cat == "SUPPORT_MESSAGE":
        if "SUPPORT_ATTACHMENT" in types or any(
            o.provenance.source_format is SourceFormat.PDF and "attachment" in file_text.get(o.provenance.file_id or "", "").lower()
            for o in lr.observations):
            return "SUPPORT_ATTACHMENT"
    return cat


def snapshot_absence(corpus, lr: LinkedResource, requested_at: str, audit_at: str) -> Optional[str]:
    """file_id of the best full account snapshot in which the resource is absent (primary+replica comparison first, then latest)."""
    snaps = [s for s in corpus.account_snapshots(requested_at, audit_at)
             if not any(o.provenance.file_id == s["file_id"] for o in lr.observations)]
    both = [s for s in snaps if s["both"]]
    pick = (both or snaps)[-1] if (both or snaps) else None
    return str(pick["file_id"]) if pick else None


def assess_resource(lr: LinkedResource, rules: Rules, audit_at: str, file_text: Optional[Dict[str, str]] = None,
                    corpus=None, requested_at: Optional[str] = None) -> Optional[Assessment]:
    rid = lr.resource_id
    cat = _category(lr, file_text or {})
    if not cat:
        return None
    rule = rules.by_category.get(cat)
    system = PREFIX_SYSTEM.get(prefix_of(rid)) or next((o.system_id for o in lr.observations if o.system_id), "") or ""
    obs = [o for o in lr.observations if not (cat == "USER_PROFILE" and o.system_id == "profile_service")]
    base = dict(resource_id=rid, system_id=system, category=cat, rule_id=rule.rule_id if rule else None, weak=lr.weak)

    def violation(ops, proof, why):
        return Assessment(verdict="violation", finding_op=ops[0], remediation_op=ops[1], verify_op=ops[2], proof=proof, reason=why, **base)

    def compliant(proof, why, verify):
        return Assessment(verdict="compliant", verify_op=verify, proof=proof, reason=why, **base)

    action = rules.action(cat)
    if cat == "USER_PROFILE":
        state, o = resolve(obs, presence)
        if state is True:
            return violation(ACTION_OPS["DELETE"], o, "account record still exists at audit_at")
        if state is False:
            return compliant(o, "lookup reports the account absent", ACTION_OPS["DELETE"][2])
        sid = snapshot_absence(corpus, lr, requested_at, audit_at) if corpus is not None and requested_at else None
        if sid and not lr.observations:                           # named only by a workflow claim, proven absent by a full snapshot
            a = compliant(None, "absent from the account snapshot %s (named by a workflow claim)" % sid, ACTION_OPS["DELETE"][2])
            a.proof_id = sid
            return a
        return Assessment(verdict="unknown", reason="no usable evidence for USER_PROFILE", **base)
    if cat == "DATA_FLOW":
        state, o = resolve(obs, flow_active)
        if state is True:
            return violation(DATA_FLOW_OPS, o, "data flow is enabled/active at audit_at")
        if state is False:
            return compliant(o, "data flow is disabled", DATA_FLOW_OPS[2])
    elif cat == "BACKUP_ARCHIVE":                                 # rule_14: retain the archive, but a restore path must be blockable
        def restore_signal(x: Observation) -> Optional[bool]:
            if x.provenance.source_format in _DOC:                # INFERENCE (documented): an archive shown in a recovery/restore console is restorable
                s = restore_risk(x)
                return s if s is not None else (True if "restore" in (file_text or {}).get(x.provenance.file_id or "", "").lower() else None)
            return restore_risk(x)
        state, o = resolve(obs, restore_signal)
        if state is True:
            inferred = o is not None and o.provenance.source_format in _DOC
            return violation(RESTORE_OPS, o, "INFERRED from a screenshot: the archive is listed in a restore console with no 'blocked' marker"
                             if inferred else "restore of the archive is allowed/eligible at audit_at")
        if state is False:
            return compliant(o, "restore is blocked", RESTORE_OPS[2])
    elif cat in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):      # rules 12/13: RETAIN while the retention/hold is in force
        state, o = resolve(obs, presence)
        if state is True:
            until = next((str(v) for v in (o.fields.get("retention_until"), o.fields.get("retained_until")) if v), None)
            if until and until < audit_at:
                return Assessment(verdict="unknown", reason="retention period ended before audit_at", **base)
            return Assessment(verdict="retained", verify_op=RETAIN_VERIFY, proof=o, reason="policy-required record is present", **base)
    elif cat == "ANALYTICS_PROFILE":                              # rule_07
        state, o = resolve(obs, lambda x: attributable(x, lr.subject_name))
        if state is True:
            return violation(ACTION_OPS["ANONYMIZE"], o, "record is still attributable to a user")
        if state is False:
            return compliant(o, "record carries no identifier", ACTION_OPS["ANONYMIZE"][2])
    elif cat == "SUPPORT_MESSAGE":                                # rule_05
        copy_state, co = resolve(obs, replica_copy)               # a replica copy with no deletion marker is a whole remaining record
        if copy_state is True:
            return violation(ACTION_OPS["DELETE"], co, "a replica copy of the support record exists and carries no deletion marker")
        state, o = resolve(obs, lambda x: support_exposed(x, lr.subject_name))
        if state is True:
            return violation(ACTION_OPS["REDACT"], o, "personal details remain in the conversation")
        if state is False:
            return compliant(o, "personal details are removed", ACTION_OPS["REDACT"][2])
    elif cat == "ACCOUNT_TOMBSTONE":                              # rule_15
        state, o = resolve(obs, lambda x: tombstone_exposed(x, lr.subject_name))
        if state is True:
            return violation(ACTION_OPS["REDACT"], o, "tombstone still holds name/e-mail/phone/hash")
        if state is False:
            return compliant(o, "tombstone keeps only the stable reference", ACTION_OPS["REDACT"][2])
    elif action == "DELETE":                                      # rules 01,03,06,09,10: the whole record must be gone
        state, o = resolve(obs, presence)
        if state is None and lr.doc_presence:                     # no structured row, but a document prints the catalog alias of the record
            a = violation(ACTION_OPS["DELETE"], None, "a document prints the catalog alias %s of the record" % ",".join(lr.aliases))
            a.proof_id = lr.doc_presence[-1]
            return a
        if state is True:
            return violation(ACTION_OPS["DELETE"], o, "record still exists at audit_at")
        if state is False:
            return compliant(o, "record is absent", ACTION_OPS["DELETE"][2])
    return Assessment(verdict="unknown", reason="no usable evidence for %s" % cat, **base)
