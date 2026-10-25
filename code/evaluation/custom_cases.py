"""Participant-created evaluation cases (AGENTS.md 6.8 asks for at least three).

Each case is a tiny synthetic world (identities, audit log, evidence observations, workflow claims) plus an EXPECTED answer
that was written by hand from the contract and the deletion rules, NOT copied from what the engine prints. They exercise
situations the public samples barely cover: a historical e-mail, a post-audit recreation trap, a look-alike decoy,
an OCR-uncertain identifier, a non-deletion request and a fully compliant account. All people and identifiers are fictional.
"""
from __future__ import annotations

import csv
import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.decide import AuditEngine  # noqa: E402
from ghost_audit.evidence.model import (  # noqa: E402
    IdentifierItem, Identifiers, Observation, ObservationKind, Provenance, SourceFormat)

SHA = lambda e: hashlib.sha256(e.encode()).hexdigest()  # noqa: E731
RULES = """rule_id,data_category,condition,required_action
rule_01,USER_PROFILE,Always,DELETE
rule_02,SECONDARY_IDENTIFIER,Always,DELETE
rule_03,SEARCH_INDEX_ENTRY,Always,DELETE
rule_04,CACHE_ENTRY,Always,DELETE
rule_05,SUPPORT_MESSAGE,shared context,REDACT
rule_06,SUPPORT_ATTACHMENT,belongs only to subject,DELETE
rule_07,ANALYTICS_PROFILE,attributable,ANONYMIZE
rule_08,PRODUCT_TELEMETRY,attributable,ANONYMIZE
rule_09,USER_EXPORT,Always,DELETE
rule_10,MARKETING_PROFILE,Always,DELETE
rule_11,EMAIL_DELIVERY_LOG,contains email,REDACT
rule_12,SECURITY_AUDIT_LOG,within retention,RETAIN
rule_13,LEGAL_HOLD_RECORD,hold active,RETAIN
rule_14,BACKUP_ARCHIVE,restore can be blocked,RETAIN
rule_15,ACCOUNT_TOMBSTONE,deleted account,REDACT
"""
IDENTITIES = [
    {"user_id": "user_1", "name": "Mira Okafor", "email": "mira.okafor@example.com", "phone": "+44 7700 900101", "email_hash": SHA("mira.okafor@example.com"), "updated_at": "2026-06-01T00:00:00Z"},
    {"user_id": "user_2", "name": "Mira Okafor", "email": "mira.o@example.net", "phone": "+44 7700 900102", "email_hash": SHA("mira.o@example.net"), "updated_at": "2026-01-01T00:00:00Z"},
]
AUDIT = [{"audit_id": "audit_1", "user_id": "user_1", "field_name": "email", "old_value": "m.okafor@example.org", "new_value": "mira.okafor@example.com", "event_time": "2026-06-01T00:00:00Z"}]
REQ, REP, AUD = "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "2026-09-10T00:00:00Z"


def _ob(fid, rid, *, cap="2026-09-09T10:00:00Z", at="2026-09-09T09:00:00Z", kind=ObservationKind.LOOKUP_RESULT, fmt=SourceFormat.LOG, sf=None, sv=None,
        ids=(), fields=None) -> Observation:
    items = tuple(IdentifierItem(t[0], t[1], t[2] if len(t) > 2 else "x", False, None, bool(t[3]) if len(t) > 3 else False) for t in ids)
    return Observation(obs_id="%s:%s" % (fid, rid), kind=kind, provenance=Provenance(fid, fmt, "t", 0, fid, "evidence/x", cap), resource_id=rid,
                       state_field=sf, state_value=sv, record_observed_at=at, identifiers=Identifiers(items=items), fields=fields or {})


@dataclass
class CustomCase:
    name: str
    why: str
    request: Dict[str, str]
    observations: List[Observation]
    expected_status: str
    expected_steps: List[Tuple[str, str, str, str, str]]       # (phase, operation, system_id, resource_id, evidence_id)


def _request(cid, email="mira.okafor@example.com", text="Please permanently delete the account associated with this email address."):
    return {"case_id": cid, "email": email, "requested_at": REQ, "reported_status": "COMPLETE", "reported_at": REP, "audit_at": AUD, "request_text": text}


def cases() -> List[CustomCase]:
    mail = ("email", "mira.okafor@example.com", "email")
    old = ("email", "m.okafor@example.org", "email")
    trace = lambda e: ("email", e, "trace_context.lookup_key")  # noqa: E731
    return [
        CustomCase("historical-email-residual-copies", "Request uses the OLD address; a search copy and an enabled sync survive and a backup can still be restored.",
                   _request("custom_1", email="m.okafor@example.org"),
                   [_ob("evidence_1", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[old]),
                    _ob("evidence_1", "data_flow_3", sf="enabled", sv=True, ids=[("user_id", "user_1", "subject_reference")]),
                    _ob("evidence_1", "backup_4", sf="restore_allowed", sv=1, ids=[mail]),
                    _ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[trace("m.okafor@example.org")]),
                    _ob("evidence_1", "audit_record_5", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[("user_id", "user_1")], fields={"retention_until": "2033-01-01T00:00:00Z"})],
                   "INCOMPLETE",
                   [("FINDING", "REPORT_REMAINING_RECORD", "search_service", "search_7", "evidence_1"),
                    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "integration_service", "data_flow_3", "evidence_1"),
                    ("FINDING", "REPORT_RESTORE_RISK", "backup_service", "backup_4", "evidence_1"),
                    ("REMEDIATION", "DISABLE_DATA_FLOW", "integration_service", "data_flow_3", ""),
                    ("REMEDIATION", "BLOCK_RESTORE", "backup_service", "backup_4", ""),
                    ("REMEDIATION", "DELETE_RECORD", "search_service", "search_7", ""),
                    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9", ""),
                    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "search_service", "search_7", ""),
                    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_5", ""),
                    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "integration_service", "data_flow_3", ""),
                    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "backup_service", "backup_4", "")]),
        CustomCase("fully-compliant-with-retained-records", "Account gone, sync off, restore blocked, tombstone reduced to the stable id, audit record retained.",
                   _request("custom_2"),
                   [_ob("evidence_2", "account_9", sf="http_status", sv="404", ids=[trace("mira.okafor@example.com")]),
                    _ob("evidence_2", "data_flow_3", sf="enabled", sv=False, ids=[("user_id", "user_1", "subject_reference")]),
                    _ob("evidence_2", "backup_4", sf="restore_allowed", sv=False, ids=[("user_id", "user_1", "subject_reference")]),
                    _ob("evidence_2", "tombstone_6", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[("user_id", "user_1", "subject_reference")]),
                    _ob("evidence_2", "audit_record_5", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[("user_id", "user_1")], fields={"retention_until": "2033-01-01T00:00:00Z"})],
                   "COMPLETE",
                   [("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9", "evidence_2"),
                    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "security_service", "audit_record_5", "evidence_2"),
                    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "identity_service", "tombstone_6", "evidence_2"),
                    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "integration_service", "data_flow_3", "evidence_2"),
                    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "backup_service", "backup_4", "evidence_2")]),
        CustomCase("marketing-opt-out-is-not-a-deletion", "Only marketing mail must stop; the account is wanted. Evidence of records must not matter.",
                   _request("custom_3", text="Please remove me from marketing lists only. I still want receipts and service messages for this account."),
                   [_ob("evidence_3", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[mail])], "NOT_APPLICABLE", []),
        CustomCase("post-audit-recreation-is-ignored", "A later file shows the account and a search copy again; the audit is about the state at audit_at.",
                   _request("custom_4"),
                   [_ob("evidence_4", "account_9", sf="http_status", sv="404", ids=[trace("mira.okafor@example.com")]),
                    _ob("evidence_5", "account_9", cap="2026-09-12T00:00:00Z", at="2026-09-12T00:00:00Z", sf="http_status", sv="200", ids=[trace("mira.okafor@example.com")]),
                    _ob("evidence_5", "search_7", cap="2026-09-12T00:00:00Z", at="2026-09-12T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[mail])],
                   "COMPLETE", [("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9", "evidence_4")]),
        CustomCase("lookalike-and-same-name-are-not-merged", "A look-alike address and another customer with the same name hold records; neither belongs to the subject.",
                   _request("custom_5"),
                   [_ob("evidence_6", "account_9", sf="http_status", sv="404", ids=[trace("mira.okafor@example.com")]),
                    _ob("evidence_6", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[("email", "mira.okafor@example.co", "email"), ("name", "Mira Okafor", "display_name")]),
                    _ob("evidence_6", "search_8", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[("email", "mira.o@example.net", "email"), ("user_id", "user_2")])],
                   "COMPLETE", [("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9", "evidence_6")]),
        CustomCase("uncertain-ocr-reading-is-not-used", "A screenshot row shows a low-confidence reading of the subject's address next to an export id.",
                   _request("custom_6"),
                   [_ob("evidence_7", "account_9", sf="http_status", sv="404", ids=[trace("mira.okafor@example.com")]),
                    _ob("evidence_8", "export_3", kind=ObservationKind.RECORD, fmt=SourceFormat.IMAGE, ids=[("email", "mira.okafor@example.com", "cells[1]", True)])],
                   "COMPLETE", [("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_service", "account_9", "evidence_7")]),
    ]


def run_custom_cases() -> List[Dict[str, object]]:
    results = []
    for c in cases():
        with tempfile.TemporaryDirectory() as tmp:
            for name, rows in (("user_identities.csv", IDENTITIES), ("user_audit_log.csv", AUDIT)):
                with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="") as h:
                    w = csv.DictWriter(h, fieldnames=list(rows[0]))
                    w.writeheader()
                    w.writerows(rows)
            Path(tmp, "deletion_rules.csv").write_text(RULES, encoding="utf-8")
            d = AuditEngine(tmp, corpus=Corpus(c.observations)).decide(c.request)
        got = [(s["phase"], s["operation"], s["system_id"], s["resource_id"], s["evidence_id"]) for s in d.steps]
        results.append({"name": c.name, "why": c.why, "expected_status": c.expected_status, "status": d.status,
                        "expected_steps": c.expected_steps, "steps": got, "ok": d.status == c.expected_status and got == c.expected_steps})
    return results
