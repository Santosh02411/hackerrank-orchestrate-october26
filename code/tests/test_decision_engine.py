"""Stage 2 tests: applicability, identity resolution, eligibility, linking, per-rule assessment, planning, output.

Three layers:
* unit tests on hand-built observations (no dataset needed) - they pin the RULES;
* synthetic end-to-end cases through ``AuditEngine`` with an injected corpus and a tiny temporary dataset;
* real-data tests (skipped when dataset/ or the OCR tools are missing): validity of all 518 rows, citation hygiene,
  determinism and a cutoff-invariance property. The 32 public samples are DEVELOPMENT data, so the sample test is a
  regression guard, not an accuracy claim.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET = REPO_ROOT / "dataset"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit import contracts as C  # noqa: E402
from ghost_audit.engine import applicability as AP  # noqa: E402
from ghost_audit.engine import assess as AS  # noqa: E402
from ghost_audit.engine.corpus import Corpus  # noqa: E402
from ghost_audit.engine.decide import AuditEngine, build_steps, order_steps  # noqa: E402
from ghost_audit.engine.evaluate import evaluate, read_output  # noqa: E402
from ghost_audit.engine.identity import IdentityDirectory  # noqa: E402
from ghost_audit.engine.linking import LinkedResource, link_subject  # noqa: E402
from ghost_audit.engine.policy import Rules  # noqa: E402
from ghost_audit.engine.writer import steps_json, write_output  # noqa: E402
from ghost_audit.evidence.model import (  # noqa: E402
    IdentifierItem,
    Identifiers,
    Observation,
    ObservationKind,
    Provenance,
    SnapshotScope,
    SourceFormat,
)
from ghost_audit.evidence.model import ScopeKind, TimestampSource  # noqa: E402
from ghost_audit.ordering import SortStrategy  # noqa: E402
from ghost_audit.validator import ValidatorConfig, validate_csv  # noqa: E402

def read_rows(path) -> list:
    with open(path, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


HAVE_DATASET = (DATASET / "deletion_requests.csv").exists() and (DATASET / "evidence").is_dir()
HAVE_TOOLS = all(importlib.util.find_spec(m) is not None for m in ("pypdf", "PIL")) and __import__("ghost_audit.evidence.ocr", fromlist=["x"]).find_tesseract() is not None
needs_dataset = unittest.skipUnless(HAVE_DATASET, "dataset/ not present")
needs_full = unittest.skipUnless(HAVE_DATASET and HAVE_TOOLS and not os.environ.get("GHOST_FAST_TESTS"),
                                  "dataset/ and pypdf+Pillow+Tesseract are required to parse every evidence format (GHOST_FAST_TESTS=1 skips these slow tests)")

RULES_CSV = """rule_id,data_category,condition,required_action
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
SHA = lambda e: hashlib.sha256(e.encode()).hexdigest()  # noqa: E731

# ----------------------------------------------------------------------------------------- synthetic world
REQ_AT, REP_AT, AUD_AT = "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "2026-09-10T00:00:00Z"
IDENTITIES = [
    {"user_id": "user_1", "name": "Ana Silva", "email": "ana.silva@example.com", "phone": "+1 555 0100", "email_hash": SHA("ana.silva@example.com"), "updated_at": "2026-06-01T00:00:00Z"},
    {"user_id": "user_2", "name": "Bob Stone", "email": "bob@example.com", "phone": "+1 555 0200", "email_hash": SHA("bob@example.com"), "updated_at": "2026-01-01T00:00:00Z"},
    {"user_id": "user_3", "name": "Ana Silva", "email": "ana.s@example.org", "phone": "+1 555 0300", "email_hash": SHA("ana.s@example.org"), "updated_at": "2026-01-01T00:00:00Z"},
    {"user_id": "user_4", "name": "Cy Late", "email": "cy.new@example.com", "phone": "+1 555 0400", "email_hash": SHA("cy.new@example.com"), "updated_at": "2026-09-20T00:00:00Z"},
]
AUDIT = [
    {"audit_id": "audit_1", "user_id": "user_1", "field_name": "email", "old_value": "old.ana@example.com", "new_value": "ana.silva@example.com", "event_time": "2026-06-01T00:00:00Z"},
    {"audit_id": "audit_2", "user_id": "user_1", "field_name": "email_hash", "old_value": SHA("old.ana@example.com"), "new_value": SHA("ana.silva@example.com"), "event_time": "2026-06-01T00:00:00Z"},
    # user_4 changed e-mail AFTER the audit time of the cases below
    {"audit_id": "audit_3", "user_id": "user_4", "field_name": "email", "old_value": "cy.old@example.com", "new_value": "cy.new@example.com", "event_time": "2026-09-20T00:00:00Z"},
    # an address shared by two users (must never be merged)
    {"audit_id": "audit_4", "user_id": "user_2", "field_name": "email", "old_value": "shared@example.com", "new_value": "bob@example.com", "event_time": "2026-03-01T00:00:00Z"},
    {"audit_id": "audit_5", "user_id": "user_3", "field_name": "email", "old_value": "shared@example.com", "new_value": "ana.s@example.org", "event_time": "2026-03-02T00:00:00Z"},
]


def directory() -> IdentityDirectory:
    return IdentityDirectory(IDENTITIES, AUDIT)


def prov(fid: str, cap: str = "2026-09-09T10:00:00Z", fmt: SourceFormat = SourceFormat.LOG, ordinal: int = 0) -> Provenance:
    return Provenance(citable_id=fid, source_format=fmt, locator="t", ordinal=ordinal, file_id=fid, file_path="evidence/x", file_captured_at=cap)


def ob(fid: str, rid: Optional[str], *, cap: str = "2026-09-09T10:00:00Z", at: Optional[str] = "2026-09-09T09:00:00Z", kind: ObservationKind = ObservationKind.LOOKUP_RESULT,
       fmt: SourceFormat = SourceFormat.LOG, sf: Optional[str] = None, sv=None, ids: Sequence[Tuple] = (), rtype: Optional[str] = None, collection: Optional[str] = None,
       store: Optional[str] = None, role: Optional[str] = None, system: Optional[str] = None, fields: Optional[dict] = None, flags: Tuple[str, ...] = (), ordinal: int = 0) -> Observation:
    items = tuple(IdentifierItem(t[0], t[1], t[2] if len(t) > 2 else "x", False, None, bool(t[3]) if len(t) > 3 else False) for t in ids)
    return Observation(obs_id="%s:%s:%d" % (fid, rid, ordinal), kind=kind, provenance=prov(fid, cap, fmt, ordinal), system_id=system, resource_id=rid, record_type=rtype,
                       collection=collection, store=store, store_role=role, state_field=sf, state_value=sv, record_observed_at=at,
                       identifiers=Identifiers(items=items), fields=fields or {}, flags=flags)


def claim(aid: str, etype: str, rid: str, at: str, target: str, details: str = "", result: str = "SUCCESS", ids: Sequence[Tuple] = ()) -> Observation:
    items = tuple(IdentifierItem(k, v, "details", True) for k, v in ids)
    return Observation(obs_id=aid, kind=ObservationKind.CLAIM, provenance=Provenance(aid, SourceFormat.CSV, "row", 0), system_id=target, resource_id=rid,
                       event_type=etype, record_observed_at=at, identifiers=Identifiers(items=items),
                       fields={"details": details, "reported_result": result, "event_type": etype})


E = lambda v, p="email": ("email", v, p)  # noqa: E731
U = lambda v, p="subject_reference": ("user_id", v, p)  # noqa: E731


def case(email: str = "ana.silva@example.com", text: str = "Please permanently delete the account associated with this email address.", cid: str = "case_1",
         req: str = REQ_AT, rep: str = REP_AT, aud: str = AUD_AT) -> Dict[str, str]:
    return {"case_id": cid, "email": email, "requested_at": req, "reported_status": "COMPLETE", "reported_at": rep, "audit_at": aud, "request_text": text}


def make_engine(observations: Iterable[Observation], scopes: Iterable[SnapshotScope] = (), file_text: Optional[Dict[str, str]] = None) -> AuditEngine:
    tmp = tempfile.mkdtemp()
    for name, rows in (("user_identities.csv", IDENTITIES), ("user_audit_log.csv", AUDIT)):
        with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="") as h:
            w = csv.DictWriter(h, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    Path(tmp, "deletion_rules.csv").write_text(RULES_CSV, encoding="utf-8")
    return AuditEngine(tmp, corpus=Corpus(list(observations), scopes, file_text=file_text))


def lr(rid: str, observations: Sequence[Observation], methods=("identifier",), **kw) -> LinkedResource:
    r = LinkedResource(rid, methods=set(methods), observations=list(observations), **kw)
    return r


@lru_cache(maxsize=1)
def rules() -> Rules:
    tmp = tempfile.mkdtemp()
    Path(tmp, "deletion_rules.csv").write_text(RULES_CSV, encoding="utf-8")
    return Rules.load(tmp)


def assess(rid: str, observations: Sequence[Observation], **kw):
    return AS.assess_resource(lr(rid, observations, **kw), rules(), AUD_AT, {})


# ============================================================================================ applicability
class TestApplicability(unittest.TestCase):
    DELETE = [
        "Please permanently delete the account associated with this email address.",
        "I would like the account associated with this address to be erased. Please review any identifiers connected to this account.",
        "Please close my account and process the associated personal-data deletion.",
        "I am asking you to remove my account and the personal information linked to it.",
        "Solicito a exclusão permanente da conta associada a este e-mail.",
        "Solicito la eliminación permanente de la cuenta asociada a este correo.",
        "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
        "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
        "I deleted my account and received the confirmation email. Could you verify that the profile is gone?",
        "Can you verify that my account was deleted? A search result with a similar email belongs to someone else.",
        "I found an old report saying my account still existed. Please check the latest state and confirm that the profile is gone.",
        "Please audit the deletion as it stood when my request was reviewed.",
        "I closed my account, but an old download link still works. Please delete that export file as well.",
    ]
    NOT_DELETE = [
        "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
        "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
        "I'd like to download my account information in a portable format. Please keep the account as it is.",
        "I can't access my profile and need help resetting the login. Do not close the account.",
        "My surname is misspelled on the account. Can you correct it without removing any of my records?",
        "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
        "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
        "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
        "Please change the email address used for this account. I want to continue using the service.",
        "Could you send me a copy of the information held on my account? I still use it, so please don\u2019t delete or change anything.",
        "",
        "Thanks!",
    ]

    def test_deletion_requests_in_every_language_are_authorized(self):
        for t in self.DELETE:
            with self.subTest(t[:50]):
                self.assertTrue(AP.classify_request(t).authorized, AP.classify_request(t).reason)

    def test_non_deletion_requests_are_not_authorized(self):
        for t in self.NOT_DELETE:
            with self.subTest(t[:50]):
                self.assertFalse(AP.classify_request(t).authorized)

    def test_negation_beats_a_deletion_word_in_the_same_sentence(self):
        self.assertFalse(AP.classify_request("I want to keep my account; do not delete it.").authorized)
        self.assertFalse(AP.classify_request("This is not a deletion request, I only want a copy of my data.").authorized)

    def test_reason_is_reported(self):
        self.assertIn("refused", AP.classify_request("Do not close the account.").reason)
        self.assertIn("marketing", AP.classify_request("Remove me from marketing lists only.").reason)

    @needs_dataset
    def test_real_requests_exactly_ten_main_and_zero_sample_are_non_deletion(self):
        rd = lambda f: read_rows(DATASET / f)  # noqa: E731
        main = [r["case_id"] for r in rd("deletion_requests.csv") if not AP.classify_request(r["request_text"]).authorized]
        self.assertEqual(len(main), 10)
        self.assertEqual([r for r in rd("sample_deletion_requests.csv") if not AP.classify_request(r["request_text"]).authorized], [])
        # independent cross-check: the workflow itself logged exactly ten request classifications (claims, never an input)
        self.assertEqual(sum(1 for a in rd("system_activity.csv") if a["event_type"] == "CLASSIFY_REQUEST"), 10)


# ============================================================================================ identity
class TestIdentity(unittest.TestCase):
    def setUp(self):
        self.d = directory()

    def test_current_and_historical_emails_resolve_to_the_same_user(self):
        a = self.d.resolve("ana.silva@example.com", AUD_AT)
        b = self.d.resolve("old.ana@example.com", AUD_AT)
        self.assertEqual((a.status, a.user_id, a.via), ("resolved", "user_1", "current"))
        self.assertEqual((b.status, b.user_id, b.via), ("resolved", "user_1", "historical"))
        self.assertEqual(a.identity, b.identity)

    def test_case_and_whitespace_are_ignored(self):
        self.assertEqual(self.d.resolve("  ANA.Silva@Example.COM ", AUD_AT).user_id, "user_1")

    def test_identity_set_contains_historical_values_hashes_and_phone_digits(self):
        i = self.d.resolve("ana.silva@example.com", AUD_AT).identity
        self.assertEqual(i.emails, frozenset({"old.ana@example.com", "ana.silva@example.com"}))
        self.assertIn(SHA("old.ana@example.com"), i.hashes)
        self.assertTrue(i.contains("phone", "+1 (555) 0100") and i.contains("user_id", "user_1") and not i.contains("user_id", "user_2"))

    def test_changes_logged_after_audit_at_are_not_applied(self):
        i = self.d.resolve("cy.old@example.com", AUD_AT).identity
        self.assertEqual(i.emails, frozenset({"cy.old@example.com"}))            # the new address did not exist yet
        later = self.d.resolve("cy.old@example.com", "2026-10-01T00:00:00Z").identity
        self.assertEqual(later.emails, frozenset({"cy.old@example.com", "cy.new@example.com"}))

    def test_an_address_held_by_two_users_is_ambiguous_and_never_merged(self):
        r = self.d.resolve("shared@example.com", AUD_AT)
        self.assertEqual((r.status, r.user_id, r.candidates), ("ambiguous", None, ("user_2", "user_3")))

    def test_unknown_address_is_unresolved(self):
        self.assertEqual(self.d.resolve("nobody@example.com", AUD_AT).status, "unresolved")

    def test_two_users_with_the_same_name_stay_separate(self):
        self.assertNotEqual(self.d.resolve("ana.silva@example.com", AUD_AT).user_id, self.d.resolve("ana.s@example.org", AUD_AT).user_id)

    def test_owner_lookup_covers_every_strong_identifier_kind(self):
        d = self.d
        self.assertEqual(d.owners_of("email", "OLD.ana@example.com"), {"user_1"})
        self.assertEqual(d.owners_of("email_hash", SHA("bob@example.com").upper()), {"user_2"})
        self.assertEqual(d.owners_of("phone", "+1 555-0200"), {"user_2"})
        self.assertEqual(d.owners_of("user_id", "user_3"), {"user_3"})
        self.assertEqual(d.owners_of("user_id", "user_999"), set())
        self.assertEqual(d.owners_of("email", "shared@example.com"), {"user_2", "user_3"})

    @needs_dataset
    def test_every_real_request_resolves_to_exactly_one_user(self):
        d = IdentityDirectory.from_dataset(DATASET)
        rows = read_rows(DATASET / "deletion_requests.csv")
        c = Counter(d.resolve(r["email"], r["audit_at"]).status for r in rows)
        self.assertEqual(dict(c), {"resolved": 518})


# ============================================================================================ eligibility
class TestEligibility(unittest.TestCase):
    def test_file_captured_after_audit_is_excluded_boundary_is_inclusive(self):
        self.assertTrue(Corpus.eligible(ob("f", "r", cap=AUD_AT, at=AUD_AT), AUD_AT))
        self.assertFalse(Corpus.eligible(ob("f", "r", cap="2026-09-10T00:00:01Z", at=None), AUD_AT))

    def test_record_time_after_audit_is_excluded_even_in_an_earlier_file(self):
        self.assertFalse(Corpus.eligible(ob("f", "r", cap="2026-09-09T00:00:00Z", at="2026-09-10T00:00:01Z"), AUD_AT))

    def test_evidence_older_than_the_request_is_excluded_only_when_a_window_is_given(self):
        old = ob("f", "r", cap="2026-08-01T00:00:00Z", at="2026-08-01T00:00:00Z")
        self.assertTrue(Corpus.eligible(old, AUD_AT))
        self.assertFalse(Corpus.eligible(old, AUD_AT, REQ_AT))

    def test_claims_are_filtered_by_event_time(self):
        c = Corpus([claim("a1", "DELETE_RECORD", "account_1", "2026-09-05T00:00:00Z", "account_service"),
                    claim("a2", "DELETE_RECORD", "account_2", "2026-09-11T00:00:00Z", "account_service")])
        self.assertEqual([x.obs_id for x in c.eligible_claims(AUD_AT)], ["a1"])

    def test_snapshot_index_lists_only_full_account_snapshots_in_window(self):
        sc = lambda fid, role, kind=ScopeKind.SQL_TABLE, store="customer_profiles": SnapshotScope(kind, fid, "account_service", store, None, TimestampSource.NONE, 0, "file", store_role=role)  # noqa: E731
        c = Corpus([], [sc("s1", "primary"), sc("s1", "replica"), sc("s2", "primary"), sc("s3", "primary"),
                        SnapshotScope(ScopeKind.JSON_SERVICE_SECTION, "s4", "account_service", "account_service.profile_lookups", None, TimestampSource.NONE, 1, "file")],
                   file_captured={"s1": "2026-09-05T00:00:00Z", "s2": "2026-09-08T00:00:00Z", "s3": "2026-09-12T00:00:00Z", "s4": "2026-09-08T00:00:00Z"})
        snaps = c.account_snapshots(REQ_AT, AUD_AT)
        self.assertEqual([(s["file_id"], s["both"]) for s in snaps], [("s1", True), ("s2", False)])   # s3 too late, s4 is not a full snapshot


# ============================================================================================ linking
class TestLinking(unittest.TestCase):
    def link(self, observations, claims=(), email="ana.silva@example.com", **kw):
        corpus = Corpus(list(observations) + list(claims), file_text=kw.pop("file_text", None))
        d = directory()
        c = case(email=email, **kw)
        return link_subject(corpus, d, d.resolve(email, c["audit_at"]), c)

    def test_identifier_link_uses_current_and_historical_email_hash_phone_and_user_id(self):
        v = self.link([ob("evidence_1", "search_1", ids=[E("OLD.ana@example.com")]), ob("evidence_1", "search_2", ids=[("email_hash", SHA("ana.silva@example.com"), "h")]),
                       ob("evidence_1", "search_3", ids=[("phone", "+1 555 0100", "p")]), ob("evidence_1", "audit_record_4", ids=[U("user_1")])])
        self.assertEqual(sorted(v.resources), ["audit_record_4", "search_1", "search_2", "search_3"])

    def test_lookalike_and_other_users_identifiers_are_not_linked(self):
        v = self.link([ob("evidence_1", "search_1", ids=[E("ana.silva@example.co")]), ob("evidence_1", "search_2", ids=[E("ana.s@example.org")]), ob("evidence_1", "search_3", ids=[U("user_3")])])
        self.assertEqual(v.resources, {})

    def test_uncertain_ocr_identifier_alone_does_not_link_but_is_noted(self):
        weak = ob("evidence_1", "backup_1", fmt=SourceFormat.IMAGE, ids=[("email", "ana.silva@example.com", "cells[1]", True)])
        v = self.link([weak])
        self.assertEqual(v.resources, {})
        self.assertTrue(any("uncertain OCR" in n for n in v.notes))
        strong = ob("evidence_1", "backup_1", fmt=SourceFormat.IMAGE, ids=[("email", "ana.silva@example.com", "cells[1]", False)])
        self.assertIn("backup_1", self.link([strong]).resources)

    def test_multi_region_ocr_rows_do_not_link(self):
        self.assertEqual(self.link([ob("evidence_1", "backup_1", fmt=SourceFormat.IMAGE, flags=("multi_region_row",), ids=[E("ana.silva@example.com", "cells[0]")])]).resources, {})

    def test_trace_lookup_key_links_a_resource_that_carries_no_identifier_itself(self):
        v = self.link([ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("old.ana@example.com", "trace_context.lookup_key")])])
        self.assertEqual(v.resources["account_9"].methods, {"trace"})

    def test_same_resource_seen_with_another_known_user_is_dropped_as_a_conflict(self):
        v = self.link([ob("evidence_1", "search_1", ids=[E("ana.silva@example.com")]), ob("f2", "search_1", ids=[E("bob@example.com")])])
        self.assertIn("another known user", v.resources["search_1"].conflict)
        self.assertEqual(v.usable(), [])

    def test_catalog_link_needs_the_subject_and_nobody_else(self):
        ok = claim("a1", "LINK_RESOURCE_IDENTITY", "export_7", "2026-09-05T00:00:00Z", "export_service",
                   "Data catalog linked export_7 (NST-77) to ana.silva@example.com and user_1.", ids=[("email", "ana.silva@example.com"), ("user_id", "user_1")])
        two = claim("a2", "LINK_RESOURCE_IDENTITY", "export_8", "2026-09-05T00:00:00Z", "export_service",
                    "linked export_8 (NST-88) to ana.silva@example.com and bob@example.com", ids=[("email", "ana.silva@example.com"), ("email", "bob@example.com")])
        v = self.link([], [ok, two])
        self.assertEqual(list(v.resources), ["export_7"])
        self.assertEqual(v.resources["export_7"].aliases, ["NST-77"])

    def test_catalog_link_contradicted_by_structured_evidence_of_a_stranger_is_dropped(self):
        c = claim("a1", "LINK_RESOURCE_IDENTITY", "marketing_1", "2026-09-05T00:00:00Z", "marketing_platform", "linked marketing_1 (marketing_1) to ana.silva@example.com and user_1.",
                  ids=[("email", "ana.silva@example.com"), ("user_id", "user_1")])
        v = self.link([ob("evidence_1", "marketing_1", fmt=SourceFormat.JSON, kind=ObservationKind.RECORD, ids=[E("stranger@elsewhere.org")])], [c])
        self.assertIn("contradicted", v.resources["marketing_1"].conflict)

    def test_the_same_contradiction_seen_only_in_a_screenshot_is_kept_and_flagged(self):
        c = claim("a1", "LINK_RESOURCE_IDENTITY", "marketing_1", "2026-09-05T00:00:00Z", "marketing_platform", "linked marketing_1 (marketing_1) to ana.silva@example.com and user_1.",
                  ids=[("email", "ana.silva@example.com"), ("user_id", "user_1")])
        v = self.link([ob("evidence_1", "marketing_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[E("stranger@elsewhere.org", "cells[0]")])], [c])
        self.assertIsNone(v.resources["marketing_1"].conflict)
        self.assertTrue(any("identity mismatch" in n for n in v.notes))

    def test_catalog_alias_found_in_an_eligible_document_becomes_presence_evidence(self):
        c = claim("a1", "LINK_RESOURCE_IDENTITY", "export_7", "2026-09-05T00:00:00Z", "export_service", "Data catalog linked export_7 (NST-77) to ana.silva@example.com and user_1.",
                  ids=[("email", "ana.silva@example.com"), ("user_id", "user_1")])
        corpus = Corpus([c], file_text={"doc_in": "statement NST-77 issued", "doc_late": "NST-77", "doc_early": "NST-77"},
                        file_captured={"doc_in": "2026-09-05T00:00:00Z", "doc_late": "2026-09-11T00:00:00Z", "doc_early": "2026-08-01T00:00:00Z"})
        d = directory()
        v = link_subject(corpus, d, d.resolve("ana.silva@example.com", AUD_AT), case())
        self.assertEqual(v.resources["export_7"].doc_presence, ["doc_in"])

    def test_pdf_is_linked_at_document_level_only_when_every_person_in_it_is_the_subject(self):
        pdf = lambda rid, e: ob("doc", rid, fmt=SourceFormat.PDF, kind=ObservationKind.RECORD, ids=[E(e, "cells[0]")] if e else [])  # noqa: E731
        mine = self.link([pdf(None, "ana.silva@example.com"), pdf("support_1", None)])
        self.assertIn("support_1", mine.resources)
        mixed = self.link([pdf(None, "ana.silva@example.com"), pdf(None, "bob@example.com"), pdf("support_1", None)])
        self.assertNotIn("support_1", mixed.resources)

    def test_claim_window_names_the_only_candidate_and_refuses_an_ambiguous_one(self):
        c1 = claim("a1", "DELETE_RECORD", "account_11", "2026-09-02T00:30:00Z", "account_service")
        c2 = claim("a2", "DELETE_RECORD", "account_12", "2026-09-02T01:00:00Z", "account_service")
        far = claim("a3", "DELETE_RECORD", "account_13", "2026-09-05T00:00:00Z", "account_service")
        self.assertEqual(self.link([], [c1, far]).resources["account_11"].methods, {"claim_window"})
        amb = self.link([], [c1, c2])
        self.assertEqual(amb.resources, {})
        self.assertTrue(any("ambiguous" in n for n in amb.notes))

    def test_claim_window_skips_resources_that_belong_to_somebody_else(self):
        mine, other = (claim("a1", "DELETE_RECORD", "account_11", "2026-09-02T00:30:00Z", "account_service"),
                       claim("a2", "DELETE_RECORD", "account_12", "2026-09-02T00:40:00Z", "account_service"))
        v = self.link([ob("evidence_1", "account_12", sf="http_status", sv="404", ids=[E("bob@example.com", "trace_context.lookup_key")])], [mine, other])
        self.assertEqual(list(v.resources), ["account_11"])

    def test_claim_window_never_overrides_a_stronger_link(self):
        c = claim("a1", "DELETE_RECORD", "account_11", "2026-09-02T00:30:00Z", "account_service")
        v = self.link([ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("ana.silva@example.com", "trace_context.lookup_key")])], [c])
        self.assertEqual(list(v.resources), ["account_9"])


# ============================================================================================ assessments
class TestAssessmentPerRule(unittest.TestCase):
    def test_rule01_user_profile_present_is_remaining_record_absent_is_compliant(self):
        a = assess("account_1", [ob("evidence_1", "account_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, sf="account_status", sv="ACTIVE", ids=[E("ana.silva@example.com")])])
        self.assertEqual((a.verdict, a.finding_op, a.remediation_op, a.verify_op), ("violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"))
        for sf, sv in (("http_status", "404"), ("status_code", 404), ("result", "NOT_FOUND"), ("rows", "0")):
            b = assess("account_1", [ob("evidence_1", "account_1", sf=sf, sv=sv)])
            self.assertEqual((b.verdict, b.verify_op, b.cite), ("compliant", "VERIFY_RECORD_ABSENT", "evidence_1"), (sf, sv))

    def test_rule01_a_ghost_row_in_a_replica_counts_even_when_the_primary_is_clean(self):
        prim = ob("evidence_1", "account_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, store="profiles_primary", role="primary", sf="http_status", sv="404", ordinal=0)
        rep = ob("evidence_1", "account_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, store="profiles_replica", role="replica", ordinal=1, ids=[E("ana.silva@example.com")])
        a = assess("account_1", [prim, rep])
        self.assertEqual((a.verdict, a.proof.store_role), ("violation", "replica"))

    def test_a_later_file_overrides_an_older_snapshot(self):
        old = ob("evidence_2", "account_1", cap="2026-09-03T00:00:00Z", at="2026-09-03T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL)
        new = ob("evidence_3", "account_1", cap="2026-09-09T00:00:00Z", at="2026-09-09T00:00:00Z", sf="http_status", sv="404")
        a = assess("account_1", [old, new])
        self.assertEqual((a.verdict, a.cite), ("compliant", "evidence_3"))

    def test_the_profile_service_copy_is_not_the_account_record(self):
        self.assertEqual(assess("account_1", [ob("evidence_1", "account_1", sf="http_status", sv="200", system="profile_service")]).verdict, "unknown")

    def test_workflow_claims_are_never_state(self):
        c = claim("a1", "DELETE_RECORD", "account_1", "2026-09-05T00:00:00Z", "account_service", "Deletion worker reported ... completed.")
        self.assertEqual(assess("account_1", [c]).verdict, "unknown")

    def test_snapshot_absence_proves_a_claim_named_account_and_prefers_the_primary_plus_replica_snapshot(self):
        sc = lambda fid, role: SnapshotScope(ScopeKind.SQL_TABLE, fid, "account_service", "customer_profiles", None, TimestampSource.NONE, 0, "file", store_role=role)  # noqa: E731
        corpus = Corpus([], [sc("evidence_6", "primary"), sc("evidence_6", "replica"), sc("evidence_7", "primary")],
                        file_captured={"evidence_6": "2026-09-03T00:00:00Z", "evidence_7": "2026-09-08T00:00:00Z"})
        weak = lr("account_5", [], methods=("claim_window",))
        a = AS.assess_resource(weak, rules(), AUD_AT, {}, corpus, REQ_AT)
        self.assertEqual((a.verdict, a.cite), ("compliant", "evidence_6"))
        self.assertEqual(AS.assess_resource(weak, rules(), AUD_AT, {}, Corpus([], []), REQ_AT).verdict, "unknown")

    def test_rule03_rule09_search_entry_and_export_must_be_deleted(self):
        for rid in ("search_1", "export_1"):
            a = assess(rid, [ob("evidence_1", rid, kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, ids=[E("ana.silva@example.com")])])
            self.assertEqual((a.verdict, a.finding_op, a.remediation_op), ("violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD"), rid)
        self.assertEqual(assess("search_1", [ob("evidence_1", "search_1", sf="result", sv="miss")]).verdict, "compliant")

    def test_rule10_marketing_contact_hosted_by_the_analytics_platform_is_deleted_not_anonymized(self):
        a = assess("analytics_9", [ob("evidence_1", "analytics_9", rtype="MARKETING_PROFILE", sf="email_opt_in", sv="true", fields={"rows": "1"})])
        self.assertEqual((a.category, a.verdict, a.finding_op, a.remediation_op), ("MARKETING_PROFILE", "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD"))
        self.assertEqual(a.system_id, "analytics_platform")

    def test_rule07_analytics_attributable_vs_anonymous(self):
        bad = assess("analytics_1", [ob("evidence_1", "analytics_1", kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, ids=[E("ana.silva@example.com", "email")])])
        self.assertEqual((bad.verdict, bad.finding_op, bad.remediation_op, bad.verify_op), ("violation", "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"))
        ok = assess("analytics_1", [ob("evidence_1", "analytics_1", kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, fields={"email": None})])
        self.assertEqual((ok.verdict, ok.verify_op), ("compliant", "VERIFY_RECORD_ANONYMIZED"))
        scan = assess("analytics_1", [ob("evidence_1", "analytics_1", sf="direct_identifiers", sv="1")])
        self.assertEqual(scan.verdict, "violation")
        ident = assess("analytics_1", [ob("evidence_1", "analytics_1", sf="result", sv="IDENTIFIABLE")])
        self.assertEqual(ident.verdict, "violation")

    def test_the_lookup_key_of_a_trace_does_not_make_an_anonymous_record_attributable(self):
        a = assess("analytics_1", [ob("evidence_1", "analytics_1", ids=[E("ana.silva@example.com", "trace_context.lookup_key")], sf="direct_identifiers", sv="0")])
        self.assertEqual(a.verdict, "compliant")

    def test_rule05_support_message_is_redacted_not_deleted(self):
        bad = assess("support_1", [ob("evidence_1", "support_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("ana.silva@example.com", "requester_email"), U("user_1", "customer_reference")])])
        self.assertEqual((bad.verdict, bad.finding_op, bad.remediation_op, bad.verify_op), ("violation", "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"))
        ok = assess("support_1", [ob("evidence_1", "support_1", kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, ids=[U("user_1", "customer_reference")], fields={"requester_email": None})])
        self.assertEqual(ok.verdict, "compliant")

    def test_support_replica_copy_without_a_deletion_marker_is_a_remaining_record(self):
        rows = ob("evidence_1", "support_2", collection="contact_query_completed", sf="rows", sv="1", system="support_replica", ordinal=0)
        marker = ob("evidence_1", "support_2", collection="deletion_marker_check", sf="marker_found", sv=False, at="2026-09-09T09:00:05Z", ordinal=1)
        a = assess("support_2", [rows, marker])
        self.assertEqual((a.verdict, a.finding_op, a.remediation_op), ("violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD"))
        gone = assess("support_2", [ob("evidence_1", "support_2", collection="deletion_marker_check", sf="marker_found", sv=True)])
        self.assertNotEqual(gone.verdict, "violation")

    def test_rule06_attachment_found_through_a_document_is_deleted(self):
        pdf = ob("doc", "support_3", fmt=SourceFormat.PDF, kind=ObservationKind.RECORD, ids=[("resource_ref", "support_3", "cells[0]")])
        a = AS.assess_resource(lr("support_3", [pdf]), rules(), AUD_AT, {"doc": "Continued - Attachment properties and upload history"})
        self.assertEqual((a.category, a.verdict, a.remediation_op), ("SUPPORT_ATTACHMENT", "violation", "DELETE_RECORD"))
        plain = AS.assess_resource(lr("support_3", [pdf]), rules(), AUD_AT, {"doc": "Support conversation export"})
        self.assertEqual(plain.category, "SUPPORT_MESSAGE")

    def test_rule15_tombstone_may_keep_only_the_stable_reference(self):
        bad = assess("tombstone_1", [ob("evidence_1", "tombstone_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1", "subject_reference"), E("ana.silva@example.com", "email"),
                                                                                                                  ("name", "Ana Silva", "name")])])
        self.assertEqual((bad.verdict, bad.finding_op, bad.remediation_op, bad.verify_op), ("violation", "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"))
        ok = assess("tombstone_1", [ob("evidence_1", "tombstone_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1", "subject_reference")])])
        self.assertEqual((ok.verdict, ok.verify_op), ("compliant", "VERIFY_RECORD_REDACTED"))

    def test_active_data_flow_is_a_finding_and_a_disabled_flow_a_proof(self):
        for v in (True, "true", 1):
            a = assess("data_flow_1", [ob("evidence_1", "data_flow_1", sf="enabled", sv=v)])
            self.assertEqual((a.verdict, a.finding_op, a.remediation_op, a.verify_op), ("violation", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"), v)
        for v in (False, "false", 0):
            self.assertEqual(assess("data_flow_1", [ob("evidence_1", "data_flow_1", sf="enabled", sv=v)]).verdict, "compliant", v)
        self.assertEqual(assess("data_flow_1", [ob("evidence_1", "data_flow_1", sf="result", sv="ACTIVE")]).verdict, "violation")

    def test_backup_is_retained_but_an_open_restore_path_is_a_risk(self):
        for sf, sv, risk in (("restore_allowed", 1, True), ("restore_allowed", False, False), ("eligible", "true", True), ("decision", "deny", False),
                             ("result", "ACTIVE", True), ("result", "BLOCKED", False)):
            a = assess("backup_1", [ob("evidence_1", "backup_1", sf=sf, sv=sv, fields={"deletion_block": "false"})])
            self.assertEqual(a.verdict, "violation" if risk else "compliant", (sf, sv))
            if risk:
                self.assertEqual((a.finding_op, a.remediation_op, a.verify_op), ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"))
        blocked = assess("backup_1", [ob("evidence_1", "backup_1", sf="eligible", sv="true", fields={"deletion_block": "true"})])
        self.assertEqual(blocked.verdict, "compliant")

    def test_a_screenshot_listing_is_an_inferred_restore_risk_and_says_so(self):
        row = ob("doc", "backup_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[("resource_ref", "backup_1", "cells[0]")], fields={"text": "backup_1 ana@x Archive"})
        a = AS.assess_resource(lr("backup_1", [row]), rules(), AUD_AT, {"doc": "Restore requests  Recent restores"})
        self.assertEqual(a.verdict, "violation")
        self.assertIn("INFERRED", a.reason)
        self.assertEqual(AS.assess_resource(lr("backup_1", [row]), rules(), AUD_AT, {"doc": "Archives list"}).verdict, "unknown")

    def test_rule12_rule13_required_records_are_retained_and_verified_present(self):
        for rid, cat in (("audit_record_1", "SECURITY_AUDIT_LOG"), ("legal_hold_1", "LEGAL_HOLD_RECORD")):
            a = assess(rid, [ob("evidence_1", rid, kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1")], fields={"retention_until": "2034-01-01T00:00:00Z"})])
            self.assertEqual((a.category, a.verdict, a.verify_op, a.remediation_op), (cat, "retained", "VERIFY_RECORD_PRESENT", None))

    def test_a_record_whose_retention_ended_is_not_claimed_as_required(self):
        a = assess("audit_record_1", [ob("evidence_1", "audit_record_1", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, fields={"retention_until": "2026-01-01T00:00:00Z"})])
        self.assertEqual(a.verdict, "unknown")

    def test_unknown_prefix_and_missing_evidence_are_unknown_not_guessed(self):
        self.assertIsNone(assess("mystery_1", [ob("evidence_1", "mystery_1", kind=ObservationKind.RECORD)]))
        self.assertEqual(assess("search_1", []).verdict, "unknown")

    def test_document_rows_are_positive_evidence_only(self):
        quiet = ob("doc", "analytics_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, fields={"text": "analytics_1 Overview"}, ids=[("resource_ref", "analytics_1", "cells[0]")])
        self.assertEqual(AS.assess_resource(lr("analytics_1", [quiet]), rules(), AUD_AT, {}).verdict, "unknown")   # silence is not proof of anonymity
        loud = ob("doc", "analytics_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[E("ana.silva@example.com", "cells[1]")], fields={"text": "x"})
        self.assertEqual(AS.assess_resource(lr("analytics_1", [loud]), rules(), AUD_AT, {}).verdict, "violation")
        named = ob("doc", "support_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, fields={"text": "support_1 - Ana Silva - Normal priority"})
        a = AS.assess_resource(lr("support_1", [named], subject_name="Ana Silva"), rules(), AUD_AT, {})
        self.assertEqual(a.verdict, "violation")

    def test_console_row_status_words_decide_a_data_flow(self):
        on = ob("doc", "data_flow_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, fields={"text": "data_flow_1 warehouse Continuous 1,284"})
        off = ob("doc", "data_flow_1", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, fields={"text": "data_flow_1 warehouse Paused"})
        self.assertEqual(AS.assess_resource(lr("data_flow_1", [on]), rules(), AUD_AT, {}).verdict, "violation")
        self.assertEqual(AS.assess_resource(lr("data_flow_1", [off]), rules(), AUD_AT, {}).verdict, "compliant")


# ============================================================================================ planning / output
class TestPlanner(unittest.TestCase):
    def violation(self, rid, system, ops, cite="evidence_1"):
        return AS.Assessment(rid, system, "X", "r", "violation", ops[0], ops[1], ops[2], proof=ob(cite, rid), reason="t")

    def sample(self):
        P = __import__("ghost_audit.engine.policy", fromlist=["x"])
        return [self.violation("search_2", "search_service", P.ACTION_OPS["DELETE"]), self.violation("data_flow_1", "integration_service", P.DATA_FLOW_OPS),
                self.violation("backup_1", "backup_service", P.RESTORE_OPS), self.violation("analytics_1", "analytics_platform", P.ACTION_OPS["ANONYMIZE"]),
                self.violation("search_10", "search_service", P.ACTION_OPS["DELETE"]),
                AS.Assessment("audit_record_1", "security_service", "SECURITY_AUDIT_LOG", "r12", "retained", verify_op="VERIFY_RECORD_PRESENT", proof=ob("evidence_1", "audit_record_1")),
                AS.Assessment("account_1", "account_service", "USER_PROFILE", "r1", "compliant", verify_op="VERIFY_RECORD_ABSENT", proof=ob("evidence_1", "account_1"))]

    def test_incomplete_plan_is_complete_ordered_and_contract_valid(self):
        steps = build_steps(self.sample(), "INCOMPLETE")
        self.assertEqual([s["step_no"] for s in steps], list(range(1, len(steps) + 1)))
        phases = [s["phase"] for s in steps]
        self.assertEqual(phases, sorted(phases, key=C.PHASE_RANK.get))
        rem = [s["operation"] for s in steps if s["phase"] == "REMEDIATION"]
        self.assertLess(rem.index("DISABLE_DATA_FLOW"), rem.index("DELETE_RECORD"))        # stop the copier before touching dependants
        self.assertLess(rem.index("BLOCK_RESTORE"), rem.index("DELETE_RECORD"))
        self.assertEqual([s["evidence_id"] for s in steps if s["phase"] != "FINDING"], [""] * sum(1 for s in steps if s["phase"] != "FINDING"))
        self.assertTrue(all(s["evidence_id"] == "evidence_1" for s in steps if s["phase"] == "FINDING"))
        self.assertIn(("VERIFICATION", "VERIFY_RECORD_ABSENT", "account_1"), [(s["phase"], s["operation"], s["resource_id"]) for s in steps])   # account stays gone
        self.assertIn(("VERIFICATION", "VERIFY_RECORD_PRESENT", "audit_record_1"), [(s["phase"], s["operation"], s["resource_id"]) for s in steps])

    def test_every_remediation_has_a_matching_verification(self):
        steps = build_steps(self.sample(), "INCOMPLETE")
        pairs = {"DELETE_RECORD": "VERIFY_RECORD_ABSENT", "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED"}
        ver = {(s["operation"], s["resource_id"]) for s in steps if s["phase"] == "VERIFICATION"}
        for s in steps:
            if s["phase"] == "REMEDIATION":
                self.assertIn((pairs[s["operation"]], s["resource_id"]), ver)

    def test_lexical_and_natural_resource_order_differ_only_when_digit_counts_differ(self):
        steps = [{"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "search_service", "resource_id": r, "state": "PRESENT", "evidence_id": "f", "step_no": 0}
                 for r in ("search_52", "search_1308")]
        self.assertEqual([s["resource_id"] for s in order_steps([dict(s) for s in steps], SortStrategy.LEXICAL)], ["search_1308", "search_52"])
        self.assertEqual([s["resource_id"] for s in order_steps([dict(s) for s in steps], SortStrategy.NATURAL)], ["search_52", "search_1308"])

    def test_complete_lists_only_cited_verifications(self):
        steps = build_steps(self.sample()[5:], "COMPLETE")
        self.assertEqual({s["phase"] for s in steps}, {"VERIFICATION"})
        self.assertTrue(all(s["evidence_id"] for s in steps))

    def test_duplicate_steps_are_collapsed(self):
        a = self.sample()
        self.assertEqual(len(build_steps(a + a, "INCOMPLETE")), len(build_steps(a, "INCOMPLETE")))

    def test_not_applicable_and_empty_plans_have_no_steps(self):
        self.assertEqual(build_steps(self.sample(), "NOT_APPLICABLE"), [])

    def test_writer_header_rows_json_and_validator_round_trip(self):
        engine = make_engine([ob("evidence_1", "search_7", cap="2026-09-09T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.JSON, ids=[E("ana.silva@example.com")])])
        decisions = [engine.decide(case(cid="case_2")), engine.decide(case(cid="case_10")),
                     engine.decide(case(cid="case_3", text="Please correct my surname. Do not delete anything."))]
        with tempfile.TemporaryDirectory() as tmp:
            for strat, first in ((SortStrategy.LEXICAL, "case_10"), (SortStrategy.NATURAL, "case_2")):
                p = Path(tmp) / ("o_%s.csv" % strat.value)
                self.assertEqual(write_output(decisions, p, strat), 3)
                raw = p.read_bytes()
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw)
                with open(p, encoding="utf-8", newline="") as handle:
                    rows = list(csv.reader(handle))
                self.assertEqual(rows[0], ["case_id", "deletion_status", "steps_json"])
                self.assertEqual(rows[1][0], first)
                for r in rows[1:]:
                    for s in json.loads(r[2]):
                        self.assertEqual(list(s), list(C.STEP_KEYS))
                rep = validate_csv(p, ValidatorConfig(case_id_order=strat, resource_order=SortStrategy.LEXICAL, expected_case_ids={"case_2", "case_10", "case_3"}, expected_row_count=3))
                self.assertTrue(rep.ok, rep.summary())

    def test_default_row_order_is_numeric_like_the_input_file_not_string_order(self):
        """Regression: the default used to be string order, which put case_100 before case_33 (the input file is numeric)."""
        engine = make_engine([])
        decisions = [engine.decide(case(cid=c, text="Please send me a copy of my data. Do not delete anything.")) for c in ("case_100", "case_33", "case_9", "case_550")]
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "o.csv"
            write_output(decisions, p)                                              # default strategy
            self.assertEqual([r["case_id"] for r in read_rows(p)], ["case_9", "case_33", "case_100", "case_550"])
            self.assertTrue(validate_csv(p, ValidatorConfig(case_id_order=SortStrategy.NATURAL, expected_case_ids={d.case_id for d in decisions})).ok)
            self.assertFalse(validate_csv(p, ValidatorConfig(case_id_order=SortStrategy.LEXICAL, expected_case_ids={d.case_id for d in decisions})).ok)

    def test_steps_json_is_compact_ascii_and_ordered(self):
        s = steps_json([{"step_no": 1, "phase": "FINDING", "system_id": "a", "resource_id": "b", "operation": "o", "state": "PRESENT", "evidence_id": "e"}])
        self.assertEqual(s, '[{"step_no":1,"phase":"FINDING","system_id":"a","resource_id":"b","operation":"o","state":"PRESENT","evidence_id":"e"}]')


# ============================================================================================ end to end (synthetic)
class TestEngineSynthetic(unittest.TestCase):
    def validate(self, *decisions):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "o.csv"
            write_output(decisions, p)
            return validate_csv(p, ValidatorConfig(expected_case_ids={d.case_id for d in decisions}))

    def incomplete_world(self):
        return [
            ob("evidence_1", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("old.ana@example.com")]),                       # historical e-mail still indexed
            ob("evidence_1", "data_flow_3", sf="enabled", sv=True, ids=[U("user_1", "subject_reference")]),
            ob("evidence_1", "backup_4", sf="restore_allowed", sv=1, ids=[E("ana.silva@example.com", "customer_email")]),
            ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("old.ana@example.com", "trace_context.lookup_key")]),
            ob("evidence_1", "audit_record_5", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1")], fields={"retention_until": "2033-01-01T00:00:00Z"}),
        ]

    def test_incomplete_with_historical_email_findings_remediation_and_verification(self):
        d = make_engine(self.incomplete_world()).decide(case(email="old.ana@example.com"))
        self.assertEqual(d.status, "INCOMPLETE")
        self.assertEqual([(s["operation"], s["resource_id"]) for s in d.steps if s["phase"] == "FINDING"],
                         [("REPORT_REMAINING_RECORD", "search_7"), ("REPORT_ACTIVE_DATA_FLOW", "data_flow_3"), ("REPORT_RESTORE_RISK", "backup_4")])
        self.assertTrue(all(s["evidence_id"] == "evidence_1" for s in d.steps if s["phase"] == "FINDING"))
        self.assertEqual(sorted(s["resource_id"] for s in d.steps if s["phase"] == "VERIFICATION"),
                         ["account_9", "audit_record_5", "backup_4", "data_flow_3", "search_7"])
        self.assertTrue(self.validate(d).ok)

    def test_complete_when_every_final_state_is_proven_and_retained_records_remain(self):
        world = [ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("ana.silva@example.com", "trace_context.lookup_key")]),
                 ob("evidence_1", "data_flow_3", sf="enabled", sv=False, ids=[U("user_1", "subject_reference")]),
                 ob("evidence_1", "backup_4", sf="restore_allowed", sv=False, ids=[U("user_1", "subject_reference")]),
                 ob("evidence_1", "audit_record_5", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[U("user_1")], fields={"retention_until": "2033-01-01T00:00:00Z"})]
        d = make_engine(world).decide(case())
        self.assertEqual(d.status, "COMPLETE")
        self.assertEqual({(s["operation"], s["resource_id"]) for s in d.steps},
                         {("VERIFY_RECORD_ABSENT", "account_9"), ("VERIFY_DATA_FLOW_DISABLED", "data_flow_3"), ("VERIFY_RESTORE_BLOCKED", "backup_4"), ("VERIFY_RECORD_PRESENT", "audit_record_5")})
        self.assertTrue(all(s["evidence_id"] == "evidence_1" for s in d.steps))
        self.assertTrue(self.validate(d).ok)

    def test_not_applicable_requests_get_an_empty_plan_even_when_records_remain(self):
        d = make_engine(self.incomplete_world()).decide(case(text="Please send me a copy of my data. I still use the account, so do not delete anything."))
        self.assertEqual((d.status, d.steps), ("NOT_APPLICABLE", []))
        self.assertTrue(self.validate(d).ok)

    def test_evidence_captured_after_audit_at_cannot_change_the_answer(self):
        base = [ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("ana.silva@example.com", "trace_context.lookup_key")])]
        later = [ob("evidence_4", "search_7", cap="2026-09-11T00:00:00Z", at="2026-09-11T00:00:00Z", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("ana.silva@example.com")]),
                 ob("evidence_5", "account_9", cap="2026-09-12T00:00:00Z", at="2026-09-12T00:00:00Z", sf="http_status", sv="200", ids=[E("ana.silva@example.com", "trace_context.lookup_key")])]
        a, b = make_engine(base).decide(case()), make_engine(base + later).decide(case())
        self.assertEqual((a.status, a.steps), (b.status, b.steps))
        self.assertEqual(a.status, "COMPLETE")

    def test_evidence_from_before_the_request_does_not_prove_the_outcome(self):
        stale = [ob("evidence_2", "account_9", cap="2026-08-01T00:00:00Z", at="2026-08-01T00:00:00Z", sf="http_status", sv="404", ids=[E("ana.silva@example.com", "trace_context.lookup_key")])]
        d = make_engine(stale).decide(case())
        self.assertEqual(d.steps, [])
        self.assertTrue(any("unproven" in n for n in d.notes))

    def test_lookalike_email_and_another_ana_silva_are_never_merged(self):
        world = [ob("evidence_1", "search_7", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("ana.silva@example.com.br"), ("name", "Ana Silva", "display_name")]),
                 ob("evidence_1", "search_8", kind=ObservationKind.RECORD, fmt=SourceFormat.SQL, ids=[E("ana.s@example.org"), U("user_3")]),
                 ob("evidence_1", "account_9", sf="http_status", sv="404", ids=[E("ana.silva@example.com", "trace_context.lookup_key")])]
        d = make_engine(world).decide(case())
        self.assertEqual(d.status, "COMPLETE")
        self.assertNotIn("search_7", {s["resource_id"] for s in d.steps})
        self.assertNotIn("search_8", {s["resource_id"] for s in d.steps})

    def test_an_activity_claim_of_success_does_not_make_a_case_complete(self):
        claims = [claim("a1", "DELETE_RECORD", "account_9", "2026-09-02T00:30:00Z", "account_service", "Deletion worker reported completed", "SUCCESS")]
        d = make_engine([], ).decide(case())
        d2 = make_engine(claims).decide(case())
        for x in (d, d2):
            self.assertEqual(x.steps, [])

    def test_ocr_uncertain_identifier_alone_never_creates_a_finding(self):
        weak = ob("doc", "export_5", fmt=SourceFormat.IMAGE, kind=ObservationKind.RECORD, ids=[("email", "ana.silva@example.com", "cells[1]", True)])
        d = make_engine([weak]).decide(case())
        self.assertEqual(d.steps, [])

    def test_ambiguous_and_unknown_identities_produce_an_unmistakably_invalid_row_not_a_guess(self):
        for email, why in (("shared@example.com", "ambiguous"), ("nobody@example.com", "unresolved")):
            d = make_engine(self.incomplete_world()).decide(case(email=email))
            self.assertEqual(d.steps, [], why)
            self.assertTrue(any(why in n for n in d.notes))
            self.assertFalse(self.validate(d).ok)                         # surfaced by the validator, never silently accepted

    def test_claim_named_account_is_proven_absent_by_a_primary_replica_snapshot(self):
        sc = lambda role: SnapshotScope(ScopeKind.SQL_TABLE, "evidence_9", "account_service", "customer_profiles", None, TimestampSource.NONE, 0, "file", store_role=role)  # noqa: E731
        eng = make_engine([claim("a1", "DELETE_RECORD", "account_5", "2026-09-02T00:30:00Z", "account_service")], [sc("primary"), sc("replica")])
        eng.corpus.file_captured["evidence_9"] = "2026-09-05T00:00:00Z"
        d = eng.decide(case())
        self.assertEqual((d.status, [(s["operation"], s["resource_id"], s["evidence_id"]) for s in d.steps]), ("COMPLETE", [("VERIFY_RECORD_ABSENT", "account_5", "evidence_9")]))

    def test_decisions_are_deterministic(self):
        eng = make_engine(self.incomplete_world())
        self.assertEqual([s for s in eng.decide(case()).steps], [s for s in eng.decide(case()).steps])


# ============================================================================================ real data
@lru_cache(maxsize=1)
def real_engine() -> AuditEngine:
    return AuditEngine(DATASET, corpus=Corpus.load_shared(DATASET))


@lru_cache(maxsize=1)
def real_decisions():
    eng = real_engine()
    rows = read_rows(DATASET / "deletion_requests.csv")
    return rows, {r["case_id"]: eng.decide(r) for r in rows}


@needs_full
class TestRealDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.dec = real_decisions()
        cls.req = {r["case_id"]: r for r in cls.rows}
        cls.manifest = {r["file_id"]: r for r in read_rows(DATASET / "evidence_files.csv")}

    def test_all_518_cases_are_decided_with_a_valid_status(self):
        self.assertEqual(len(self.dec), 518)
        self.assertEqual(set(d.status for d in self.dec.values()) - {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}, set())
        self.assertEqual(sum(1 for d in self.dec.values() if d.status == "NOT_APPLICABLE"), 10)

    def test_written_output_is_valid_complete_and_in_contract_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "output.csv"
            self.assertEqual(write_output(self.dec.values(), p), 518)
            rep = validate_csv(p, ValidatorConfig(case_id_order=SortStrategy.NATURAL, resource_order=SortStrategy.LEXICAL, expected_case_ids=set(self.dec), expected_row_count=518))
            self.assertTrue(rep.ok, rep.summary() + "\n" + "\n".join(str(i) for i in rep.errors[:5]))
            rows = read_rows(p)
            self.assertEqual([r["case_id"] for r in rows], [r["case_id"] for r in self.rows], "default row order must equal dataset/deletion_requests.csv")
            self.assertEqual(rows[0]["case_id"] + "|" + rows[-1]["case_id"], "case_33|case_550")
            self.assertEqual(len({r["case_id"] for r in rows}), 518)

    def test_every_citation_is_a_real_file_inside_the_case_window(self):
        for cid, d in self.dec.items():
            r = self.req[cid]
            for s in d.steps:
                e = s["evidence_id"]
                if s["phase"] == "FINDING" or (d.status == "COMPLETE"):
                    self.assertIn(e, self.manifest, "%s cites unknown evidence %r" % (cid, e))
                    cap = self.manifest[e]["captured_at"]
                    self.assertLessEqual(cap, r["audit_at"], "%s cites %s captured after audit_at" % (cid, e))
                    self.assertGreaterEqual(cap, r["requested_at"], "%s cites %s captured before the request" % (cid, e))
                else:
                    self.assertEqual(e, "", "%s: future steps must not cite evidence" % cid)

    def test_incomplete_cases_have_findings_remediation_and_verification_and_complete_have_only_verification(self):
        for cid, d in self.dec.items():
            phases = Counter(s["phase"] for s in d.steps)
            if d.status == "INCOMPLETE":
                self.assertTrue(phases["FINDING"] and phases["REMEDIATION"] and phases["VERIFICATION"], cid)
            elif d.status == "COMPLETE":
                self.assertEqual(set(phases), {"VERIFICATION"}, cid)
            else:
                self.assertEqual(d.steps, [], cid)

    def test_resources_cited_in_findings_were_linked_by_a_recorded_method(self):
        for cid, d in self.dec.items():
            for s in d.steps:
                if s["phase"] == "FINDING":
                    self.assertTrue(d.view.resources[s["resource_id"]].methods, cid)

    def test_no_decision_depends_on_evidence_after_audit_at(self):
        """Property: physically removing every file/claim later than audit_at must not change a single decision."""
        eng = real_engine()
        base = eng.corpus
        for cid in sorted(self.dec)[::9]:
            r = self.req[cid]
            aud = r["audit_at"]
            # independent of Corpus.eligible on purpose: a property test must not trust the code it is checking
            keep = [o for o in base.observations if (o.provenance.file_captured_at or "") <= aud and (o.effective_time().value or "") <= aud] \
                + [c for c in base.claims if (c.record_observed_at or "") <= aud]
            cut = Corpus(keep, base.scopes, file_text=base.file_text, file_captured={k: v for k, v in base.file_captured.items() if v <= aud})
            alt = AuditEngine(DATASET, corpus=cut).decide(r)
            self.assertEqual((alt.status, alt.steps), (self.dec[cid].status, self.dec[cid].steps), cid)

    def test_a_later_restore_recreation_does_not_change_an_earlier_audit(self):
        # the only RESTORE_BACKUP claim (Aug 22) postdates this case's audit_at (Apr 30): the decision must not mention search_4882
        for cid, d in self.dec.items():
            if d.resolution and d.resolution.user_id == "user_16":
                self.assertLess(self.req[cid]["audit_at"], "2026-08-22T00:00:00Z")
                self.assertNotIn("search_4882", {s["resource_id"] for s in d.steps})

    def test_every_step_follows_the_operation_table_of_problem_statement_md(self):
        """Independent of contracts.py: the table is parsed from the challenge statement itself."""
        text = (REPO_ROOT / "problem_statement.md").read_text(encoding="utf-8").replace("\r\n", "\n")
        table = [m.groups() for m in re.finditer(r"^\|\s*`(FINDING|REMEDIATION|VERIFICATION)`\s*\|\s*`(\w+)`\s*\|\s*`(\w+)`", text, re.M)]
        self.assertEqual(len(table), 15)
        index = {(p, o): i for i, (p, o, _s) in enumerate(table)}
        state = {o: s for _p, o, s in table}
        keys = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
        pairs = {"DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED", "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
                 "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED"}
        for cid, d in self.dec.items():
            st = d.steps
            self.assertEqual([s["step_no"] for s in st], list(range(1, len(st) + 1)), cid)
            for s in st:
                self.assertEqual((list(s), state[s["operation"]]), (keys, s["state"]), cid)
            self.assertEqual(st, sorted(st, key=lambda s: (index[(s["phase"], s["operation"])], s["system_id"], s["resource_id"])), cid)
            verified = {(s["operation"], s["system_id"], s["resource_id"]) for s in st if s["phase"] == "VERIFICATION"}
            found = {(s["system_id"], s["resource_id"]) for s in st if s["phase"] == "FINDING"}
            rem = [s["operation"] for s in st if s["phase"] == "REMEDIATION"]
            for s in st:
                if s["phase"] == "REMEDIATION":
                    self.assertIn((pairs[s["operation"]], s["system_id"], s["resource_id"]), verified, cid)
                    self.assertIn((s["system_id"], s["resource_id"]), found, cid)
            stops = [i for i, o in enumerate(rem) if o in ("DISABLE_DATA_FLOW", "BLOCK_RESTORE")]
            edits = [i for i, o in enumerate(rem) if o in ("DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD")]
            if stops and edits:
                self.assertLess(max(stops), min(edits), "%s: copiers and restore paths must be stopped before records are edited" % cid)

    def test_policy_invariants_hold_against_raw_observation_fields(self):
        """Independent re-derivation (does not call the assessors): active sync, open restore, exposed tombstone and retained records."""
        from ghost_audit.evidence.model import flag_value
        when = lambda o: o.effective_time().value or ""  # noqa: E731
        checked = Counter()
        for cid, d in self.dec.items():
            if d.status == "NOT_APPLICABLE":
                continue
            steps = {(s["operation"], s["resource_id"]) for s in d.steps}
            for rid, lr in d.view.resources.items():
                if lr.conflict:
                    continue
                obs = lr.observations
                if rid.startswith("data_flow_"):
                    seen = sorted([o for o in obs if o.state_field == "enabled" and flag_value(o.state_value) is not None], key=when)
                    if seen:
                        checked["flow"] += 1
                        self.assertEqual(bool(flag_value(seen[-1].state_value)), ("REPORT_ACTIVE_DATA_FLOW", rid) in steps, "%s %s" % (cid, rid))
                if rid.startswith("backup_"):
                    seen = sorted([o for o in obs if o.state_field == "restore_allowed" and flag_value(o.state_value) is not None], key=when)
                    if seen:
                        checked["restore"] += 1
                        self.assertEqual(bool(flag_value(seen[-1].state_value)), ("REPORT_RESTORE_RISK", rid) in steps, "%s %s" % (cid, rid))
                if rid.startswith("tombstone_"):
                    rec = sorted([o for o in obs if o.collection == "deleted_customer_references" or o.record_type == "ACCOUNT_TOMBSTONE"], key=when)
                    if rec:
                        checked["tombstone"] += 1
                        direct = any(i.kind in ("email", "email_hash", "phone", "name") and not i.path.startswith("trace") for i in rec[-1].identifiers.items)
                        self.assertEqual(direct, ("REPORT_EXPOSED_PII", rid) in steps, "%s %s" % (cid, rid))
                if rid.startswith(("audit_record_", "legal_hold_")) and [o for o in obs if o.kind.value == "record" or str(o.fields.get("rows", "")) not in ("", "0")]:
                    checked["retained"] += 1
                    self.assertIn(("VERIFY_RECORD_PRESENT", rid), steps, "%s: a retained record is present but not verified" % cid)
        self.assertGreater(checked["flow"], 100)
        self.assertGreater(checked["retained"], 200)
        self.assertGreater(checked["restore"], 30)
        self.assertGreater(checked["tombstone"], 0)

    def test_the_run_is_deterministic(self):
        eng = real_engine()
        for r in self.rows[::37]:
            self.assertEqual(eng.decide(r).steps, self.dec[r["case_id"]].steps)

    def test_workflow_reported_status_is_not_trusted(self):
        c = Counter((self.req[cid]["reported_status"], d.status) for cid, d in self.dec.items())
        self.assertGreater(c[("COMPLETE", "INCOMPLETE")], 0)      # reported COMPLETE contradicted by evidence
        self.assertGreater(c[("NOT_STARTED", "COMPLETE")], 0)     # reported NOT_STARTED, evidence shows compliance

    def test_public_samples_regression_development_data_not_an_accuracy_claim(self):
        eng = real_engine()
        rows = read_rows(DATASET / "sample_deletion_requests.csv")
        pred = {}
        for r in rows:
            d = eng.decide(r)
            pred[r["case_id"]] = (d.status, d.steps)
        m = evaluate(pred, read_output(DATASET / "sample_output.csv"))
        self.assertEqual(m["status_accuracy"], 1.0)
        self.assertEqual(m["steps_extra"], 0)
        self.assertEqual(m["evidence_accuracy_on_matched"], 1.0)
        self.assertGreaterEqual(m["step_recall"], 0.85)


if __name__ == "__main__":
    unittest.main()
