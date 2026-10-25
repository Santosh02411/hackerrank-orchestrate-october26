"""Link evidence to the resolved subject without ever merging unrelated customers.

Link methods, strongest first (every resource records which ones supported it):

``identifier``   an eligible observation carries a strong identifier (e-mail, hash, phone, user_id) that the subject held
                 at ``audit_at``. OCR identifiers flagged uncertain are NOT used.
``trace``        the identifier is the lookup key of the trace that returned the resource (``trace_context.*``).
``document``     a PDF in which every person-identifying value belongs to the subject; its resource references are linked.
``catalog``      a ``LINK_RESOURCE_IDENTITY`` activity row naming the resource AND the subject (and nobody else).
``claim_window`` (weak) the only workflow claim for that kind of resource within +-2 h of ``reported_at``, on a resource not
                 tied to anyone else. Used only to name the account / analytics profile when nothing stronger exists.

A resource is dropped as a ``conflict`` when its observations carry strong identifiers owned by another known user, or
(for catalog/claim links) an identifier that is not the subject's at all.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from ..evidence.model import Observation, SourceFormat
from .corpus import Corpus, identifier_keys
from .identity import norm_email, norm_phone
from .identity import IdentityDirectory, Resolution

_ALIAS = re.compile(r"(?:linked|confirmed)\s+(\S+)\s+\(([^)]+)\)")      # "linked export_1842 (NST-2026-0718-1842) to ..."
CLAIM_WINDOW_HOURS = 2.0
_P = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
# claim event type -> (resource prefix, target system) that claim_window attribution may name
CLAIM_WINDOW_KINDS = {"account_": ("DELETE_RECORD", "account_service"), "analytics_": ("ANONYMIZE_RECORD", "analytics_platform")}


@dataclass
class LinkedResource:
    resource_id: str
    methods: Set[str] = field(default_factory=set)
    observations: List[Observation] = field(default_factory=list)   # eligible, non-claim, deduplicated
    claims: List[Observation] = field(default_factory=list)         # activity rows on the resource (claims only)
    conflict: Optional[str] = None
    from_document: bool = False
    subject_name: Optional[str] = None                              # corroboration only: a document row may show the subject's name
    doc_presence: List[str] = field(default_factory=list)           # eligible documents that mention the catalog alias of this resource
    aliases: List[str] = field(default_factory=list)

    @property
    def weak(self) -> bool:
        return self.methods <= {"claim_window"}


@dataclass
class SubjectView:
    resolution: Resolution
    audit_at: str
    resources: Dict[str, LinkedResource] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def usable(self) -> List[LinkedResource]:
        return [r for _k, r in sorted(self.resources.items()) if r.conflict is None]


def _norm(kind: str, value: str) -> str:
    return norm_email(value) if kind == "email" else norm_phone(value) if kind == "phone" else value.strip().lower() if kind == "email_hash" else value.strip()


def _owners(directory: IdentityDirectory, o: Observation, skip_uncertain: bool = True) -> Set[str]:
    out: Set[str] = set()
    for kind, value, unc in identifier_keys(o):
        if unc and skip_uncertain:
            continue
        out |= directory.owners_of(kind, value)
    return out


def link_subject(corpus: Corpus, directory: IdentityDirectory, res: Resolution, case: Dict[str, str]) -> SubjectView:
    aud = case["audit_at"]
    since = case["requested_at"]
    S = res.identity
    view = SubjectView(res, aud)

    def add(rid: str, method: str, o: Optional[Observation] = None) -> LinkedResource:
        lr = view.resources.setdefault(rid, LinkedResource(rid, subject_name=S.name))
        lr.methods.add(method)
        return lr

    # 1. identifier / trace links -------------------------------------------------------------------------
    doc_hits: Dict[str, List[Observation]] = defaultdict(list)
    seen: Set[int] = set()
    keys = [("email", e) for e in S.emails] + [("email_hash", h) for h in S.hashes] + [("phone", p) for p in S.phones] + [("user_id", S.user_id)]
    for key in keys:
        for o in corpus.by_identifier.get(key, ()):
            if id(o) in seen or not corpus.eligible(o, aud, since):
                continue
            hit = [(k, v, u) for k, v, u in identifier_keys(o) if (k, v) == key]
            if all(u for _k, _v, u in hit):                      # only OCR-uncertain readings match: do not link
                view.notes.append("uncertain OCR identifier ignored on %s" % o.obs_id)
                continue
            seen.add(id(o))
            multi_region = "multi_region_row" in o.flags
            if o.provenance.source_format is SourceFormat.PDF:
                doc_hits[o.provenance.file_id].append(o)
            if o.resource_id and not multi_region:
                paths = [i.path for i in o.identifiers.items if i.kind == key[0] and _norm(i.kind, i.value) == key[1]]
                add(o.resource_id, "trace" if paths and all(p.startswith("trace_context") for p in paths) else "identifier")

    # 2. PDF documents that concern only the subject ---------------------------------------------------------
    for fid, hits in doc_hits.items():
        owners: Set[str] = set()
        for o in corpus.observations:
            if o.provenance.file_id == fid:
                owners |= _owners(directory, o)
        if owners == {S.user_id}:
            for o in corpus.observations:
                if o.provenance.file_id == fid and o.resource_id and corpus.eligible(o, aud, since):
                    add(o.resource_id, "document").from_document = True

    # 3. explicit catalog links (LINK_RESOURCE_IDENTITY) ---------------------------------------------------------
    for c in corpus.eligible_claims(aud):
        if c.event_type != "LINK_RESOURCE_IDENTITY" or not c.resource_id:
            continue
        users: Set[str] = set()
        for kind, value, _u in identifier_keys(c):
            users |= directory.owners_of(kind, value)
        if users == {S.user_id}:
            lr = add(c.resource_id, "catalog")
            m = _ALIAS.search(str(c.fields.get("details", "")))
            if m and m.group(2) != c.resource_id:
                lr.aliases.append(m.group(2))

    # 4. propagate: every eligible observation of a linked resource, with conflict detection ----------------------------
    for rid, lr in list(view.resources.items()):
        lr.observations = corpus.eligible_on(rid, aud, since)
        lr.claims = [c for c in corpus.claims_by_resource.get(rid, ()) if (c.record_observed_at or "") <= aud]
        for alias in lr.aliases:                                   # a document that prints the catalog alias shows the record exists
            for fid, text in sorted(corpus.file_text.items(), key=lambda kv: corpus.file_captured.get(kv[0], "")):
                cap = corpus.file_captured.get(fid, "")
                if alias in text and since <= cap <= aud:
                    lr.doc_presence.append(fid)
        foreign: Set[str] = set()
        stray = False
        for o in lr.observations:
            others = _owners(directory, o) - {S.user_id}
            foreign |= others
            if not others and lr.methods <= {"catalog", "claim_window"}:
                for kind, value, unc in identifier_keys(o):
                    if kind in ("email", "phone", "email_hash") and not unc and not S.contains(kind, value):
                        if o.provenance.source_format in (SourceFormat.PDF, SourceFormat.IMAGE):
                            view.notes.append("identity mismatch on %s: %s shows %s, the catalog attributes it to the subject; kept (catalog link) "
                                              "and flagged" % (rid, o.provenance.citable_id, value))
                        else:
                            stray = True
        if foreign and not (lr.methods & {"identifier", "trace", "document"}):
            lr.conflict = "linked weakly but carries identifiers of another user: %s" % ",".join(sorted(foreign))
        elif foreign:
            lr.conflict = "carries identifiers of another known user: %s" % ",".join(sorted(foreign))
        elif stray:
            lr.conflict = "catalog link contradicted by a different identifier on the resource's own evidence"
        if lr.conflict:
            view.notes.append("conflict %s: %s" % (rid, lr.conflict))

    # 5. weak claim-window attribution for the account / analytics resource, only if nothing stronger exists ---------------
    reported, requested = _P(case["reported_at"]), _P(case["requested_at"])
    for prefix, (etype, tsys) in CLAIM_WINDOW_KINDS.items():
        if any(rid.startswith(prefix) and lr.conflict is None and not lr.weak for rid, lr in view.resources.items()):
            continue
        cands = []
        for c in corpus.eligible_claims(aud):
            if c.event_type != etype or c.system_id != tsys or not c.resource_id or not c.resource_id.startswith(prefix):
                continue
            t = _P(c.record_observed_at)
            if t < requested or abs((t - reported).total_seconds()) > CLAIM_WINDOW_HOURS * 3600:
                continue
            ev = corpus.eligible_on(c.resource_id, aud, since)
            other = set()
            for o in ev:
                other |= _owners(directory, o)
            if other and S.user_id not in other:
                continue                                           # tied to somebody else
            if c.resource_id in view.resources:
                continue
            cands.append(c.resource_id)
        cands = sorted(set(cands))
        if len(cands) == 1:
            lr = add(cands[0], "claim_window")
            lr.observations = corpus.eligible_on(cands[0], aud, since)
            lr.claims = [c for c in corpus.claims_by_resource.get(cands[0], ()) if (c.record_observed_at or "") <= aud]
        elif len(cands) > 1:
            view.notes.append("claim_window ambiguous for %s*: %d candidates, none attributed" % (prefix, len(cands)))
    return view
