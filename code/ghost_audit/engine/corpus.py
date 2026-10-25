"""All parsed evidence, indexed, with the audit-time eligibility rule.

Eligibility (AGENTS.md 6.2/6.6, validated against the 75 evidence citations of the public sample, every one of
which is a file captured at or before its case's ``audit_at``):

* a file-derived observation is usable only if the FILE's manifest ``captured_at`` is <= ``audit_at`` (the boundary
  is inclusive) - a later-captured file is never used, not even to learn that a record exists;
* and its own effective time (record time, else snapshot time) must be <= ``audit_at``;
* an activity row is a CLAIM and is usable as such only if its ``event_time`` <= ``audit_at``.
"""
from __future__ import annotations

import pickle
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from ..evidence import FULL_FORMATS, ObservationKind, ingest_dataset
from ..evidence.model import Observation, SnapshotScope
from .identity import norm_email, norm_phone


def identifier_keys(o: Observation) -> List[Tuple[str, str, bool]]:
    """(kind, normalised value, uncertain) for every strong identifier on an observation."""
    out = []
    for i in o.identifiers.items:
        if i.kind == "email":
            out.append(("email", norm_email(i.value), i.uncertain))
        elif i.kind == "email_hash":
            out.append(("email_hash", i.value.strip().lower(), i.uncertain))
        elif i.kind == "phone":
            out.append(("phone", norm_phone(i.value), i.uncertain))
        elif i.kind == "user_id":
            out.append(("user_id", i.value.strip(), i.uncertain))
    return out


class Corpus:
    def __init__(self, observations: Iterable[Observation], scopes: Iterable[SnapshotScope] = (), formats: Tuple = (),
                 file_text: Optional[Dict[str, str]] = None, file_captured: Optional[Dict[str, str]] = None) -> None:
        self.file_text: Dict[str, str] = file_text or {}
        self.observations: List[Observation] = []
        self.claims: List[Observation] = []
        for o in observations:
            (self.claims if o.kind is ObservationKind.CLAIM else self.observations).append(o)
        self.scopes = list(scopes)
        self.formats = formats
        self.file_captured: Dict[str, str] = dict(file_captured or {})
        for o in self.observations:                       # fallback when no manifest map was supplied
            if o.provenance.file_id and o.provenance.file_captured_at:
                self.file_captured.setdefault(o.provenance.file_id, o.provenance.file_captured_at)
        self.by_resource: Dict[str, List[Observation]] = defaultdict(list)
        self.by_identifier: Dict[Tuple[str, str], List[Observation]] = defaultdict(list)
        self.claims_by_resource: Dict[str, List[Observation]] = defaultdict(list)
        for o in self.observations:
            if o.resource_id:
                self.by_resource[o.resource_id].append(o)
            for kind, value, _unc in identifier_keys(o):
                self.by_identifier[(kind, value)].append(o)
        for c in self.claims:
            if c.resource_id:
                self.claims_by_resource[c.resource_id].append(c)

    # ---- construction -----------------------------------------------------------------------------------
    @classmethod
    def load(cls, dataset_dir: Union[str, Path], cache: Optional[Union[str, Path]] = None) -> "Corpus":
        """Parse every evidence format (OCR included) or read a developer cache written by :meth:`save_cache`."""
        if cache and Path(cache).is_file():
            obs, scopes, file_text, captured = pickle.loads(Path(cache).read_bytes())
            return cls(obs, scopes, file_text=file_text, file_captured=captured)
        result = ingest_dataset(dataset_dir, formats=FULL_FORMATS)
        obs = [o for p in result.all_parsed() for o in p.observations]
        scopes = [s for p in result.files for s in p.scopes]
        file_text = {p.file_id: " ".join([str(o.fields.get("text", "")) for o in p.observations] +
                                         [str(r.get("text", "")) for r in p.metadata.get("unanchored_rows", [])])
                     for p in result.files if p.source_format.value in ("pdf", "image")}
        corpus = cls(obs, scopes, file_text=file_text, file_captured={p.file_id: p.ref.captured_at for p in result.files if p.ref})
        corpus.parse_status = {p.file_id or "activity": p.status.value for p in result.all_parsed()}
        corpus.parse_warnings = [(p.file_id, w.code, w.level) for p in result.all_parsed() for w in p.warnings]
        return corpus

    _shared: Dict[str, "Corpus"] = {}

    @classmethod
    def load_shared(cls, dataset_dir: Union[str, Path]) -> "Corpus":
        """Parse once per process and reuse (used by the test-suite so the OCR pass is not repeated by every test module)."""
        key = str(Path(dataset_dir).resolve())
        if key not in cls._shared:
            cls._shared[key] = cls.load(dataset_dir)
        return cls._shared[key]

    def save_cache(self, path: Union[str, Path]) -> None:
        Path(path).write_bytes(pickle.dumps((self.observations + self.claims, self.scopes, self.file_text, self.file_captured)))

    # ---- eligibility --------------------------------------------------------------------------------------
    @staticmethod
    def eligible(o: Observation, audit_at: str, since: Optional[str] = None) -> bool:
        """Usable at ``audit_at``; with ``since`` (= the request time) also not older than the request, because evidence
        from before the request cannot describe its outcome (0 of the 75 sample citations precede ``requested_at``)."""
        cap = o.provenance.file_captured_at
        if o.provenance.file_id and cap and cap > audit_at:
            return False
        t = o.effective_time().value
        if t is not None and t > audit_at:
            return False
        if since and ((o.provenance.file_id and cap and cap < since) or (t is not None and t < since)):
            return False
        return True

    def eligible_on(self, resource_id: str, audit_at: str, since: Optional[str] = None) -> List[Observation]:
        return [o for o in self.by_resource.get(resource_id, ()) if self.eligible(o, audit_at, since)]

    def account_snapshots(self, since: str, audit_at: str) -> List[Dict[str, object]]:
        """Full-table snapshots of the account service captured inside [since, audit_at]: a record missing from one of
        these is proven absent. ``both`` marks files that contain primary AND replica tables (they also rule out ghost replicas)."""
        files: Dict[str, Dict[str, object]] = {}
        for s in self.scopes:
            kind = s.kind.value
            full = (kind == "sql_table" and s.system_id == "account_service") or \
                   (kind == "json_snapshot" and (s.store or "").endswith("account_service/customer_profiles"))
            if not full or not s.file_id:
                continue
            cap = self.file_captured.get(s.file_id)
            if cap is None or cap < since or cap > audit_at:
                continue
            f = files.setdefault(s.file_id, {"file_id": s.file_id, "captured_at": cap, "roles": set()})
            f["roles"].add(s.store_role)
        for f in files.values():
            f["both"] = {"primary", "replica"} <= f["roles"]
        return sorted(files.values(), key=lambda f: (f["captured_at"], f["file_id"]))

    def eligible_claims(self, audit_at: str) -> List[Observation]:
        return [c for c in self.claims if (c.record_observed_at or "") <= audit_at]
