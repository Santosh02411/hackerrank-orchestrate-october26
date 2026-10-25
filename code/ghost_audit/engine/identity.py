"""Identity resolution: request e-mail -> one stable ``user_id`` and the identifiers it held at ``audit_at``.

Sources: ``user_identities.csv`` (current snapshot) and ``user_audit_log.csv`` (history of email,
email_hash and phone changes; names are not logged, so only the current name is known).

Rules
* The request e-mail may be a current or a historical address (case-insensitive, trimmed).
* It resolves only if it maps to exactly ONE user; an address shared by several users is ``ambiguous`` and is
  never merged (no such address exists in the supplied data, but the guard is tested).
* As-of semantics: the identifier set contains every value the user held up to ``audit_at``; a change that is
  logged AFTER ``audit_at`` is not applied (its new value did not exist yet, its old value did).
* The SHA-256 of every held e-mail is added to the hash set, because older systems may store only the hash.
* Names are kept only as corroboration (they can collide: the data has repeated names); they never link evidence.
"""
from __future__ import annotations

import csv
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple, Union

STRONG_KINDS = ("email", "email_hash", "phone", "user_id")


def norm_email(value: str) -> str:
    return value.strip().lower()


def norm_phone(value: str) -> str:
    return re.sub(r"\D", "", value)


@dataclass(frozen=True)
class IdentitySet:
    user_id: str
    emails: FrozenSet[str]
    hashes: FrozenSet[str]
    phones: FrozenSet[str]
    name: Optional[str]

    def contains(self, kind: str, value: str) -> bool:
        if kind == "email":
            return norm_email(value) in self.emails
        if kind == "email_hash":
            return value.strip().lower() in self.hashes
        if kind == "phone":
            return norm_phone(value) in self.phones
        if kind == "user_id":
            return value.strip() == self.user_id
        return False


@dataclass(frozen=True)
class Resolution:
    status: str                      # "resolved" | "unresolved" | "ambiguous"
    request_email: str
    user_id: Optional[str] = None
    via: Optional[str] = None        # "current" | "historical"
    candidates: Tuple[str, ...] = ()
    identity: Optional[IdentitySet] = None


class IdentityDirectory:
    def __init__(self, identities: List[Dict[str, str]], audit: List[Dict[str, str]]) -> None:
        self.current = {r["user_id"]: r for r in identities}
        self._events: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
        for a in audit:
            self._events[(a["user_id"], a["field_name"])].append(a)
        for v in self._events.values():
            v.sort(key=lambda e: (e["event_time"], e["audit_id"]))
        # every address a user ever held -> users (any time), used to resolve the request e-mail
        self._email_users: Dict[str, Set[str]] = defaultdict(set)
        for r in identities:
            self._email_users[norm_email(r["email"])].add(r["user_id"])
        for a in audit:
            if a["field_name"] == "email":
                for col in ("old_value", "new_value"):
                    self._email_users[norm_email(a[col])].add(a["user_id"])
        # owners of any strong identifier at any time: used to detect evidence that belongs to somebody else
        self._owners: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        for uid in self.current:
            for kind, vals in self._all_values(uid).items():
                for v in vals:
                    self._owners[(kind, v)].add(uid)

    @classmethod
    def from_dataset(cls, dataset_dir: Union[str, Path]) -> "IdentityDirectory":
        root = Path(dataset_dir)

        def read(name: str) -> List[Dict[str, str]]:
            with open(root / name, encoding="utf-8", newline="") as handle:
                return list(csv.DictReader(handle))

        return cls(read("user_identities.csv"), read("user_audit_log.csv"))

    # ---- values ---------------------------------------------------------------------------------------------
    def _values(self, uid: str, fld: str, audit_at: Optional[str]) -> List[str]:
        cur = self.current[uid][fld]
        evs = self._events.get((uid, fld), [])
        if not evs:
            return [cur]
        out = [evs[0]["old_value"]]
        out += [e["new_value"] for e in evs if audit_at is None or e["event_time"] <= audit_at]
        return out

    def _all_values(self, uid: str) -> Dict[str, Set[str]]:
        emails = {norm_email(v) for v in self._values(uid, "email", None)}
        hashes = {v.strip().lower() for v in self._values(uid, "email_hash", None)} | {hashlib.sha256(e.encode()).hexdigest() for e in emails}
        phones = {norm_phone(v) for v in self._values(uid, "phone", None)}
        return {"email": emails, "email_hash": hashes, "phone": phones, "user_id": {uid}}

    def identity_at(self, uid: str, audit_at: str) -> IdentitySet:
        emails = {norm_email(v) for v in self._values(uid, "email", audit_at)}
        hashes = {v.strip().lower() for v in self._values(uid, "email_hash", audit_at)} | {hashlib.sha256(e.encode()).hexdigest() for e in emails}
        phones = {norm_phone(v) for v in self._values(uid, "phone", audit_at)}
        return IdentitySet(uid, frozenset(emails), frozenset(hashes), frozenset(phones), self.current[uid].get("name") or None)

    # ---- resolution -----------------------------------------------------------------------------------------
    def resolve(self, request_email: str, audit_at: str) -> Resolution:
        e = norm_email(request_email)
        users = sorted(self._email_users.get(e, ()))
        if not users:
            return Resolution("unresolved", request_email)
        if len(users) > 1:
            return Resolution("ambiguous", request_email, candidates=tuple(users))
        uid = users[0]
        via = "current" if norm_email(self.current[uid]["email"]) == e else "historical"
        return Resolution("resolved", request_email, uid, via, (uid,), self.identity_at(uid, audit_at))

    def owners_of(self, kind: str, value: str) -> Set[str]:
        """Users that hold (or ever held) this strong identifier. ``user_id`` values own themselves."""
        if kind == "email":
            return set(self._owners.get(("email", norm_email(value)), ()))
        if kind == "email_hash":
            return set(self._owners.get(("email_hash", value.strip().lower()), ()))
        if kind == "phone":
            return set(self._owners.get(("phone", norm_phone(value)), ()))
        if kind == "user_id":
            return {value.strip()} if value.strip() in self.current else set()
        return set()
