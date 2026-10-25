"""Does the request text authorize deletion? (AGENTS.md 6.5: access, correction, export, marketing opt-out
or any other non-deletion request is NOT_APPLICABLE.)

Rule-based and multilingual (en, es, pt, fr, ja, ko - the languages present in the requests), deterministic,
no model call. The decision is made in three steps on the normalised text:

1. mask *negated* deletion phrases ("I am not asking for deletion", "do not close the account",
   "without removing any of my records", "not a request to erase it");
2. look for a positive deletion phrase in what is left;
3. a marketing-only opt-out ("remove me from marketing lists only") never authorizes deletion.

Anything that talks about the deletion having ALREADY happened ("I deleted my account, please verify")
is a deletion audit and does authorize the review, matching the deletion-audit task.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import List

# --- negations: deletion verbs that are explicitly refused ------------------------------------------------
_NEG = [
    r"not (?:asking|requesting|wanting|looking) (?:for|to)\s*(?:the\s*)?(?:deletion|delet\w*|eras\w*|clos\w*|remov\w*)",
    r"not (?:a|an) (?:request|ask)\s*to\s*(?:delete|erase|close|remove)\w*",
    r"not (?:a|an)\s*(?:deletion|erasure)\s*request",
    r"(?:do not|don't|dont|please do not|please don't|never)\s*(?:\w+\s+)?(?:delete|erase|close|remove|change)\w*",
    r"without\s+(?:removing|deleting|erasing|closing)\w*",
    r"(?:leave|keep)\s+(?:the|my|this)\s+(?:account|profile)\s+(?:active|as it is|in place|open)",
    r"keep the account",
    r"leave my profile",
    r"no (?:quiero|deseo) (?:eliminar|borrar|cancelar)\w*",
    r"nao (?:quero|desejo) (?:excluir|apagar|cancelar)\w*",
    r"ne (?:veux|souhaite) pas (?:supprimer|effacer|fermer)\w*",
    r"削除(?:は)?(?:しないで|は不要|を希望しません)",
    r"삭제(?:하지 마|를 원하지 않)",
]
_NEG_RE = re.compile("|".join("(?:%s)" % p for p in _NEG), re.I)

# --- positive deletion phrases ------------------------------------------------------------------------------
_OBJ = r"(?:account|profile|personal|data|information|details|record|records|search|export|download|archive|file|copy|copies|document|identity|integration|history|conversation|message|trace|result)"
_POS_EN = [
    rf"\b(?:delet\w*|eras\w*|remov\w*|clos\w*|eliminat\w*)\b(?:\W+\w+){{0,6}}?\W+{_OBJ}",
    rf"{_OBJ}\b(?:\W+\w+){{0,9}}?\W+(?:delet\w*|eras\w*|remov\w*|clos\w*|eliminat\w*)\b",
    r"\bpermanent\w*\b(?:\W+\w+){0,3}?\W+(?:deletion|delet\w*|account-deletion)",
    r"\bdeletion\b", r"\berasure\b",
    r"\bfinish the deletion\b", r"\bcomplete the deletion\b",
    # deletion AUDITS: the person asks us to confirm/inspect a deletion that should already have happened
    r"\b(?:is|are|was|were|been|already)\s+(?:gone|removed|deleted|erased)\b", r"\baudit the deletion\b",
    r"\bconfirm that the (?:profile|account)\b",
]
_POS_OTHER = [
    r"\b(?:eliminaci[oó]n|eliminar|elimin\w+|borrar|borrado)\b",          # es
    r"\b(?:exclus[aã]o|excluir|apagar|remo[cç][aã]o)\b",                  # pt
    r"\b(?:suppression|supprimer|effacer|supprim\w+|fermeture)\b",        # fr
    r"削除", r"消去", r"退会",                                              # ja
    r"삭제", r"탈퇴",                                                       # ko
]
_POS_RE = re.compile("|".join("(?:%s)" % p for p in _POS_EN + _POS_OTHER), re.I)
_MARKETING_ONLY = re.compile(r"(?:marketing|promotional|newsletter|mailing)[^.]{0,60}\b(?:only|lists?)\b|\b(?:only|lists?)\b[^.]{0,40}(?:marketing|promotional|newsletter)", re.I)
_ACCOUNT_DELETE = re.compile(r"(?:delet\w*|eras\w*|clos\w*)\W+(?:\w+\W+){0,3}?(?:account|profile)", re.I)


@dataclass(frozen=True)
class Applicability:
    authorized: bool
    reason: str
    positives: tuple = ()
    negated: tuple = ()


def normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).replace("\u2019", "'").replace("\u2018", "'").strip()


def classify_request(text: str) -> Applicability:
    t = normalise(text)
    negated: List[str] = [m.group(0) for m in _NEG_RE.finditer(t)]
    masked = _NEG_RE.sub(" ", t)
    positives = [m.group(0) for m in _POS_RE.finditer(masked)]
    if _MARKETING_ONLY.search(masked) and not _ACCOUNT_DELETE.search(masked):
        return Applicability(False, "marketing-only opt-out; deletion is not requested", tuple(positives), tuple(negated))
    if positives:
        return Applicability(True, "explicit deletion request", tuple(positives[:3]), tuple(negated))
    if negated:
        return Applicability(False, "deletion is explicitly refused", (), tuple(negated))
    return Applicability(False, "no deletion request (access, correction, export, login or other request)", (), ())
