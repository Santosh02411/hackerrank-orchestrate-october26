"""Turn the engine's results into the JSON the Evidence Explorer shows.

This module only READS what the existing pipeline already produced (decisions, link methods, assessments, notes, provenance and the
corpus' own eligibility rule). It never re-decides a case, never invents a score and never explains a link with anything other than a
recorded field. Every string shown to a reader is either (a) a verbatim recorded value, (b) a count computed from recorded values, or
(c) the definition of a link method taken from ``engine/linking.py``'s own documentation.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..engine.assess import Assessment, assess_resource
from ..engine.decide import AuditEngine, CaseDecision
from ..engine.evaluate import STEP_KEY, evaluate
from ..evidence.model import Observation

PAYLOAD_VERSION = 1
CODE_DIR = Path(__file__).resolve().parents[2]

# What each recorded link method means, as written in engine/linking.py (not an interpretation).
METHOD_DEFINITIONS = {
    "identifier": "An eligible observation carries a strong identifier (e-mail, e-mail hash, phone or user_id) that the person held at audit_at. "
                  "Identifiers that OCR flagged as uncertain are never used.",
    "trace": "The matching identifier is the lookup key of the log trace that returned the record (trace_context.*).",
    "document": "A PDF in which every person-identifying value belongs to this person; resource references printed in it are linked.",
    "catalog": "A LINK_RESOURCE_IDENTITY activity row names the resource and this person, and nobody else.",
    "claim_window": "WEAK link: the only workflow claim of its kind within +-2 h of reported_at, on a record not tied to anyone else. "
                    "A time-window inference, not an identifier.",
}
ELIGIBILITY_LABELS = {
    "eligible": "Eligible: captured inside [requested_at, audit_at]",
    "after_audit": "Excluded: captured or recorded after audit_at",
    "before_request": "Excluded: captured or recorded before requested_at",
}
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
_AMBIGUOUS_NOTE = re.compile(r"claim_window ambiguous for (\w+\*): (\d+) candidates")


# ------------------------------------------------------------------------------------------------ eligibility
def classify_eligibility(o: Observation, requested_at: str, audit_at: str) -> str:
    """Why an observation was (not) usable for this case. Mirrors Corpus.eligible; tests assert the two always agree."""
    cap = o.provenance.file_captured_at
    t = o.effective_time().value
    if o.provenance.file_id and cap and cap > audit_at:
        return "after_audit"
    if t is not None and t > audit_at:
        return "after_audit"
    if (o.provenance.file_id and cap and cap < requested_at) or (t is not None and t < requested_at):
        return "before_request"
    return "eligible"


def _scalar(v: Any) -> Any:
    return v if isinstance(v, (str, int, float, bool)) or v is None else str(v)


# ------------------------------------------------------------------------------------------------ observations
def observation_json(o: Observation, identity, requested_at: str, audit_at: str) -> Dict[str, Any]:
    eff = o.effective_time()
    idents = []
    for i in o.identifiers.items:
        if i.kind in ("email", "email_hash", "phone", "user_id", "name"):
            idents.append({"kind": i.kind, "value": i.value, "path": i.path, "uncertain": bool(i.uncertain),
                           "confidence": None if i.confidence is None else round(i.confidence, 1),
                           "matches_person": bool(identity is not None and i.kind != "name" and identity.contains(i.kind, i.value))})
    text = o.fields.get("text") if isinstance(o.fields, dict) else None
    return {"obs_id": o.obs_id, "evidence_id": o.provenance.citable_id, "format": o.provenance.source_format.value,
            "locator": o.provenance.locator, "collection": o.collection, "store": o.store,
            "store_role": o.store_role, "system_id": o.system_id, "record_type": o.record_type, "state_field": o.state_field,
            "state_value": _scalar(o.state_value), "captured_at": o.provenance.file_captured_at, "time": eff.value, "time_source": eff.source.value,
            "identifiers": idents, "flags": list(o.flags), "text": (str(text)[:160] if text else None),
            "eligibility": classify_eligibility(o, requested_at, audit_at)}


def claim_json(c: Observation, audit_at: str) -> Dict[str, Any]:
    t = c.record_observed_at
    return {"activity_id": c.provenance.citable_id, "event_type": c.event_type, "time": t, "result": c.fields.get("reported_result"),
            "details": str(c.fields.get("details", ""))[:200], "source_system": c.fields.get("source_system"), "target_system": c.system_id,
            "eligible": bool(t and t <= audit_at)}


# ------------------------------------------------------------------------------------------------ one case
def _link_evidence(lr, observations: List[Dict[str, Any]], claims: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """For each recorded link method: the recorded items that carry it (never more than what the linker actually used)."""
    out = []
    eligible = [o for o in observations if o["eligibility"] == "eligible"]
    for method in sorted(lr.methods):
        item: Dict[str, Any] = {"method": method, "definition": METHOD_DEFINITIONS.get(method, ""), "items": []}
        if method in ("identifier", "trace"):
            for o in eligible:
                for i in o["identifiers"]:
                    is_trace = i["path"].startswith("trace_context")
                    if i["matches_person"] and not i["uncertain"] and is_trace == (method == "trace"):
                        item["items"].append({"obs_id": o["obs_id"], "kind": i["kind"], "path": i["path"]})      # the value is read from the observation itself
        elif method == "document":
            item["items"] = [{"obs_id": o["obs_id"]} for o in eligible if o["format"] == "pdf"]
        elif method in ("catalog", "claim_window"):
            wanted = "LINK_RESOURCE_IDENTITY" if method == "catalog" else None
            item["items"] = [{"activity_id": c["activity_id"]}                                                    # the claim itself is in the resource's claims list
                             for c in claims if c["eligible"] and (c["event_type"] == wanted if wanted else c["event_type"] in ("DELETE_RECORD", "ANONYMIZE_RECORD"))]
        out.append(item)
    return out


def _unknown_reason(engine: AuditEngine, lr, case: Dict[str, str]) -> Tuple[str, str]:
    a = assess_resource(lr, engine.rules, case["audit_at"], engine.file_text, engine.corpus, case["requested_at"])
    return ("unknown", a.reason if a is not None else "No record category is defined for this resource prefix")


def case_json(engine: AuditEngine, d: CaseDecision, case: Dict[str, str], contested: Dict[str, list]) -> Dict[str, Any]:
    corpus = engine.corpus
    aud, since = case["audit_at"], case["requested_at"]
    ident = d.resolution.identity if d.resolution else None
    by_res: Dict[str, Assessment] = {a.resource_id: a for a in d.assessments}
    resources, counts = [], Counter()
    integrity: Dict[str, list] = {k: [] for k in ("conflicts", "contested", "missing_identifiers", "uncertain_ocr", "retained", "flows", "restore", "tombstones")}
    cited_by = defaultdict(list)
    for s in d.steps:
        cited_by[s["resource_id"]].append(s["step_no"])
    for rid, lr in sorted((d.view.resources.items() if d.view else [])):
        obs = [observation_json(o, ident, since, aud) for o in sorted(corpus.by_resource.get(rid, ()), key=lambda x: (x.effective_time().value or "", x.obs_id))]
        claims = [claim_json(c, aud) for c in sorted(corpus.claims_by_resource.get(rid, ()), key=lambda x: (x.record_observed_at or "", x.obs_id))]
        a = by_res.get(rid)
        verdict, reason = (a.verdict, a.reason) if a else _unknown_reason(engine, lr, case)
        for o in obs:
            counts[o["eligibility"]] += 1
        counts["claims_after_audit"] += sum(1 for c in claims if not c["eligible"])
        r = {"id": rid, "system_id": a.system_id if a else None, "category": a.category if a else None, "rule_id": a.rule_id if a else None,
             "methods": sorted(lr.methods), "weak": lr.weak, "conflict": lr.conflict, "aliases": list(lr.aliases), "document_presence": list(lr.doc_presence),
             "verdict": verdict, "reason": reason, "cited_evidence": a.cite if a else "", "proof_obs": a.proof.obs_id if a and a.proof else None,
             "absence_proof": (a.proof_id or None) if a else None,
             "steps": cited_by.get(rid, []), "link_evidence": [], "observations": obs, "claims": claims}
        r["link_evidence"] = _link_evidence(lr, obs, claims)
        resources.append(r)
        if lr.conflict:
            integrity["conflicts"].append({"resource_id": rid, "text": lr.conflict})
        if rid in contested and cited_by.get(rid):          # only a record this case actually CITES is "cited for more than one person"
            integrity["contested"].append({"resource_id": rid, "people": [{"case_id": c, "user_id": u, "via": v} for c, u, v in contested[rid]]})
        used = [o for o in obs if o["eligibility"] == "eligible"]
        for o in used:
            if not o["identifiers"] and o["format"] != "csv":
                integrity["missing_identifiers"].append({"resource_id": rid, "evidence_id": o["evidence_id"], "locator": o["locator"],
                                                         "why": "This eligible observation records no identifier"})
            for i in o["identifiers"]:
                if i["uncertain"]:
                    integrity["uncertain_ocr"].append({"resource_id": rid, "evidence_id": o["evidence_id"], "value": i["value"], "confidence": i["confidence"]})
        if a:
            row = {"resource_id": rid, "category": a.category, "verdict": a.verdict, "reason": a.reason, "evidence_id": a.cite, "rule_id": a.rule_id}
            if a.category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") and a.verdict == "retained":
                integrity["retained"].append(row)
            elif a.category == "DATA_FLOW":
                integrity["flows"].append(row)
            elif a.category == "BACKUP_ARCHIVE":
                integrity["restore"].append(row)
            elif a.category == "ACCOUNT_TOMBSTONE":
                integrity["tombstones"].append(row)
    ambiguous = []
    for n in d.notes:
        m = _AMBIGUOUS_NOTE.search(n)
        if m:
            ambiguous.append({"prefix": m.group(1), "candidates": int(m.group(2)), "text": n})
    flags = []
    if any(r["weak"] for r in resources): flags.append("weak_link")           # noqa: E701
    if ambiguous: flags.append("ambiguous")                                   # noqa: E701
    if counts["after_audit"] or counts["claims_after_audit"]: flags.append("after_cutoff")   # noqa: E701
    if integrity["uncertain_ocr"] or any(o["format"] in ("image", "pdf") for r in resources for o in r["observations"] if o["eligibility"] == "eligible"):
        flags.append("document_evidence")
    if integrity["conflicts"] or integrity["contested"]: flags.append("conflict")  # noqa: E701
    res = d.resolution
    return {
        "id": d.case_id, "status": d.status,
        "request": {"email": case["email"], "text": case["request_text"], "requested_at": case["requested_at"], "reported_at": case["reported_at"],
                    "audit_at": aud, "reported_status": case["reported_status"]},
        "applicability": {"authorized": d.applicability.authorized, "reason": d.applicability.reason} if d.applicability else None,
        "identity": None if res is None else {"status": res.status, "user_id": res.user_id, "via": res.via, "candidates": list(res.candidates), "name": ident.name if ident else None,
                                              "emails": sorted(ident.emails) if ident else [], "phones": len(ident.phones) if ident else 0, "hashes": len(ident.hashes) if ident else 0},
        "steps": [{k: s[k] for k in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")} for s in d.steps],
        "resources": resources, "ambiguous": ambiguous, "notes": list(d.notes), "integrity": integrity, "counts": dict(counts), "flags": flags,
    }


# ------------------------------------------------------------------------------------------------ explanations for samples
def explain_missing(step_key: Tuple[str, ...], case: Dict[str, Any]) -> List[str]:
    """Facts (counts and recorded ids/times) about why a reference step is absent from the engine's answer. Never speculation."""
    rid = step_key[3]
    facts = []
    res = next((r for r in case["resources"] if r["id"] == rid), None)
    if res is None:
        facts.append("%s is not linked to this person by any recorded method." % rid)
        for a in case["ambiguous"]:
            if rid.startswith(a["prefix"].rstrip("*")):
                facts.append("Link left unattributed on purpose: %d candidate %s records matched the time window." % (a["candidates"], a["prefix"]))
        return facts
    obs = res["observations"]
    elig = [o for o in obs if o["eligibility"] == "eligible"]
    late = [o for o in obs if o["eligibility"] == "after_audit"]
    facts.append("%s is linked via %s; %d eligible observation(s), %d excluded as after audit_at." % (rid, ", ".join(res["methods"]), len(elig), len(late)))
    for o in late[:3]:
        facts.append("Excluded evidence: %s captured %s, after audit_at." % (o["evidence_id"], o["captured_at"]))
    facts.append("Engine verdict for this record: %s (%s)." % (res["verdict"], res["reason"]))
    return facts


def reference_comparison(case_payload: Dict[str, Any], ref: Tuple[str, List[dict]]) -> Dict[str, Any]:
    rstatus, rsteps = ref
    key = lambda s: tuple(s[k] for k in STEP_KEY)  # noqa: E731
    pred = {key(s): s for s in case_payload["steps"]}
    refd = {key(s): s for s in rsteps}
    return {"status": rstatus, "status_matches": rstatus == case_payload["status"], "steps": rsteps,
            "matched": [list(k) for k in refd if k in pred], "extra": [list(k) for k in pred if k not in refd],
            "missing": [{"step": refd[k], "facts": explain_missing(k, case_payload)} for k in refd if k not in pred],
            "wrong_evidence": [list(k) for k in refd if k in pred and refd[k]["evidence_id"] != pred[k]["evidence_id"]]}


# ------------------------------------------------------------------------------------------------ evaluation overview
def _load_evaluation_module():
    spec = importlib.util.spec_from_file_location("ghost_explorer_evaluation", CODE_DIR / "evaluation" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def limitations_from_report(report_path: Path) -> List[str]:
    """The bullets of section 6 of the evaluation report, verbatim (so the explorer cannot drift from the report)."""
    if not report_path.is_file():
        return []
    text = report_path.read_text(encoding="utf-8").replace("\r\n", "\n")
    m = re.search(r"^## 6\..*?\n(.*)$", text, re.S | re.M)
    clean = lambda b: re.sub(r"\*\*|`", "", re.sub(r"\s+", " ", b)).lstrip("* ").strip()      # markdown markers removed, wording untouched
    return [clean(b) for b in re.split(r"\n(?=\* )", m.group(1).strip())] if m else []


def usage_from_report(path: Path) -> Dict[str, str]:
    if not path.is_file():
        return {}
    rows = re.findall(r"^\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*$", path.read_text(encoding="utf-8").replace("\r\n", "\n"), re.M)
    return {k: v for k, v in rows if k not in ("Item", "---") and not set(k) <= set("-")}


def load_test_results(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) and "tests_run" in data else None


def output_file_check(path: Path, decisions: Dict[str, CaseDecision]) -> Dict[str, Any]:
    if not path.is_file():
        return {"present": False}
    try:
        with open(path, encoding="utf-8", newline="") as h:
            reader = csv.DictReader(h)
            header = reader.fieldnames
            rows = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in reader}
    except (ValueError, KeyError, OSError) as exc:
        return {"present": True, "readable": False, "error": str(exc)[:120]}
    differing = sorted(c for c in decisions if c in rows and (decisions[c].status, decisions[c].steps) != rows[c])
    return {"present": True, "readable": True, "header_ok": header == ["case_id", "deletion_status", "steps_json"], "rows": len(rows),
            "missing_from_file": sorted(c for c in decisions if c not in rows), "unknown_in_file": sorted(c for c in rows if c not in decisions),
            "differing": differing, "matches_all": not differing and set(rows) == set(decisions)}


# ------------------------------------------------------------------------------------------------ payload
def _summary(cases: List[Dict[str, Any]], decisions: Sequence[CaseDecision]) -> Dict[str, Any]:
    ops, link, phases = Counter(), Counter(), Counter()
    for c in cases:
        for s in c["steps"]:
            ops[s["operation"]] += 1
            phases[s["phase"]] += 1
        for r in c["resources"]:
            if r["steps"]:
                link["+".join(r["methods"])] += 1
    elig = Counter()
    for c in cases:
        for k, v in c["counts"].items():
            elig[k] += v
    flag_counts = Counter(f for c in cases for f in c["flags"])
    integ = {k: sum(1 for c in cases if c["integrity"][k]) for k in cases[0]["integrity"]} if cases else {}
    return {"cases": len(cases), "statuses": dict(Counter(c["status"] for c in cases)), "steps": sum(phases.values()), "phases": dict(phases),
            "operations": dict(sorted(ops.items())), "link_methods": dict(sorted(link.items())), "evidence": dict(elig), "flags": dict(flag_counts),
            "integrity_cases": integ, "unresolved_identities": sum(1 for c in cases if c["identity"] and c["identity"]["status"] != "resolved")}


def build_payload(engine: AuditEngine, main_requests: List[Dict[str, str]], sample_requests: List[Dict[str, str]], *, repo_root: Path, dataset_dir: Path,
                  sample_reference: Optional[Dict[str, Tuple[str, List[dict]]]] = None) -> Dict[str, Any]:
    ev = _load_evaluation_module()
    main_dec = {r["case_id"]: engine.decide(r) for r in main_requests}
    samp_dec = {r["case_id"]: engine.decide(r) for r in sample_requests}
    contested = ev.contested_resources(list(samp_dec.values()) + list(main_dec.values()))
    main_cases = [case_json(engine, main_dec[r["case_id"]], r, contested) for r in main_requests]
    samp_cases = [case_json(engine, samp_dec[r["case_id"]], r, contested) for r in sample_requests]
    metrics = None
    if sample_reference:
        for c in samp_cases:
            if c["id"] in sample_reference:
                c["reference"] = reference_comparison(c, sample_reference[c["id"]])
        metrics = evaluate({c: (d.status, d.steps) for c, d in samp_dec.items()}, sample_reference)
    eval_dir = repo_root / "code" / "evaluation"
    missing = Counter()
    if metrics:
        for pc in metrics["per_case"].values():
            for k in pc["missing"]:
                missing[(k[1], k[2])] += 1
    custom = [{"name": c["name"], "why": c["why"], "expected_status": c["expected_status"], "status": c["status"], "ok": c["ok"], "steps": len(c["steps"])}
              for c in ev.run_custom_cases()]
    evaluation = {
        "samples": None if metrics is None else {k: v for k, v in metrics.items() if k != "per_case"},
        "missing_breakdown": [{"operation": o, "system_id": s, "count": n} for (o, s), n in sorted(missing.items())],
        "custom_cases": custom, "tests": load_test_results(repo_root / "evaluation" / "test_results.json"),
        "limitations": limitations_from_report(eval_dir / "evaluation_report.md"), "usage": usage_from_report(eval_dir / "usage_report.md"),
        "labels": {"samples": "DEVELOPMENT SET: the engine was built while studying these 32 cases, so these numbers are an upper bound, not a held-out estimate.",
                   "evaluation": "The 518 evaluation cases have NO available ground truth. Nothing on those cases is a measured accuracy; they show what the engine "
                                 "decided and the recorded evidence behind it."},
    }
    files = {}
    manifest = dataset_dir / "evidence_files.csv"
    if manifest.is_file():                     # every manifest file, including ones with no observation (e.g. an empty snapshot)
        with open(manifest, encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                files[row["file_id"]] = {"path": row["file_path"], "origin": row["origin"], "format": Path(row["file_path"]).suffix.lstrip(".").lower(),
                                         "captured_at": row["captured_at"]}
    return {
        "version": PAYLOAD_VERSION,
        "files": files,
        "meta": {"engine": "ghost_audit.engine (deterministic, offline; no model or API calls)", "dataset_files": len(list((dataset_dir / "evidence").glob("**/*"))) if (dataset_dir / "evidence").is_dir() else 0,
                 "link_method_definitions": METHOD_DEFINITIONS, "eligibility_labels": ELIGIBILITY_LABELS},
        "datasets": {"evaluation": {"label": "Evaluation requests (518, no ground truth)", "cases": main_cases, "summary": _summary(main_cases, list(main_dec.values()))},
                     "samples": {"label": "Public samples (32, development set)", "cases": samp_cases, "summary": _summary(samp_cases, list(samp_dec.values()))}},
        "evaluation": evaluation,
        "output_check": output_file_check(repo_root / "output.csv", main_dec),
        "contested": [{"resource_id": r, "people": [{"case_id": c, "user_id": u, "via": v} for c, u, v in w]} for r, w in contested.items()],
        "featured": featured_cases(main_cases),
    }


def featured_cases(cases: List[Dict[str, Any]], n: int = 3) -> List[Dict[str, Any]]:
    """Cases that show the most distinct recorded behaviours (a generic score, not a hand-picked list). Reasons are counts of recorded facts."""
    scored = []
    for c in cases:
        if c["status"] == "NOT_APPLICABLE" or not c["identity"]:
            continue
        reasons = []
        score = 0
        if c["identity"]["via"] == "historical": reasons.append("request uses a historical e-mail"); score += 2   # noqa: E702
        methods = sorted({m for r in c["resources"] if r["steps"] for m in r["methods"]})
        if len(methods) >= 2: reasons.append("linked through %s" % " + ".join(methods)); score += len(methods)    # noqa: E702
        if c["counts"].get("after_audit"): reasons.append("%d observation(s) excluded as captured after audit_at" % c["counts"]["after_audit"]); score += 2   # noqa: E702
        if c["ambiguous"]: reasons.append("an ambiguous link was left unattributed"); score += 2                  # noqa: E702
        if c["integrity"]["uncertain_ocr"]: reasons.append("OCR-uncertain identifier(s) not used"); score += 1    # noqa: E702
        if c["status"] == "INCOMPLETE": reasons.append("%d finding(s)" % sum(1 for s in c["steps"] if s["phase"] == "FINDING")); score += 1   # noqa: E702
        scored.append((score, len(c["steps"]), c["id"], reasons))
    scored.sort(key=lambda t: (-t[0], -t[1], t[2]))
    return [{"case_id": cid, "reasons": rs} for _s, _n, cid, rs in scored[:n]]
