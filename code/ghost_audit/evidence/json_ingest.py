"""JSON evidence -> observations.

Four top-level layouts exist (all 28 files verified):

``json:snapshot_bundle``
    ``{exported_at, source, snapshots: [{captured_at, data_store, collection, records}]}``.
    Each snapshot has its OWN ``captured_at``, which differs from the file's
    manifest capture time in most bundles, so it is kept per observation.
``json:service_resource_export``
    ``{exported_at, region, source, service_exports: {<service>: {<list>: [records]}}}``
    with a per-record ``observed_at``.
``json:flat_ledger``
    ``{exported_at, origin, record_count, records: [{recorded_at, system,
    resource_id, record_type, result, subject_reference}]}``. The record's own
    ``recorded_at`` may be later than the file's capture time; it is preserved.
``json:single_collection``
    ``{captured_at, source, collection, records}``.

A file's *name* is never used to pick a layout (``connector_configurations_...json``
actually holds lookup results); the content decides.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Mapping, Optional, Tuple, Union

from .builders import (
    FileContext,
    collection_record_observation,
    ledger_observation,
    unrecognized_observation,
)
from .identifiers import extract_identifiers
from .model import (
    EvidenceFileRef,
    Observation,
    ObservationKind,
    ParsedFile,
    ParseStatus,
    ScopeKind,
    SnapshotScope,
    SourceFormat,
    TimestampSource,
)
from .schema_maps import (
    COLLECTION_SPECS,
    SERVICE_SECTION_SPECS,
    SINGLE_COLLECTION_SYSTEMS,
    ServiceSectionSpec,
)


def detect_json_layout(doc: Any) -> Optional[str]:
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("snapshots"), list):
        return "json:snapshot_bundle"
    if isinstance(doc.get("service_exports"), dict):
        return "json:service_resource_export"
    if isinstance(doc.get("records"), list) and "record_count" in doc:
        return "json:flat_ledger"
    if isinstance(doc.get("records"), list) and "collection" in doc:
        return "json:single_collection"
    return None


def parse_json_text(ref: EvidenceFileRef, text: str) -> ParsedFile:
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.JSON, status=ParseStatus.PARSED, ref=ref)
    ctx = FileContext(ref, ref.file_path, SourceFormat.JSON)
    try:
        doc = json.loads(text)
    except ValueError as exc:
        ctx.warn("JSON_INVALID", "not valid JSON: %s" % exc)
        parsed.status = ParseStatus.FAILED
        parsed.warnings = ctx.warnings
        return parsed.finalize()

    layout = detect_json_layout(doc)
    parsed.layout = layout
    cov = parsed.coverage
    if layout is None:
        keys = sorted(doc) if isinstance(doc, dict) else type(doc).__name__
        ctx.warn("JSON_UNKNOWN_LAYOUT", "top-level shape %s matches no known layout; content kept as one unrecognized observation" % (keys,))
        cov.containers_seen = 1
        cov.records_seen = cov.records_unrecognized = 1
        parsed.observations.append(unrecognized_observation(ctx, doc if isinstance(doc, dict) else {"_raw": doc}, locator="$", reason="unknown_layout"))
        parsed.status = ParseStatus.FAILED
        parsed.warnings = ctx.warnings
        return parsed.finalize()

    if layout == "json:snapshot_bundle":
        _bundle(ctx, parsed, doc)
    elif layout == "json:service_resource_export":
        _service_export(ctx, parsed, doc)
    elif layout == "json:flat_ledger":
        _flat_ledger(ctx, parsed, doc)
    else:
        _single_collection(ctx, parsed, doc)

    parsed.warnings = ctx.warnings
    if cov.records_unrecognized or cov.containers_recognized < cov.containers_seen:
        parsed.status = ParseStatus.PARTIAL
    return parsed.finalize()


# --------------------------------------------------------------------------- #
def _count(parsed: ParsedFile, obs: Observation) -> None:
    parsed.coverage.records_seen += 1
    parsed.observations.append(obs)
    if obs.kind is ObservationKind.UNRECOGNIZED:
        parsed.coverage.records_unrecognized += 1
    else:
        parsed.coverage.records_recognized += 1


def _set_content_time(ctx: FileContext, value: Any, field_name: str) -> None:
    ts = ctx.check_ts(value, field_name, "$.%s" % field_name)
    if ts is None:
        ctx.warn("FILE_TIME_MISSING", "file has no valid %s; effective time falls back to the manifest" % field_name, "$.%s" % field_name)
    ctx.file_content_time, ctx.file_content_time_field = ts, field_name if ts else None


def _bundle(ctx: FileContext, parsed: ParsedFile, doc: Mapping[str, Any]) -> None:
    cov = parsed.coverage
    _set_content_time(ctx, doc.get("exported_at"), "exported_at")
    parsed.metadata.update({"source": doc.get("source"), "snapshots": len(doc["snapshots"])})
    for i, snap in enumerate(doc["snapshots"]):
        sloc = "$.snapshots[%d]" % i
        cov.containers_seen += 1
        if not isinstance(snap, dict) or not isinstance(snap.get("records"), list) or not isinstance(snap.get("data_store"), str) \
                or not isinstance(snap.get("collection"), str):
            ctx.warn("JSON_SNAPSHOT_MALFORMED", "snapshot needs data_store, collection and a records list", sloc)
            _count(parsed, unrecognized_observation(ctx, snap if isinstance(snap, dict) else {"_raw": snap}, locator=sloc, reason="snapshot_malformed"))
            continue
        store_name, collection = snap["data_store"], snap["collection"]
        store = "%s/%s" % (store_name, collection)
        captured = ctx.check_ts(snap.get("captured_at"), "captured_at", sloc + ".captured_at")
        if captured is None:
            ctx.warn("SNAPSHOT_CAPTURED_AT_MISSING", "snapshot has no valid captured_at; effective time falls back to the file-level time", sloc)
        spec = COLLECTION_SPECS.get(collection)
        records = snap["records"]
        parsed.scopes.append(SnapshotScope(
            ScopeKind.JSON_SNAPSHOT, ctx.ref.file_id if ctx.ref else None,
            store_name if spec and not spec.ledger_like else None, store, captured,
            TimestampSource.SNAPSHOT_CAPTURED if captured else TimestampSource.NONE, len(records), sloc,
            extra={"data_store": store_name, "collection": collection}))
        if spec is None:
            ctx.warn("UNKNOWN_COLLECTION", "collection %r is not a known collection; %d record(s) kept as unrecognized" % (collection, len(records)), sloc)
        else:
            cov.containers_recognized += 1
            if not spec.ledger_like and spec.system_id and spec.system_id != store_name:
                ctx.warn("DATA_STORE_MISMATCH", "data_store=%r but collection %s belongs to %s" % (store_name, collection, spec.system_id), sloc)
        for j, rec in enumerate(records):
            rloc = "%s.records[%d]" % (sloc, j)
            if spec is None:
                _count(parsed, unrecognized_observation(ctx, rec, locator=rloc, reason="unknown_collection", store=store, collection=collection,
                                                        system_id=store_name, snapshot_captured_at=captured))
            elif not isinstance(rec, dict):
                ctx.warn("JSON_RECORD_NOT_OBJECT", "record is %s, expected an object" % type(rec).__name__, rloc)
                _count(parsed, unrecognized_observation(ctx, rec, locator=rloc, reason="record_not_object", store=store, collection=collection,
                                                        system_id=store_name, snapshot_captured_at=captured))
            elif spec.ledger_like:
                obs = ledger_observation(ctx, rec, locator=rloc, store=store, collection=collection, snapshot_captured_at=captured)
                if obs is None:
                    ctx.warn("LEDGER_ROW_INCOMPLETE", "ledger row lacks system/resource_id/record_type/result", rloc)
                    obs = unrecognized_observation(ctx, rec, locator=rloc, reason="ledger_missing_keys", store=store, collection=collection,
                                                   snapshot_captured_at=captured)
                _count(parsed, obs)
            else:
                _count(parsed, collection_record_observation(ctx, spec, rec, locator=rloc, system_id=store_name, store=store, snapshot_captured_at=captured))


def _service_export(ctx: FileContext, parsed: ParsedFile, doc: Mapping[str, Any]) -> None:
    cov = parsed.coverage
    _set_content_time(ctx, doc.get("exported_at"), "exported_at")
    parsed.metadata.update({"source": doc.get("source"), "region": doc.get("region"),
                            "services": sorted(doc["service_exports"])})
    for service, body in doc["service_exports"].items():
        if not isinstance(body, dict):
            ctx.warn("JSON_SECTION_MALFORMED", "service_exports.%s is not an object" % service, "$.service_exports.%s" % service)
            cov.containers_seen += 1
            continue
        for list_key, records in body.items():
            sloc = "$.service_exports.%s.%s" % (service, list_key)
            cov.containers_seen += 1
            spec = SERVICE_SECTION_SPECS.get((service, list_key))
            if not isinstance(records, list):
                ctx.warn("JSON_SECTION_MALFORMED", "%s is not a list" % sloc, sloc)
                continue
            times = sorted(r["observed_at"] for r in records if isinstance(r, dict) and isinstance(r.get("observed_at"), str))
            parsed.scopes.append(SnapshotScope(
                ScopeKind.JSON_SERVICE_SECTION, ctx.ref.file_id if ctx.ref else None, service, "%s.%s" % (service, list_key),
                ctx.file_content_time, TimestampSource.FILE_EXPORTED if ctx.file_content_time else TimestampSource.NONE, len(records), sloc,
                extra={"min_record_observed_at": times[0] if times else None, "max_record_observed_at": times[-1] if times else None}))
            if spec is None:
                ctx.warn("UNKNOWN_SECTION", "%s.%s is not a known service section; %d record(s) kept as unrecognized" % (service, list_key, len(records)), sloc)
            else:
                cov.containers_recognized += 1
            for j, rec in enumerate(records):
                rloc = "%s[%d]" % (sloc, j)
                store = "%s.%s" % (service, list_key)
                if spec is None or not isinstance(rec, dict):
                    if spec is not None:
                        ctx.warn("JSON_RECORD_NOT_OBJECT", "record is %s, expected an object" % type(rec).__name__, rloc)
                    _count(parsed, unrecognized_observation(ctx, rec, locator=rloc, reason="unknown_section" if spec is None else "record_not_object",
                                                            store=store, collection=list_key, system_id=service))
                    continue
                for obs in _service_observations(ctx, spec, rec, rloc, store):
                    parsed.observations.append(obs)
                parsed.coverage.records_seen += 1
                parsed.coverage.records_recognized += 1


def _service_observations(ctx: FileContext, spec: ServiceSectionSpec, rec: Mapping[str, Any], loc: str, store: str) -> List[Observation]:
    observed = ctx.record_time(rec.get("observed_at"), "observed_at", loc + ".observed_at")
    if observed is None:
        ctx.warn("RECORD_TIMESTAMP_MISSING", "record has no valid observed_at; effective time falls back to the file-level time", loc)
    flags = ("record_time_after_file_capture",) if observed and ctx.after_file_capture(observed) else ()
    kind = ObservationKind.LOOKUP_RESULT if spec.kind == "lookup" else ObservationKind.RECORD
    common = dict(system_id=spec.service, record_type=spec.record_type, record_type_source="derived_from_layout",
                  collection=spec.list_key, store=store, record_observed_at=observed,
                  record_timestamp_field="observed_at" if observed else None)

    def make(resource_id: Optional[str], fields: Mapping[str, Any], at: str, state_field: Optional[str], state_value: Any, extra: Tuple[str, ...] = ()) -> Observation:
        obs_id, prov = ctx.next_provenance(at)
        if resource_id is None:
            ctx.warn("RESOURCE_ID_MISSING", "record has no usable resource_id", at)
        return Observation(obs_id=obs_id, kind=kind, provenance=prov, resource_id=resource_id, state_field=state_field,
                           state_value=state_value, identifiers=extract_identifiers(fields), fields=dict(fields), flags=flags + extra, **common)

    rid = rec.get("resource_id") if isinstance(rec.get("resource_id"), str) and rec.get("resource_id") else None
    if spec.expand_hits:
        hits = rec.get("hits") if isinstance(rec.get("hits"), dict) else {}
        docs = hits.get("documents") if isinstance(hits.get("documents"), list) else []
        total = hits.get("total")
        if not docs:
            return [make(rid, rec, loc, "hits.total", total if total is not None else 0, ("no_hits",))]
        out = []
        for k, d in enumerate(docs):
            doc_rid = d.get("resource_id") if isinstance(d, dict) and isinstance(d.get("resource_id"), str) else rid
            fields = {"query": rec.get("query"), "observed_at": rec.get("observed_at"), "hits_total": total, "hit_index": k, "document": d}
            out.append(make(doc_rid, fields, "%s.hits.documents[%d]" % (loc, k), "hits.total", total))
        return out
    state_value = rec.get(spec.state_field) if spec.state_field else None
    return [make(rid, rec, loc, spec.state_field if spec.state_field and spec.state_field in rec else None, state_value)]


def _flat_ledger(ctx: FileContext, parsed: ParsedFile, doc: Mapping[str, Any]) -> None:
    cov = parsed.coverage
    _set_content_time(ctx, doc.get("exported_at"), "exported_at")
    records = doc["records"]
    origin = doc.get("origin") if isinstance(doc.get("origin"), str) else None
    cov.containers_seen = cov.containers_recognized = 1
    declared = doc.get("record_count")
    if declared != len(records):
        ctx.warn("RECORD_COUNT_MISMATCH", "record_count=%r but the file holds %d record(s)" % (declared, len(records)), "$.record_count")
    parsed.metadata.update({"origin": origin, "declared_record_count": declared})
    parsed.scopes.append(SnapshotScope(ScopeKind.JSON_CONTAINER, ctx.ref.file_id if ctx.ref else None, None, origin, ctx.file_content_time,
                                       TimestampSource.FILE_EXPORTED if ctx.file_content_time else TimestampSource.NONE, len(records), "$",
                                       extra={"declared_record_count": declared}))
    for j, rec in enumerate(records):
        rloc = "$.records[%d]" % j
        if not isinstance(rec, dict):
            ctx.warn("JSON_RECORD_NOT_OBJECT", "record is %s, expected an object" % type(rec).__name__, rloc)
            _count(parsed, unrecognized_observation(ctx, rec, locator=rloc, reason="record_not_object", store=origin))
            continue
        obs = ledger_observation(ctx, rec, locator=rloc, store=origin or "ledger", collection=None, snapshot_captured_at=None)
        if obs is None:
            ctx.warn("LEDGER_ROW_INCOMPLETE", "ledger row lacks system/resource_id/record_type/result", rloc)
            obs = unrecognized_observation(ctx, rec, locator=rloc, reason="ledger_missing_keys", store=origin)
        _count(parsed, obs)


def _single_collection(ctx: FileContext, parsed: ParsedFile, doc: Mapping[str, Any]) -> None:
    cov = parsed.coverage
    captured = ctx.check_ts(doc.get("captured_at"), "captured_at", "$.captured_at")
    ctx.file_content_time, ctx.file_content_time_field = captured, "captured_at" if captured else None
    if captured is None:
        ctx.warn("SNAPSHOT_CAPTURED_AT_MISSING", "file has no valid captured_at; effective time falls back to the manifest", "$.captured_at")
    collection = doc.get("collection") if isinstance(doc.get("collection"), str) else None
    spec = COLLECTION_SPECS.get(collection) if collection else None
    system = SINGLE_COLLECTION_SYSTEMS.get(collection or "") or (spec.system_id if spec else None)
    source = doc.get("source") if isinstance(doc.get("source"), str) else None
    store = "%s/%s" % (source, collection)
    records = doc["records"]
    cov.containers_seen = 1
    parsed.metadata.update({"source": source, "collection": collection})
    parsed.scopes.append(SnapshotScope(ScopeKind.JSON_SNAPSHOT, ctx.ref.file_id if ctx.ref else None, system, store, captured,
                                       TimestampSource.SNAPSHOT_CAPTURED if captured else TimestampSource.NONE, len(records), "$"))
    if spec is None:
        ctx.warn("UNKNOWN_COLLECTION", "collection %r is not a known collection; %d record(s) kept as unrecognized" % (collection, len(records)), "$.collection")
    else:
        cov.containers_recognized = 1
    for j, rec in enumerate(records):
        rloc = "$.records[%d]" % j
        if spec is None or not isinstance(rec, dict):
            if spec is not None:
                ctx.warn("JSON_RECORD_NOT_OBJECT", "record is %s, expected an object" % type(rec).__name__, rloc)
            _count(parsed, unrecognized_observation(ctx, rec, locator=rloc, reason="unknown_collection" if spec is None else "record_not_object",
                                                    store=store, collection=collection, system_id=system, snapshot_captured_at=captured))
        else:
            _count(parsed, collection_record_observation(ctx, spec, rec, locator=rloc, system_id=system, store=store, snapshot_captured_at=captured))


def parse_json_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    path = Path(dataset_dir) / ref.file_path
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.JSON, status=ParseStatus.FAILED, ref=ref)
        ctx = FileContext(ref, ref.file_path, SourceFormat.JSON)
        ctx.warn("FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_json_text(ref, text)
