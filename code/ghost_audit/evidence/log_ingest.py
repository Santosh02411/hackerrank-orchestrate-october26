"""Log evidence -> observations (Stage 1B).

All 26 ``.log`` files are line-oriented, one event per line, in one of seven
grammars (each file uses exactly one; detection is per line, not per file name):

=====================  =====================================================================
``json_lines``         ``<ts> {"severity":..,"service":..,"event":..,..}``
``syslog_rfc5424``     ``<ts> <PRI>1 <node> <service> <trace> - - level=.. key="v" ..``
``bracketed``          ``<ts> [LEVEL] [service] [trace] event: key="v" ..``
``pipe_delimited``     ``<ts> | LEVEL | service | trace | event | key="v" ..``
``cloud_runtime``      ``<ts> requestId=<trace> level=.. function=<service> message="<escaped kv>"``
``key_value``          ``<ts> level=.. service=.. event=.. key=v ..``
``key_value_bare_level`` ``<ts> LEVEL service=.. event=record_lookup ..``
=====================  =====================================================================

What becomes an Observation (see ``schema_maps.LOG_EVENT_SPECS``):

* ``fact`` events (a resource plus a state/identifiers): kind ``lookup_result``, with the
  line's own timestamp as ``record_observed_at`` - the file capture time is never substituted.
* ``record_lookup`` rows: same vocabulary as the flat JSON ledgers.
* ``*_started`` events are not results. Their key fields (``lookup_key``, ``subject_key`` ...)
  are attached to the fact event that follows in the SAME trace of the SAME file as
  ``fields["trace_context"]`` (trace ids are reused across files, so correlation is per file).
  A start that no fact event ever follows is kept as an observation flagged
  ``lookup_started_without_completion``; nothing is inferred from that.
* Infrastructure chatter and ``export_started`` / ``export_completed`` are counted, not turned
  into observations; the export metadata becomes a ``LOG_EXPORT`` scope that records declared vs
  parsed event counts and drops.

Every non-blank line is accounted for: an unparseable line or an unknown event becomes an
``unrecognized`` observation plus a warning, never a silent skip.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .builders import FileContext, ledger_observation, unrecognized_observation
from .identifiers import extract_identifiers
from .manifest import resolve_inside
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
from .schema_maps import AUXILIARY_SERVICES, LOG_EVENT_SPECS, TRACE_CONTEXT_SKIP

_NULL_LITERAL = "null"   # logs spell a missing value as the string null
_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) (.*)$", re.S)
_KV = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|[^\s"]*)')
_SYSLOG = re.compile(r"^<\d+>1 (?P<node>\S+) (?P<svc>\S+) (?P<trace>\S+) - - (?P<kv>.*)$")
_BRACKET = re.compile(r"^\[(?P<lvl>\w+)\] \[(?P<svc>[^\]]+)\] \[(?P<trace>[^\]]+)\] (?P<ev>\w+): (?P<kv>.*)$")
_PIPE = re.compile(r"^\| (?P<lvl>\w+) \| (?P<svc>\S+) \| (?P<trace>\S+) \| (?P<ev>\w+) \| (?P<kv>.*)$")
_CLOUD = re.compile(r'^requestId=(?P<trace>\S+) level=(?P<lvl>\w+) function=(?P<svc>\S+) message=(?P<msg>".*")$')
_KV_LEVEL = re.compile(r"^level=(?P<lvl>\w+) service=(?P<svc>\S+) (?P<kv>.*)$")
_KV_BARE = re.compile(r"^(?P<lvl>[A-Z]+) service=(?P<svc>\S+) (?P<kv>.*)$")


@dataclass(frozen=True)
class LogEvent:
    line_no: int
    raw: str
    ts: str
    grammar: str
    level: Optional[str]
    service: Optional[str]
    trace_id: Optional[str]
    event: Optional[str]
    fields: Dict[str, Any]


def _decode(value: str) -> str:
    if value.startswith('"'):
        try:
            return json.loads(value)
        except ValueError:
            return value[1:-1]
    return value


def _kv(text: str) -> Dict[str, str]:
    return {k: _decode(v) for k, v in _KV.findall(text)}


def _trace(candidate: Optional[str], fields: Dict[str, Any]) -> Optional[str]:
    """A 'trace' slot that merely repeats the emitting instance (``collector-3``) is not a trace id."""
    if candidate in (None, "", "-") or candidate == fields.get("instance"):
        return None
    return candidate


def tokenize_line(line_no: int, raw: str) -> Optional[LogEvent]:
    """Parse one log line, or return ``None`` if it matches no known grammar."""
    m = _LINE.match(raw)
    if not m:
        return None
    ts, rest = m.group(1), m.group(2)
    if rest.startswith("{"):
        try:
            d = json.loads(rest)
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None
        level = d.pop("severity", None) if "severity" in d else None
        return LogEvent(line_no, raw, ts, "json_lines", level, d.get("service") or d.get("logger"),
                        _trace(d.get("trace_id"), d), d.get("event"), d)
    g = _SYSLOG.match(rest)
    if g:
        f = _kv(g.group("kv"))
        return LogEvent(line_no, raw, ts, "syslog_rfc5424", f.pop("level", None), g.group("svc"),
                        _trace(g.group("trace"), f), f.get("event"), f)
    g = _BRACKET.match(rest)
    if g:
        f = _kv(g.group("kv"))
        f["event"] = g.group("ev")
        return LogEvent(line_no, raw, ts, "bracketed", g.group("lvl"), g.group("svc"), _trace(g.group("trace"), f), g.group("ev"), f)
    g = _PIPE.match(rest)
    if g:
        f = _kv(g.group("kv"))
        f["event"] = g.group("ev")
        return LogEvent(line_no, raw, ts, "pipe_delimited", g.group("lvl"), g.group("svc"), _trace(g.group("trace"), f), g.group("ev"), f)
    g = _CLOUD.match(rest)
    if g:
        try:
            inner = json.loads(g.group("msg"))
        except ValueError:
            return None
        f = _kv(inner) if isinstance(inner, str) else {}
        return LogEvent(line_no, raw, ts, "cloud_runtime", g.group("lvl"), g.group("svc"), _trace(g.group("trace"), f), f.get("event"), f)
    g = _KV_LEVEL.match(rest)
    if g:
        f = _kv(g.group("kv"))
        return LogEvent(line_no, raw, ts, "key_value", g.group("lvl"), g.group("svc"), _trace(f.get("trace_id"), f), f.get("event"), f)
    g = _KV_BARE.match(rest)
    if g:
        f = _kv(g.group("kv"))
        return LogEvent(line_no, raw, ts, "key_value_bare_level", g.group("lvl"), g.group("svc"), _trace(f.get("trace_id"), f), f.get("event"), f)
    return None


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _role(ev: LogEvent) -> Optional[str]:
    spec = LOG_EVENT_SPECS.get(ev.event or "")
    if spec is not None:
        return spec.role
    if ev.service in AUXILIARY_SERVICES:
        return "auxiliary"
    return None  # unknown event from a platform service


def _identifier_source(fields: Dict[str, Any]) -> Dict[str, Any]:
    """What identifier extraction looks at: the record minus the `log` meta and minus `null` placeholders.
    (The observation's `fields` keep every value verbatim, including the string ``null``.)"""
    out: Dict[str, Any] = {}
    for k, v in fields.items():
        if k == "log" or v == _NULL_LITERAL:
            continue
        if isinstance(v, dict):
            v = _identifier_source(v)
        out[k] = v
    return out


def _meta(ev: LogEvent) -> Dict[str, Any]:
    return {"service": ev.service, "level": ev.level, "trace_id": ev.trace_id, "grammar": ev.grammar, "line": ev.line_no, "raw_line": ev.raw}


def _context(start: LogEvent) -> Dict[str, Any]:
    ctx = {k: v for k, v in start.fields.items() if k not in TRACE_CONTEXT_SKIP}
    ctx.update({"started_event": start.event, "started_at": start.ts, "started_line": start.line_no})
    return ctx


def parse_log_text(ref: EvidenceFileRef, text: str) -> ParsedFile:
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.LOG, status=ParseStatus.PARSED, ref=ref)
    ctx = FileContext(ref, ref.file_path, SourceFormat.LOG)
    cov = parsed.coverage
    cov.containers_seen = 1

    # ---- pass 1: tokenize every line --------------------------------------------------
    entries: List[Tuple[int, str, Optional[LogEvent]]] = []
    blank = 0
    for i, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), start=1):
        if not raw.strip():
            blank += 1
            continue
        entries.append((i, raw, tokenize_line(i, raw)))
    cov.records_seen = len(entries)

    # ---- pass 2: classify, pair starts with facts (per file, per trace) ------------------
    roles: Dict[int, Optional[str]] = {}
    pairing: Dict[int, LogEvent] = {}            # fact line -> the start event that opened its trace
    open_starts: Dict[str, List[Tuple[LogEvent, List[bool]]]] = {}
    all_starts: List[Tuple[LogEvent, List[bool]]] = []
    event_counts: Counter = Counter()
    role_counts: Counter = Counter()
    grammar_counts: Counter = Counter()
    cache_results: Counter = Counter()
    platform_events = aux_events = 0
    timestamps: List[str] = []
    for line_no, _raw, ev in entries:
        if ev is None:
            continue
        role = _role(ev)
        roles[line_no] = role
        grammar_counts[ev.grammar] += 1
        event_counts[ev.event or "?"] += 1
        role_counts[role or "unknown"] += 1
        timestamps.append(ev.ts)
        if ev.event == "cache_lookup":
            cache_results[ev.fields.get("result", "?")] += 1
        if role != "meta":
            if ev.service in AUXILIARY_SERVICES:
                aux_events += 1
            else:
                platform_events += 1
        if role == "start":
            slot = (ev, [False])
            all_starts.append(slot)
            if ev.trace_id:
                open_starts.setdefault(ev.trace_id, []).append(slot)
        elif role == "fact" and ev.trace_id:
            earlier = [s for s in open_starts.get(ev.trace_id, []) if s[0].line_no < ev.line_no]
            if earlier:
                earlier[-1][1][0] = True
                pairing[line_no] = earlier[-1][0]
        if role not in ("fact", "ledger_row"):
            ctx.check_ts(ev.ts, "timestamp", "line=%d" % line_no)  # facts are checked when built

    # ---- export metadata -> LOG_EXPORT scope ------------------------------------------------
    meta_events = {e.event: e for _l, _r, e in entries if e is not None and roles.get(e.line_no) == "meta" and e.event not in ()}
    started, completed = meta_events.get("export_started"), meta_events.get("export_completed")
    declared_candidates: List[Tuple[str, int]] = []
    for label, ev, key in (("export_started.expected_source_events", started, "expected_source_events"),
                           ("export_completed.source_events", completed, "source_events")):
        if ev is not None and key in ev.fields:
            n = _as_int(ev.fields[key])
            if n is None:
                ctx.warn("LOG_METADATA_MALFORMED", "%s=%r is not an integer" % (label, ev.fields[key]), "line=%d" % ev.line_no)
            else:
                declared_candidates.append((label, n))
    declared = declared_candidates[0][1] if declared_candidates else None
    if len({n for _l, n in declared_candidates}) > 1:
        ctx.warn("LOG_METADATA_CONFLICT", "export metadata disagrees about the source event count: %s" % declared_candidates)
    if declared is not None and declared != platform_events:
        ctx.warn("LOG_EVENT_COUNT_MISMATCH", "the log declares %d source events but %d platform-service events were parsed" % (declared, platform_events))
    dropped = _as_int(completed.fields.get("dropped")) if completed is not None and "dropped" in completed.fields else None
    if dropped:
        ctx.warn("LOG_EVENTS_DROPPED", "export_completed reports dropped=%d: the export is incomplete" % dropped,
                 "line=%d" % completed.line_no)  # type: ignore[union-attr]
    queries = _as_int(completed.fields.get("queries")) if completed is not None and "queries" in completed.fields else None
    target = _as_int(started.fields.get("target_count")) if started is not None and "target_count" in started.fields else None
    if queries is not None and (queries != len(all_starts) or (target is not None and target != queries)):
        ctx.warn("LOG_QUERY_COUNT_MISMATCH", "target_count=%r, queries=%r, but %d lookup(s) were started" % (target, queries, len(all_starts)))
    window = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    parsed.scopes.append(SnapshotScope(
        ScopeKind.LOG_EXPORT, ref.file_id, None, ref.origin, None, TimestampSource.NONE,
        declared if declared is not None else platform_events, "file",
        extra={"declared_source_events": declared, "parsed_platform_events": platform_events, "auxiliary_events": aux_events,
               "dropped": dropped, "dropped_auxiliary": _as_int(completed.fields.get("dropped_auxiliary")) if completed is not None else None,
               "queries": queries, "target_count": target, "mode": started.fields.get("mode") if started is not None else None,
               "first_event_at": window[0], "last_event_at": window[1]}))

    # ---- pass 3: build observations in file order ----------------------------------------------
    orphan_lines = {s[0].line_no for s in all_starts if not s[1][0]}
    for line_no, raw, ev in entries:
        loc = "line=%d" % line_no
        if ev is None:
            ctx.warn("LOG_LINE_UNPARSEABLE", "line matches none of the 7 known log grammars; kept as unrecognized", loc)
            parsed.observations.append(unrecognized_observation(ctx, {"raw_line": raw, "line": line_no}, locator=loc, reason="log_line_unparseable"))
            cov.records_unrecognized += 1
            continue
        role = roles[line_no]
        if role is None:
            ctx.warn("LOG_EVENT_UNKNOWN", "event %r from service %r is not in the event registry; kept as unrecognized" % (ev.event, ev.service), loc)
            fields = dict(ev.fields)
            fields["log"] = _meta(ev)
            parsed.observations.append(unrecognized_observation(ctx, fields, locator=loc, reason="log_event_unknown",
                                                                system_id=ev.service, collection=ev.event))
            cov.records_unrecognized += 1
            continue
        cov.records_recognized += 1
        if role == "ledger_row":
            row = {k: v for k, v in ev.fields.items()}
            row["recorded_at"] = ev.ts
            obs = ledger_observation(ctx, row, locator=loc, store=ev.service or "log", collection=ev.event, snapshot_captured_at=None)
            if obs is None:
                ctx.warn("LEDGER_ROW_INCOMPLETE", "record_lookup lacks system/resource_id/record_type/result", loc)
                cov.records_recognized -= 1
                cov.records_unrecognized += 1
                parsed.observations.append(unrecognized_observation(ctx, dict(row, log=_meta(ev)), locator=loc, reason="ledger_missing_keys"))
            else:
                parsed.observations.append(replace(obs, record_timestamp_field="log_timestamp", fields=dict(obs.fields, log=_meta(ev))))
        elif role == "fact":
            parsed.observations.append(_fact_observation(ctx, ev, loc, pairing.get(line_no)))
        elif role == "start" and line_no in orphan_lines:
            ctx.warn("LOG_TRACE_INCOMPLETE", "%s has no later fact event in its trace; kept as an observation without a result (nothing is inferred)" % ev.event, loc, level="info")
            parsed.observations.append(_orphan_observation(ctx, ev, loc))

    parsed.layout = "log:" + (next(iter(grammar_counts)) if len(grammar_counts) == 1 else "mixed" if grammar_counts else "unknown")
    parsed.metadata.update({
        "grammars": dict(grammar_counts), "event_counts": dict(event_counts), "role_counts": dict(role_counts), "blank_lines": blank,
        "traces": len({e.trace_id for _l, _r, e in entries if e is not None and e.trace_id}),
        "starts": len(all_starts), "orphan_starts": len(orphan_lines), "cache_lookup_results": dict(cache_results)})
    if cov.records_recognized:
        cov.containers_recognized = 1
    else:
        ctx.warn("LOG_EMPTY" if not entries else "LOG_NO_RECOGNIZED_LINES", "no usable log lines" if not entries else "no line could be recognized")
        parsed.status = ParseStatus.FAILED
    if parsed.status is ParseStatus.PARSED and cov.records_unrecognized:
        parsed.status = ParseStatus.PARTIAL
    parsed.warnings = ctx.warnings
    return parsed.finalize()


def _fact_observation(ctx: FileContext, ev: LogEvent, loc: str, start: Optional[LogEvent]) -> Observation:
    spec = LOG_EVENT_SPECS[ev.event or ""]
    ts = ctx.record_time(ev.ts, "timestamp", loc)
    fields: Dict[str, Any] = dict(ev.fields)
    flags: List[str] = []
    if start is not None:
        fields["trace_context"] = _context(start)
        flags.append("trace_context")
    fields["log"] = _meta(ev)
    rid = ev.fields.get("resource_id")
    if not isinstance(rid, str) or not rid:
        ctx.warn("RESOURCE_ID_MISSING", "log event has no usable resource_id", loc)
        rid = None
    if ts and ctx.after_file_capture(ts):
        flags.append("record_time_after_file_capture")
    obs_id, prov = ctx.next_provenance(loc)
    has_state = bool(spec.state_field) and spec.state_field in ev.fields
    return Observation(
        obs_id=obs_id, kind=ObservationKind.LOOKUP_RESULT, provenance=prov, system_id=ev.service, resource_id=rid,
        record_type=spec.record_type, record_type_source="derived_from_layout", collection=ev.event,
        state_field=spec.state_field if has_state else None, state_value=ev.fields.get(spec.state_field) if has_state else None,
        record_observed_at=ts, record_timestamp_field="log_timestamp" if ts else None,
        identifiers=extract_identifiers(_identifier_source(fields)), fields=fields, flags=tuple(flags))


def _orphan_observation(ctx: FileContext, ev: LogEvent, loc: str) -> Observation:
    ts = ctx.record_time(ev.ts, "timestamp", loc)
    fields: Dict[str, Any] = dict(ev.fields)
    fields["log"] = _meta(ev)
    rid = ev.fields.get("resource_id") if isinstance(ev.fields.get("resource_id"), str) and ev.fields.get("resource_id") else None
    obs_id, prov = ctx.next_provenance(loc)
    return Observation(
        obs_id=obs_id, kind=ObservationKind.LOOKUP_RESULT, provenance=prov, system_id=ev.service, resource_id=rid,
        collection=ev.event, record_observed_at=ts, record_timestamp_field="log_timestamp" if ts else None,
        identifiers=extract_identifiers(_identifier_source(fields)), fields=fields,
        flags=("lookup_started_without_completion",))


def parse_log_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    try:
        text = resolve_inside(dataset_dir, ref.file_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.LOG, status=ParseStatus.FAILED, ref=ref)
        ctx = FileContext(ref, ref.file_path, SourceFormat.LOG)
        ctx.warn("FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_log_text(ref, text)
