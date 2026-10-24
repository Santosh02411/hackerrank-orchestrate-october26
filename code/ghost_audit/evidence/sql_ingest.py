"""SQL snapshot evidence -> observations.

Every ``.sql`` file is a script of CREATE TABLE / INSERT / CREATE INDEX /
PRAGMA / BEGIN / COMMIT statements (verified for all 24 files; no UPDATE,
DELETE, trigger or view). It is executed in a private ``:memory:`` SQLite
database, so the source file is only ever *read* and nothing is persisted.
A defensive authorizer additionally refuses ATTACH/DETACH (which could touch
other files), virtual tables and every PRAGMA except ``foreign_keys``.

Four table layouts occur (see ``schema_maps.SQL_TABLE_LAYOUTS``):

* ``inventory_table`` + ``snapshot_scope`` - typed tables, per-system capture time
* ``json_record_table`` - ``(resource_id, origin_system, collection_name, record_json, updated_at)``
  for a ``..._primary`` table and one or more replica tables
* ``account_profile_table`` - ``customer_profiles_primary`` / ``..._failover_replica``
* ``search_document_table`` - ``search_documents_primary``

Rows are never merged across primary/replica tables: each keeps its ``store``,
``store_role`` and ``replica_name`` so replication drift stays visible.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    SNAPSHOT_SCOPE_COLUMNS,
    SNAPSHOT_SCOPE_TABLE,
    SqlTableLayout,
    classify_store,
    match_sql_layout,
    sql_file_layout,
)
from .timestamps import parse_iso_utc

# sqlite3 authorizer action codes (numeric fallbacks keep older Pythons working)
_ACTION_NAMES = {1: "CREATE_INDEX", 2: "CREATE_TABLE", 7: "CREATE_TRIGGER", 8: "CREATE_VIEW", 9: "DELETE",
                 11: "DROP_TABLE", 18: "INSERT", 23: "UPDATE", 26: "ALTER_TABLE"}
_PRAGMA, _ATTACH, _DETACH, _CREATE_VTABLE = 19, 24, 25, 29
_READ, _SELECT, _FUNCTION, _RECURSIVE = 20, 21, 31, 33
_OK = getattr(sqlite3, "SQLITE_OK", 0)
_DENY = getattr(sqlite3, "SQLITE_DENY", 1)
_INSPECTION_PRAGMAS = frozenset({"table_info", "table_xinfo"})


def _inspection_authorizer(action: int, arg1: Any, arg2: Any, dbname: Any, source: Any) -> int:
    """Read-only authorizer used AFTER the evidence script has run.

    The parser must still query its own in-memory database (``sqlite_master``,
    ``PRAGMA table_info``, ``SELECT * FROM <table>``), but nothing may write,
    create, attach or reconfigure anything any more. It is installed instead of
    ``set_authorizer(None)``: ``None`` only means "remove the authorizer" from
    Python 3.11; on 3.7-3.10 it registers a callback that is ``None``, every call
    raises inside SQLite's C trampoline, and that is reported as DENY - i.e. every
    later query fails with ``not authorized``.
    """
    if action in (_SELECT, _READ, _FUNCTION, _RECURSIVE):
        return _OK
    if action == _PRAGMA and str(arg1).lower() in _INSPECTION_PRAGMAS:
        return _OK
    return _DENY

_HEADER_CAPTURED = re.compile(r"^--\s*Captured at:\s*(\S+)\s*$", re.M)
_HEADER_TOPOLOGY = re.compile(r"^--\s*Database topology:\s*(\S+)\s*$", re.M)
_HEADER_DIALECT = re.compile(r"^--\s*Dialect:\s*(.+?)\s*$", re.M)
_HEADER_COMPLETED = re.compile(r"^--\s*snapshot_completed_at=(\S+)\s*$", re.M)


def parse_sql_header(text: str) -> Dict[str, Optional[str]]:
    """Comment metadata (``-- Captured at:`` etc.). Missing items are ``None``."""
    def first(rx: "re.Pattern[str]") -> Optional[str]:
        m = rx.search(text)
        return m.group(1) if m else None

    return {"captured_at": first(_HEADER_CAPTURED), "topology": first(_HEADER_TOPOLOGY),
            "dialect": first(_HEADER_DIALECT), "snapshot_completed_at": first(_HEADER_COMPLETED)}


def _has_sql(text: str) -> bool:
    """True if ``text`` contains anything besides blank lines and ``--`` comments."""
    return any(ln.strip() and not ln.strip().startswith("--") for ln in text.splitlines())


def _execute_script(text: str) -> Tuple[sqlite3.Connection, Dict[str, int], List[Dict[str, Any]]]:
    """Run the script in an isolated in-memory DB, one complete statement at a time.

    Statements are split with ``sqlite3.complete_statement`` (which understands
    quotes, multi-line literals and comments), so a failing statement is reported
    with its line number and the statements after it still execute - one bad
    INSERT does not discard the rest of the snapshot. Returns (connection,
    statement counts, statement errors).
    """
    # isolation_level=None = explicit autocommit: the file's own BEGIN/COMMIT run as written
    # and Python never injects an implicit COMMIT between statements.
    con = sqlite3.connect(":memory:", isolation_level=None)
    counts: Dict[str, int] = {}

    def authorizer(action: int, arg1: Any, arg2: Any, dbname: Any, source: Any) -> int:
        if action in (_ATTACH, _DETACH, _CREATE_VTABLE):
            return _DENY
        if action == _PRAGMA and str(arg1).lower() != "foreign_keys":
            return _DENY
        name = _ACTION_NAMES.get(action)
        # CREATE TABLE/INDEX make SQLite write to its own sqlite_master; that is not a user statement
        if name and not str(arg1).lower().startswith("sqlite_"):
            counts[name] = counts.get(name, 0) + 1
        return _OK

    errors: List[Dict[str, Any]] = []

    def run(chunk: str, line: int) -> None:
        try:
            try:
                con.execute(chunk)
            except (sqlite3.ProgrammingError, sqlite3.Warning) as exc:
                if "one statement" not in str(exc):
                    raise
                con.executescript(chunk)  # several statements on one line (rare)
        except sqlite3.Error as exc:
            first = next((ln.strip() for ln in chunk.splitlines() if ln.strip() and not ln.strip().startswith("--")), "")
            errors.append({"line": line, "statement": first[:80], "error": "%s: %s" % (type(exc).__name__, exc)})

    con.set_authorizer(authorizer)
    buf: List[str] = []
    start = 1
    for lineno, raw in enumerate(text.splitlines(keepends=True), start=1):
        if not buf:
            start = lineno
        buf.append(raw)
        chunk = "".join(buf)
        if sqlite3.complete_statement(chunk):
            run(chunk, start)
            buf = []
    leftover = "".join(buf)
    if _has_sql(leftover):
        errors.append({"line": start, "statement": leftover.strip().splitlines()[0][:80], "error": "incomplete statement at end of file (no terminating ';')"})
    con.set_authorizer(_inspection_authorizer)  # NOT set_authorizer(None): see _inspection_authorizer
    return con, counts, errors


def _table_names(con: sqlite3.Connection) -> List[str]:
    rows = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid")
    return [r[0] for r in rows]


def _columns(con: sqlite3.Connection, table: str) -> List[str]:
    return [r[1] for r in con.execute('PRAGMA table_info("%s")' % table.replace('"', '""'))]


def _rows(con: sqlite3.Connection, table: str, columns: List[str]) -> List[Tuple[int, Dict[str, Any]]]:
    quoted = '"%s"' % table.replace('"', '""')
    try:
        cur = con.execute("SELECT rowid, * FROM %s ORDER BY rowid" % quoted)
        return [(r[0], dict(zip(columns, r[1:]))) for r in cur]
    except sqlite3.OperationalError:  # WITHOUT ROWID table: fall back to scan order
        cur = con.execute("SELECT * FROM %s" % quoted)
        return [(i + 1, dict(zip(columns, r))) for i, r in enumerate(cur)]


def parse_sql_text(ref: EvidenceFileRef, text: str) -> ParsedFile:
    header = parse_sql_header(text)
    stated_time = header["captured_at"] or header["snapshot_completed_at"]
    stated_field = "header_captured_at" if header["captured_at"] else ("snapshot_completed_at" if header["snapshot_completed_at"] else None)
    ctx = FileContext(ref, ref.file_path, SourceFormat.SQL, file_content_time=stated_time, file_content_time_field=stated_field)
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.SQL, status=ParseStatus.PARSED, ref=ref)
    cov = parsed.coverage
    meta: Dict[str, Any] = {"header": header}
    parsed.metadata = meta

    # --- execute -------------------------------------------------------------
    con, counts, errors = _execute_script(text)
    meta["statement_counts"] = counts
    meta["statement_errors"] = errors
    for err in errors:
        ctx.warn("SQL_STATEMENT_ERROR", "line %d `%s` failed (%s); later statements were still executed" % (err["line"], err["statement"], err["error"]), "line=%d" % err["line"])
    tables = _table_names(con)
    meta["tables"] = tables
    if not tables:
        ctx.warn("SQL_NO_TABLES", "script produced no tables")
    if stated_time is None:
        ctx.warn("SQL_SNAPSHOT_TIME_MISSING", "no '-- Captured at:' or '-- snapshot_completed_at=' comment; capture time falls back to the manifest")
    for label in ("captured_at", "snapshot_completed_at"):
        v = header[label]
        if v is not None and ctx.check_ts(v, "header %s" % label, "header") is not None and v != ref.captured_at:
            ctx.warn("SQL_CAPTURE_TIME_DISAGREES_WITH_MANIFEST", "header %s=%s but manifest captured_at=%s" % (label, v, ref.captured_at), "header")

    # --- snapshot_scope first: it supplies per-system capture times -------------
    scope_time: Dict[str, Optional[str]] = {}
    table_layouts: Set[str] = set()
    if SNAPSHOT_SCOPE_TABLE in tables and SNAPSHOT_SCOPE_COLUMNS <= frozenset(_columns(con, SNAPSHOT_SCOPE_TABLE)):
        cols = _columns(con, SNAPSHOT_SCOPE_TABLE)
        table_layouts.add("snapshot_scope")
        cov.containers_seen += 1
        cov.containers_recognized += 1
        for rowid, row in _rows(con, SNAPSHOT_SCOPE_TABLE, cols):
            loc = "table=%s;rowid=%d" % (SNAPSHOT_SCOPE_TABLE, rowid)
            cov.records_seen += 1
            cov.records_recognized += 1
            ts = ctx.check_ts(row["captured_at"], "captured_at", loc)
            if ts and ts != ref.captured_at:
                ctx.warn("SQL_CAPTURE_TIME_DISAGREES_WITH_MANIFEST", "scope row %s captured_at=%s but manifest captured_at=%s" % (row["origin_system"], ts, ref.captured_at), loc)
            scope_time[row["origin_system"]] = ts
            parsed.scopes.append(SnapshotScope(ScopeKind.SQL_ORIGIN_SYSTEM, ref.file_id, row["origin_system"], SNAPSHOT_SCOPE_TABLE,
                                               ts, TimestampSource.SNAPSHOT_CAPTURED if ts else TimestampSource.NONE, None, loc))
    elif SNAPSHOT_SCOPE_TABLE in tables:
        ctx.warn("SQL_UNKNOWN_TABLE", "table snapshot_scope lacks columns origin_system/captured_at", "table=%s" % SNAPSHOT_SCOPE_TABLE)
        cov.containers_seen += 1

    # --- data tables --------------------------------------------------------------
    for table in tables:
        if table == SNAPSHOT_SCOPE_TABLE:
            continue
        columns = _columns(con, table)
        layout = match_sql_layout(table, frozenset(columns))
        rows = _rows(con, table, columns)
        role, replica = classify_store(table)
        cov.containers_seen += 1
        if layout is None:
            ctx.warn("SQL_UNKNOWN_TABLE", "table %s (%s) matches no known layout; its %d row(s) are kept as unrecognized" % (table, ", ".join(columns), len(rows)), "table=%s" % table)
        else:
            cov.containers_recognized += 1
            table_layouts.add(layout.layout)
        systems_seen: Set[str] = set()
        unknown_collections: Dict[str, int] = {}
        scope_system = layout.system_id if layout else None
        # Snapshot time: inventory tables use their system's snapshot_scope row; every
        # other layout uses the script header. Missing -> None (never silently the manifest).
        if layout is not None and layout.time_basis == "scope":
            table_snapshot = scope_time.get(scope_system) or stated_time
        else:
            table_snapshot = stated_time
        table_flags: Tuple[str, ...] = () if table_snapshot else ("snapshot_time_missing",)

        for rowid, row in rows:
            loc = "table=%s;rowid=%d" % (table, rowid)
            cov.records_seen += 1
            obs = _row_observation(ctx, layout, table, role, replica, row, loc, table_snapshot, table_flags, unknown_collections)
            if obs.system_id:
                systems_seen.add(obs.system_id)
            parsed.observations.append(obs)
            if obs.kind is ObservationKind.UNRECOGNIZED:
                cov.records_unrecognized += 1
            else:
                cov.records_recognized += 1
        for coll, n in sorted(unknown_collections.items()):
            ctx.warn("UNKNOWN_COLLECTION", "collection_name %r (%d row(s)) is not a known collection; rows kept as unrecognized" % (coll, n), "table=%s" % table)
        parsed.scopes.append(SnapshotScope(
            ScopeKind.SQL_TABLE, ref.file_id, scope_system, table, table_snapshot,
            TimestampSource.SNAPSHOT_CAPTURED if table_snapshot else TimestampSource.NONE, len(rows), "table=%s" % table,
            store_role=role, replica_name=replica,
            extra={"layout": layout.layout if layout else None, "columns": tuple(columns), "origin_systems": tuple(sorted(systems_seen)),
                   "topology": header["topology"]}))

    parsed.layout = sql_file_layout(frozenset(table_layouts))
    parsed.warnings = ctx.warnings
    if not tables:
        parsed.status = ParseStatus.FAILED
    elif errors or cov.records_unrecognized or cov.containers_recognized < cov.containers_seen:
        parsed.status = ParseStatus.PARTIAL
    con.close()
    return parsed.finalize()


def _row_observation(
    ctx: FileContext, layout: Optional[SqlTableLayout], table: str, role: Optional[str], replica: Optional[str],
    row: Dict[str, Any], loc: str, snapshot_at: Optional[str], base_flags: Tuple[str, ...], unknown_collections: Dict[str, int],
) -> Observation:
    updated_field = layout.updated_field if layout else None
    updated_at = ctx.check_ts(row.get(updated_field), updated_field, loc) if updated_field and updated_field in row else None
    flags = base_flags
    if updated_at and snapshot_at and parse_iso_utc(updated_at) and parse_iso_utc(snapshot_at) and parse_iso_utc(updated_at) > parse_iso_utc(snapshot_at):
        ctx.warn("RECORD_UPDATED_AFTER_SNAPSHOT", "%s=%s is later than the snapshot time %s" % (updated_field, updated_at, snapshot_at), loc)
        flags = flags + ("updated_after_snapshot",)
    common = dict(locator=loc, store=table, snapshot_captured_at=snapshot_at, store_role=role, replica_name=replica,
                  record_updated_at=updated_at, record_updated_field=updated_field if updated_at else None)

    if layout is None:
        return unrecognized_observation(ctx, row, reason="unknown_table", **common)

    if layout.layout == "json_record_table":
        collection, origin = row.get("collection_name"), row.get("origin_system")
        try:
            payload = json.loads(row["record_json"])
        except (TypeError, ValueError) as exc:
            ctx.warn("SQL_RECORD_JSON_INVALID", "record_json is not valid JSON (%s)" % exc, loc)
            return unrecognized_observation(ctx, row, reason="record_json_invalid", collection=collection, system_id=origin, **common)
        if not isinstance(payload, dict):
            ctx.warn("SQL_RECORD_JSON_INVALID", "record_json is %s, expected an object" % type(payload).__name__, loc)
            return unrecognized_observation(ctx, row, reason="record_json_not_object", collection=collection, system_id=origin, **common)
        spec = COLLECTION_SPECS.get(collection)
        if spec is None:
            unknown_collections[str(collection)] = unknown_collections.get(str(collection), 0) + 1
            return unrecognized_observation(ctx, payload, reason="unknown_collection", collection=collection, system_id=origin, **common)
        if payload.get("resource_id") != row.get("resource_id"):
            ctx.warn("RESOURCE_ID_MISMATCH", "column resource_id=%r but record_json resource_id=%r" % (row.get("resource_id"), payload.get("resource_id")), loc)
        if spec.system_id and origin != spec.system_id:
            ctx.warn("SYSTEM_MISMATCH", "origin_system=%r but collection %s belongs to %s" % (origin, collection, spec.system_id), loc)
        if spec.ledger_like:
            obs = ledger_observation(ctx, payload, locator=loc, store=table, collection=collection, snapshot_captured_at=snapshot_at, flags=flags)
            if obs is None:
                return unrecognized_observation(ctx, payload, reason="ledger_missing_keys", collection=collection, system_id=origin, **common)
            return _with_store(obs, role, replica, updated_at, updated_field if updated_at else None)
        return collection_record_observation(ctx, spec, payload, locator=loc, system_id=origin, store=table, snapshot_captured_at=snapshot_at,
                                             store_role=role, replica_name=replica, record_updated_at=updated_at,
                                             record_updated_field=updated_field if updated_at else None, flags=flags)

    # typed layouts: the row itself is the record (NULL columns preserved as None)
    resource_id = row.get("resource_id") if isinstance(row.get("resource_id"), str) and row.get("resource_id") else None
    if resource_id is None:
        ctx.warn("RESOURCE_ID_MISSING", "row has no usable resource_id", loc)
    obs_id, prov = ctx.next_provenance(loc)
    return Observation(
        obs_id=obs_id, kind=ObservationKind.RECORD, provenance=prov, system_id=layout.system_id, resource_id=resource_id,
        record_type=layout.record_type, record_type_source="derived_from_layout", collection=None, store=table,
        store_role=role, replica_name=replica,
        state_field=layout.state_field if layout.state_field in row else None,
        state_value=row.get(layout.state_field) if layout.state_field else None,
        snapshot_captured_at=snapshot_at, record_updated_at=updated_at,
        record_updated_field=updated_field if updated_at else None,
        identifiers=extract_identifiers(row), fields=dict(row), flags=flags)


def _with_store(obs: Observation, role: Optional[str], replica: Optional[str], updated_at: Optional[str], updated_field: Optional[str]) -> Observation:
    return replace(obs, store_role=role, replica_name=replica, record_updated_at=updated_at, record_updated_field=updated_field)


def parse_sql_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    path = Path(dataset_dir) / ref.file_path
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.SQL, status=ParseStatus.FAILED, ref=ref)
        ctx = FileContext(ref, ref.file_path, SourceFormat.SQL)
        ctx.warn("FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_sql_text(ref, text)
