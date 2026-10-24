"""Stage 1A tests: structured evidence ingestion (SQL, JSON, CSV).

Run from the repository root:

    python -m unittest discover -s code/tests -t code -v

Principles
  * Real-evidence tests use the supplied participant-visible files and assert
    *structural* facts (layout, counts reconciled independently with sqlite3 /
    json, timestamp semantics, provenance). They never hard-code case IDs,
    resource IDs of a particular case, or deletion labels.
  * Malformed-input tests use small synthetic fixtures, written only to
    temporary directories.
  * The dataset is hashed before and after the module runs; any write fails it.
"""
from __future__ import annotations

import ast
import csv
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET = REPO_ROOT / "dataset"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit import contracts as C  # noqa: E402  (Stage 0 integration)
from ghost_audit.evidence import (  # noqa: E402
    EvidenceFileRef,
    ObservationKind,
    ParseStatus,
    SourceFormat,
    TimestampSource,
    flag_value,
    ingest_dataset,
    load_manifest,
    parse_evidence_file,
)
from ghost_audit.evidence.csv_ingest import parse_activity_text  # noqa: E402
from ghost_audit.evidence.identifiers import classify_value, extract_identifiers  # noqa: E402
from ghost_audit.evidence.json_ingest import parse_json_text  # noqa: E402
from ghost_audit.evidence.model import ScopeKind  # noqa: E402
from ghost_audit.evidence import sql_ingest as sql_mod  # noqa: E402
from ghost_audit.evidence.sql_ingest import parse_sql_header, parse_sql_text  # noqa: E402
from ghost_audit.evidence.timestamps import is_iso_utc, parse_iso_utc  # noqa: E402

HAVE_DATASET = (DATASET / "evidence_files.csv").exists() and (DATASET / "evidence").is_dir()
needs_dataset = unittest.skipUnless(HAVE_DATASET, "dataset/ not present (e.g. unpacked code.zip)")

_BEFORE: Dict[str, str] = {}


def _tree_hash() -> Dict[str, str]:
    out: Dict[str, str] = {}
    if DATASET.is_dir():
        for dirpath, _d, names in os.walk(str(DATASET)):
            for n in names:
                p = os.path.join(dirpath, n)
                with open(p, "rb") as h:
                    out[os.path.relpath(p, str(DATASET))] = hashlib.sha256(h.read()).hexdigest()
    return out


def setUpModule() -> None:
    _BEFORE.update(_tree_hash())


def tearDownModule() -> None:
    after = _tree_hash()
    if after != _BEFORE:
        changed = sorted(set(after) ^ set(_BEFORE)) or sorted(k for k in after if after[k] != _BEFORE.get(k))
        raise AssertionError("evidence ingestion modified the dataset: %s" % changed[:5])


@lru_cache(maxsize=1)
def full_result():
    return ingest_dataset(DATASET)


def rec_query_for(doc, obs):
    """The original query string of the index_queries record an observation came from (independent lookup)."""
    m = re.match(r"^\$\.service_exports\.search_service\.index_queries\[(\d+)\]", obs.provenance.locator)
    return doc["service_exports"]["search_service"]["index_queries"][int(m.group(1))]["query"]


def refs_by_format(fmt: SourceFormat) -> List[EvidenceFileRef]:
    refs, _ = load_manifest(DATASET)
    return [r for r in refs if r.source_format is fmt]


def mkref(fmt: SourceFormat = SourceFormat.SQL, file_id: str = "evidence_900", captured: str = "2026-09-01T12:00:00Z") -> EvidenceFileRef:
    return EvidenceFileRef(file_id, "evidence/test/%s.%s" % (file_id, fmt.value), "test_origin", captured, fmt)


def sql_lit(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


GENERIC_DDL = ("CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT NOT NULL, "
               "collection_name TEXT NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL);")


def generic_row(table: str, rid: str, system: str, collection: str, payload, updated: str = "2026-09-01T11:00:00Z", raw_json: Optional[str] = None) -> str:
    rj = raw_json if raw_json is not None else json.dumps(payload)
    return "INSERT INTO %s VALUES(%s,%s,%s,%s,%s);" % (table, sql_lit(rid), sql_lit(system), sql_lit(collection), sql_lit(rj), sql_lit(updated))


def sql_script(body: List[str], captured: Optional[str] = "2026-09-01T12:00:00Z", topology: str = "primary_only") -> str:
    head = ["-- Ghost Data Still Exists: point-in-time database snapshot", "-- Dialect: SQLite-compatible SQL"]
    if captured:
        head += ["-- Captured at: %s" % captured, "-- Database topology: %s" % topology]
    return "\n".join(head + ["", "BEGIN TRANSACTION;"] + body + ["COMMIT;", ""])


# =========================================================================== #
class TestTimestamps(unittest.TestCase):
    def test_accepts_the_repository_format(self):
        self.assertTrue(is_iso_utc("2026-09-15T12:00:00Z"))
        self.assertEqual(parse_iso_utc("2026-09-15T12:00:00Z").isoformat(), "2026-09-15T12:00:00+00:00")
        self.assertIsNotNone(parse_iso_utc("2026-09-15T12:00:00.250Z"))

    def test_rejects_everything_else_instead_of_guessing(self):
        for bad in ("2026-09-15", "2026-09-15 12:00:00Z", "2026-09-15T12:00:00+02:00", "2026-09-15T12:00:00", "2026-13-15T12:00:00Z",
                    "", None, 20260915, "15 Sep 2026"):
            with self.subTest(bad):
                self.assertIsNone(parse_iso_utc(bad))


class TestIdentifierExtraction(unittest.TestCase):
    def kinds(self, record, **kw):
        return [(i.kind, i.value, i.path) for i in extract_identifiers(record, **kw).items]

    def test_fixed_fields_and_shapes(self):
        ids = extract_identifiers({"email": "A.B@Example.com", "email_hash": "a" * 64, "phone": "+44 7700 900016",
                                   "user_id": "user_7", "full_name": "Ada L"})
        self.assertEqual(ids.emails, ("A.B@Example.com",))           # case preserved
        self.assertEqual(ids.emails_normalized, ("a.b@example.com",))
        self.assertEqual((ids.email_hashes, ids.phones, ids.user_ids, ids.names), (("a" * 64,), ("+44 7700 900016",), ("user_7",), ("Ada L",)))

    def test_mixed_fields_are_classified_by_value_shape(self):
        for key in ("subject_reference", "subject_selector", "lookup_value", "customer_reference"):
            self.assertEqual(self.kinds({key: "user_12"}), [("user_id", "user_12", key)])
            self.assertEqual(self.kinds({key: "x@y.org"}), [("email", "x@y.org", key)])

    def test_value_shape_overrules_field_name(self):
        self.assertEqual(self.kinds({"email": "not-an-email"}), [("unclassified", "not-an-email", "email")])
        self.assertEqual(self.kinds({"email_hash": "short"}), [("unclassified", "short", "email_hash")])

    def test_missing_and_empty_values_are_skipped_not_invented(self):
        self.assertTrue(extract_identifiers({"email": None, "phone": "", "user_id": None, "full_name": "  ", "count": 3}).is_empty())

    def test_nested_paths_are_recorded(self):
        got = self.kinds({"document": {"email": "a@b.co", "display_name": "N"}, "hits": {"documents": [{"email": "c@d.co"}]}})
        self.assertIn(("email", "a@b.co", "document.email"), got)
        self.assertIn(("email", "c@d.co", "hits.documents[0].email"), got)

    def test_free_text_is_extracted_and_marked(self):
        ids = extract_identifiers({"message_text": "Please mail jo@x.org about user_44."})
        self.assertEqual([(i.kind, i.free_text) for i in ids.items], [("email", True), ("user_id", True)])

    def test_redaction_markers_are_recorded_not_treated_as_identifiers(self):
        ids = extract_identifiers({"message_text": "[REDACTED]", "email": "[redacted]", "full_name": "REDACTED"})
        self.assertTrue(ids.is_empty())
        self.assertEqual(set(ids.redacted_paths), {"message_text", "email", "full_name"})

    def test_classify_value(self):
        self.assertEqual([classify_value(v) for v in ("a@b.io", "user_9", "f" * 64, "+81 90 1234 5678", "hello")],
                         ["email", "user_id", "email_hash", "phone", None])

    def test_flag_value_normalises_sql_and_json_booleans(self):
        self.assertEqual([flag_value(v) for v in (1, 0, True, False, "true", "False", 2, "x", None)],
                         [True, False, True, False, True, False, None, None, None])


# =========================================================================== #
@needs_dataset
class TestManifest(unittest.TestCase):
    def test_real_manifest_is_complete_and_clean(self):
        refs, warnings = load_manifest(DATASET)
        self.assertEqual(len(refs), 94)
        self.assertEqual([str(w) for w in warnings], [])
        self.assertEqual(len({r.file_id for r in refs}), 94)
        self.assertEqual(Counter(r.source_format.value for r in refs), {"json": 28, "log": 26, "sql": 24, "image": 11, "pdf": 4, "text": 1})
        nums = [int(r.file_id.split("_")[1]) for r in refs]
        self.assertEqual(nums, sorted(nums), "manifest is returned in natural file_id order")

    def test_problems_are_reported_not_fixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "present.sql").write_text("-- x", encoding="utf-8")
            (root / "evidence" / "unlisted.json").write_text("{}", encoding="utf-8")
            (root / "evidence_files.csv").write_text(
                "file_id,file_path,origin,captured_at\n"
                "evidence_1,evidence/present.sql,o,2026-01-01T00:00:00Z\n"
                "evidence_1,evidence/present.sql,o,2026-01-01T00:00:00Z\n"
                "evidence_3,evidence/present.sql,o,2026-01-01T00:00:00Z\n"
                "evidence_2,evidence/gone.sql,o,2026-01-01T00:00:00Z\n", encoding="utf-8")
            refs, warnings = load_manifest(root)
        self.assertEqual([r.file_id for r in refs], ["evidence_1", "evidence_2", "evidence_3"])
        self.assertEqual({w.code for w in warnings}, {"MANIFEST_DUPLICATE_FILE_ID", "MANIFEST_DUPLICATE_PATH", "MANIFEST_FILE_MISSING", "MANIFEST_UNLISTED_FILE"})

    def test_missing_manifest_and_missing_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual([w.code for w in load_manifest(tmp)[1]], ["MANIFEST_UNREADABLE"])
            (Path(tmp) / "evidence_files.csv").write_text("file_id,path\nx,y\n", encoding="utf-8")
            self.assertEqual([w.code for w in load_manifest(tmp)[1]], ["MANIFEST_COLUMNS"])


# =========================================================================== #
@needs_dataset
class TestRealSqlEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs = refs_by_format(SourceFormat.SQL)
        cls.parsed = {r.file_id: parse_evidence_file(r, DATASET) for r in cls.refs}

    @staticmethod
    def sqlite_rows(ref: EvidenceFileRef) -> Dict[str, int]:
        """Independent ground truth: run the script ourselves and count rows per table."""
        con = sqlite3.connect(":memory:")
        con.executescript((DATASET / ref.file_path).read_text(encoding="utf-8"))
        names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        return {n: con.execute('SELECT COUNT(*) FROM "%s"' % n).fetchone()[0] for n in names}

    def test_all_24_files_parse_cleanly(self):
        self.assertEqual(len(self.parsed), 24)
        for fid, p in self.parsed.items():
            with self.subTest(fid):
                self.assertEqual(p.status, ParseStatus.PARSED)
                self.assertEqual([str(w) for w in p.warnings], [])
                self.assertEqual(p.coverage.records_unrecognized, 0)
                self.assertEqual(p.coverage.containers_recognized, p.coverage.containers_seen)

    def test_four_layouts_are_recognised(self):
        self.assertEqual(Counter(p.layout for p in self.parsed.values()), {
            "sql:inventory_snapshot": 11, "sql:json_record_replicas": 11, "sql:account_profile_replicas": 1, "sql:search_primary": 1})

    def test_observation_counts_reconcile_with_an_independent_sqlite_count(self):
        for ref in self.refs:
            with self.subTest(ref.file_id):
                truth = self.sqlite_rows(ref)
                p = self.parsed[ref.file_id]
                per_store = Counter(o.store for o in p.observations)
                self.assertEqual({t: n for t, n in truth.items() if t != "snapshot_scope"},
                                 {t: per_store.get(t, 0) for t in truth if t != "snapshot_scope"})
                # snapshot_scope rows become SnapshotScope objects, not observations
                self.assertEqual(p.coverage.records_seen, len(p.observations) + truth.get("snapshot_scope", 0))

    def test_replicas_are_kept_as_separate_stores_so_drift_stays_visible(self):
        drift_files = 0
        for p in self.parsed.values():
            if p.layout not in ("sql:json_record_replicas", "sql:account_profile_replicas"):
                continue
            by_role: Dict[str, set] = {"primary": set(), "replica": set()}
            for o in p.observations:
                self.assertIn(o.store_role, ("primary", "replica"))
                by_role[o.store_role].add(o.resource_id)
                self.assertEqual(o.replica_name is not None, o.store_role == "replica")
            self.assertTrue(by_role["primary"], p.file_id)
            if by_role["replica"] - by_role["primary"]:
                drift_files += 1
        self.assertGreaterEqual(drift_files, 1, "expected at least one snapshot where a replica holds a record the primary lacks")

    def test_regional_replica_files_expose_multiple_named_replicas(self):
        names = {o.replica_name for p in self.parsed.values() for o in p.observations if o.replica_name}
        self.assertTrue({"read_replica", "failover_replica", "reporting_replica", "replica_ap_south", "replica_eu_west"} <= names, names)

    def test_inventory_scope_rows_and_per_system_snapshot_time(self):
        for p in self.parsed.values():
            if p.layout != "sql:inventory_snapshot":
                continue
            truth = self.sqlite_rows(p.ref)["snapshot_scope"]
            scopes = [s for s in p.scopes if s.kind is ScopeKind.SQL_ORIGIN_SYSTEM]
            self.assertEqual(len(scopes), truth, p.file_id)
            by_system = {s.system_id: s.captured_at for s in scopes}
            for o in p.observations:
                self.assertEqual(o.snapshot_captured_at, by_system[o.system_id], "%s %s" % (p.file_id, o.obs_id))

    def test_every_table_gets_a_scope_with_its_true_row_count_including_empty_ones(self):
        zero_scopes = 0
        for p in self.parsed.values():
            truth = {t: n for t, n in self.sqlite_rows(p.ref).items() if t != "snapshot_scope"}
            table_scopes = {s.store: s for s in p.scopes if s.kind is ScopeKind.SQL_TABLE}
            self.assertEqual({t: s.record_count for t, s in table_scopes.items()}, truth, p.file_id)
            zero_scopes += sum(1 for n in truth.values() if n == 0)
        self.assertGreater(zero_scopes, 0, "the dataset contains empty tables; they must surface as explicit zero-count scopes")

    def test_a_fully_empty_snapshot_is_scope_only(self):
        empty = [p for p in self.parsed.values() if not p.observations]
        self.assertTrue(empty, "dataset has a snapshot whose tables are all empty")
        for p in empty:
            tables = [s for s in p.scopes if s.kind is ScopeKind.SQL_TABLE]
            self.assertTrue(tables)
            self.assertTrue(all(s.record_count == 0 for s in tables))
            self.assertTrue([s for s in p.scopes if s.kind is ScopeKind.SQL_ORIGIN_SYSTEM], "and it still states which system it covered")

    def test_snapshot_time_is_not_confused_with_record_update_time_or_manifest_time(self):
        differs = 0
        for p in self.parsed.values():
            header = parse_sql_header((DATASET / p.ref.file_path).read_text(encoding="utf-8"))
            stated = header["captured_at"] or header["snapshot_completed_at"]
            for o in p.observations:
                self.assertIsNone(o.record_observed_at, "SQL rows carry no observation time of their own")
                eff = o.effective_time()
                self.assertEqual(eff.source, TimestampSource.SNAPSHOT_CAPTURED)
                self.assertEqual(eff.value, o.snapshot_captured_at)
                self.assertEqual(o.snapshot_captured_at, stated)
                self.assertIsNotNone(o.record_updated_at)
                self.assertLessEqual(parse_iso_utc(o.record_updated_at), parse_iso_utc(o.snapshot_captured_at))
                differs += o.record_updated_at != o.snapshot_captured_at
        self.assertGreater(differs, 0, "record update time must stay distinct from snapshot time")

    def test_null_columns_are_preserved_and_yield_no_identifiers(self):
        found = 0
        for p in self.parsed.values():
            for o in p.observations:
                if o.record_type == "ANALYTICS_PROFILE" and o.fields.get("email") is None and "email" in o.fields:
                    found += 1
                    self.assertIsNone(o.fields["email"])
                    self.assertEqual(o.identifiers.emails, ())
                    self.assertIsNotNone(o.resource_id)
        self.assertGreater(found, 0)

    def test_json_in_sql_payload_is_preserved_verbatim(self):
        ref = next(r for r in self.refs if self.parsed[r.file_id].layout == "sql:json_record_replicas")
        con = sqlite3.connect(":memory:")
        con.executescript((DATASET / ref.file_path).read_text(encoding="utf-8"))
        truth = {}
        for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            for rid, origin, rj, upd in con.execute('SELECT resource_id, origin_system, record_json, updated_at FROM "%s"' % t):
                truth[(t, rid)] = (json.loads(rj), origin, upd)
        for o in self.parsed[ref.file_id].observations:
            payload, origin, upd = truth[(o.store, o.resource_id)]
            self.assertEqual(dict(o.fields), payload)
            self.assertEqual(o.system_id, origin)          # the row's origin_system column, not a guess
            self.assertEqual(o.record_updated_at, upd)

    def test_provenance_points_back_to_the_manifest_entry_and_the_row(self):
        seen = set()
        for p in self.parsed.values():
            for i, o in enumerate(p.observations):
                pv = o.provenance
                self.assertEqual((pv.file_id, pv.citable_id, pv.file_path, pv.origin, pv.file_captured_at, pv.source_format),
                                 (p.ref.file_id, p.ref.file_id, p.ref.file_path, p.ref.origin, p.ref.captured_at, SourceFormat.SQL))
                self.assertRegex(pv.locator, r"^table=\w+;rowid=\d+$")
                self.assertEqual(pv.ordinal, i)
                self.assertNotIn(o.obs_id, seen)
                seen.add(o.obs_id)

    def test_record_types_are_labelled_as_derived_from_layout(self):
        for p in self.parsed.values():
            for o in p.observations:
                if o.collection != "operational_record_history":
                    self.assertEqual(o.record_type_source, "derived_from_layout")
                    self.assertIsNotNone(o.record_type)

    def test_flag_columns_keep_their_verbatim_values(self):
        vals = {o.state_value for p in self.parsed.values() for o in p.observations if o.record_type in ("DATA_FLOW", "BACKUP_ARCHIVE") and o.state_field in ("enabled", "restore_allowed")}
        self.assertTrue(vals <= {0, 1, True, False} and vals, vals)

    def test_parsing_creates_no_files_and_leaves_sources_untouched(self):
        before_cwd = set(os.listdir("."))
        before_tree = _tree_hash()
        for r in self.refs[:5]:
            parse_evidence_file(r, DATASET)
        self.assertEqual(set(os.listdir(".")), before_cwd)
        self.assertEqual(_tree_hash(), before_tree)


class TestSyntheticSql(unittest.TestCase):
    def test_multi_statement_script_with_comments_pragma_and_indexes(self):
        text = sql_script([
            "PRAGMA foreign_keys=ON;", GENERIC_DDL, "-- a comment between statements",
            "CREATE INDEX idx_x ON customer_data_primary(collection_name);",
            generic_row("customer_data_primary", "account_1", "account_service", "customer_profiles",
                        {"resource_id": "account_1", "email": "a@b.co", "account_status": "ACTIVE", "customer_reference": None, "full_name": None, "phone": None, "signup_channel": "web"}),
            generic_row("customer_data_primary", "search_1", "search_service", "customer_search_documents",
                        {"resource_id": "search_1", "index_name": "i", "document": {"email": "a@b.co", "display_name": "A", "customer_reference": "user_1"}}),
        ])
        p = parse_sql_text(mkref(), text)
        self.assertEqual((p.status, p.layout, len(p.observations)), (ParseStatus.PARSED, "sql:json_record_replicas", 2))
        self.assertEqual(p.metadata["statement_counts"]["INSERT"], 2)
        self.assertEqual(p.metadata["header"]["topology"], "primary_only")
        profile, search = p.observations
        self.assertEqual((profile.record_type, profile.state_field, profile.state_value, profile.system_id), ("USER_PROFILE", "account_status", "ACTIVE", "account_service"))
        self.assertEqual(profile.identifiers.emails, ("a@b.co",))
        self.assertIn(("user_id", "user_1", "document.customer_reference"), [(i.kind, i.value, i.path) for i in search.identifiers.items])

    def test_failing_statement_is_reported_with_its_line_and_the_rest_still_loads(self):
        text = sql_script([GENERIC_DDL, generic_row("customer_data_primary", "a_1", "account_service", "customer_profiles", {"resource_id": "a_1"}),
                           "INSERT INTO nowhere VALUES(1);", generic_row("customer_data_primary", "a_2", "account_service", "customer_profiles", {"resource_id": "a_2"})])
        p = parse_sql_text(mkref(), text)
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertEqual([w.code for w in p.warnings], ["SQL_STATEMENT_ERROR"])
        self.assertIn("nowhere", p.warnings[0].message)
        self.assertEqual(p.metadata["statement_errors"][0]["line"], 9)  # reported with its line number
        self.assertEqual([o.resource_id for o in p.observations], ["a_1", "a_2"])  # statements after the failure still ran

    def test_attach_and_other_pragmas_are_denied_and_create_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "evil.db"
            for stmt in ("ATTACH DATABASE '%s' AS evil;" % target.as_posix(), "PRAGMA journal_mode=WAL;"):
                with self.subTest(stmt):
                    p = parse_sql_text(mkref(), sql_script([GENERIC_DDL, stmt]))
                    self.assertIn("SQL_STATEMENT_ERROR", {w.code for w in p.warnings})
            self.assertFalse(target.exists())
            self.assertEqual(os.listdir(tmp), [])

    def test_invalid_record_json_is_kept_as_unrecognized_with_a_warning(self):
        for label, raw in (("not json", "{oops"), ("not an object", "[1,2]")):
            with self.subTest(label):
                text = sql_script([GENERIC_DDL, generic_row("customer_data_primary", "x_1", "account_service", "customer_profiles", None, raw_json=raw)])
                p = parse_sql_text(mkref(), text)
                self.assertEqual(p.status, ParseStatus.PARTIAL)
                self.assertEqual((p.coverage.records_seen, p.coverage.records_unrecognized, len(p.observations)), (1, 1, 1))
                self.assertEqual(p.observations[0].kind, ObservationKind.UNRECOGNIZED)
                self.assertIn("SQL_RECORD_JSON_INVALID", {w.code for w in p.warnings})

    def test_unknown_collection_and_unknown_table_are_reported_not_dropped(self):
        text = sql_script([GENERIC_DDL, "CREATE TABLE mystery (resource_id TEXT, blob TEXT);", "INSERT INTO mystery VALUES('m_1','zzz');",
                           generic_row("customer_data_primary", "n_1", "new_service", "brand_new_collection", {"resource_id": "n_1", "email": "q@r.st"})])
        p = parse_sql_text(mkref(), text)
        self.assertEqual({w.code for w in p.warnings}, {"SQL_UNKNOWN_TABLE", "UNKNOWN_COLLECTION"})
        self.assertEqual(sorted(o.resource_id for o in p.observations), ["m_1", "n_1"])
        self.assertTrue(all(o.kind is ObservationKind.UNRECOGNIZED for o in p.observations))
        self.assertEqual(next(o for o in p.observations if o.resource_id == "n_1").identifiers.emails, ("q@r.st",))  # best-effort identifiers survive
        self.assertEqual((p.coverage.containers_seen, p.coverage.containers_recognized), (2, 1))

    def test_resource_id_and_system_mismatches_warn_but_keep_the_record(self):
        text = sql_script([GENERIC_DDL, generic_row("customer_data_primary", "col_id", "search_service", "customer_profiles", {"resource_id": "payload_id"})])
        p = parse_sql_text(mkref(), text)
        self.assertEqual({w.code for w in p.warnings}, {"RESOURCE_ID_MISMATCH", "SYSTEM_MISMATCH"})
        self.assertEqual(len(p.observations), 1)

    def test_missing_header_time_never_silently_becomes_the_manifest_time(self):
        text = sql_script([GENERIC_DDL, generic_row("customer_data_primary", "a_1", "account_service", "customer_profiles", {"resource_id": "a_1"})], captured=None)
        p = parse_sql_text(mkref(captured="2026-09-01T12:00:00Z"), text)
        self.assertIn("SQL_SNAPSHOT_TIME_MISSING", {w.code for w in p.warnings})
        o = p.observations[0]
        self.assertIsNone(o.snapshot_captured_at)
        self.assertIn("snapshot_time_missing", o.flags)
        eff = o.effective_time()
        self.assertEqual((eff.value, eff.source), ("2026-09-01T12:00:00Z", TimestampSource.MANIFEST_CAPTURED))  # explicitly labelled fallback

    def test_header_time_that_disagrees_with_the_manifest_is_reported(self):
        text = sql_script([GENERIC_DDL], captured="2026-09-02T00:00:00Z")
        p = parse_sql_text(mkref(captured="2026-09-01T12:00:00Z"), text)
        self.assertIn("SQL_CAPTURE_TIME_DISAGREES_WITH_MANIFEST", {w.code for w in p.warnings})
        self.assertEqual(p.metadata["header"]["captured_at"], "2026-09-02T00:00:00Z")

    def test_row_updated_after_snapshot_and_unparseable_updated_at(self):
        text = sql_script([GENERIC_DDL,
                           generic_row("customer_data_primary", "a_1", "account_service", "customer_profiles", {"resource_id": "a_1"}, updated="2026-09-05T00:00:00Z"),
                           generic_row("customer_data_primary", "a_2", "account_service", "customer_profiles", {"resource_id": "a_2"}, updated="yesterday")])
        p = parse_sql_text(mkref(), text)
        self.assertEqual({w.code for w in p.warnings}, {"RECORD_UPDATED_AFTER_SNAPSHOT", "TIMESTAMP_UNPARSEABLE"})
        late, bad = p.observations
        self.assertIn("updated_after_snapshot", late.flags)
        self.assertEqual(late.record_updated_at, "2026-09-05T00:00:00Z")
        self.assertIsNone(bad.record_updated_at)

    def test_empty_script_fails_visibly(self):
        p = parse_sql_text(mkref(), "-- nothing here\n")
        self.assertEqual(p.status, ParseStatus.FAILED)
        self.assertIn("SQL_NO_TABLES", {w.code for w in p.warnings})

    def test_inventory_snapshot_scope_without_data_tables(self):
        text = ("-- x\nCREATE TABLE snapshot_scope (origin_system TEXT PRIMARY KEY, captured_at TEXT NOT NULL);\n"
                "INSERT INTO snapshot_scope VALUES ('account_service','2026-09-01T12:00:00Z');\n-- snapshot_completed_at=2026-09-01T12:00:00Z\n")
        p = parse_sql_text(mkref(), text)
        self.assertEqual((len(p.observations), len(p.scopes), p.layout), (0, 1, "sql:inventory_snapshot"))
        self.assertEqual(p.scopes[0].kind, ScopeKind.SQL_ORIGIN_SYSTEM)


# =========================================================================== #
class _LegacyAuthorizerConnection(sqlite3.Connection):
    """A Connection that reproduces Python 3.7-3.10 behaviour for ``set_authorizer(None)``.

    Before Python 3.11 ``None`` did not remove the authorizer: the C layer still
    registered its trampoline with ``None`` as the callable, calling it raised
    ``TypeError`` and the trampoline turned that into SQLITE_DENY, so every later
    statement failed with ``not authorized``. Subclassing lets any interpreter
    (including 3.11+, where the bug is invisible) exercise that behaviour.
    """

    def set_authorizer(self, authorizer_callback):
        if authorizer_callback is None:
            authorizer_callback = lambda *args: sqlite3.SQLITE_DENY  # noqa: E731
        super().set_authorizer(authorizer_callback)


def _legacy_connect(*args, **kwargs):
    kwargs["factory"] = _LegacyAuthorizerConnection
    return _REAL_CONNECT(*args, **kwargs)


_REAL_CONNECT = sqlite3.connect
TWO_TABLE_SCRIPT = sql_script([
    GENERIC_DDL, "CREATE TABLE extra_table (a TEXT, b INTEGER);", "INSERT INTO extra_table VALUES('x', 1);",
    generic_row("customer_data_primary", "account_1", "account_service", "customer_profiles", {"resource_id": "account_1", "account_status": "ACTIVE"}),
])


class TestSqlAuthorizerLifecycle(unittest.TestCase):
    """Regression: the parser must read back the tables its own script created.

    Root cause of the original failure: ``con.set_authorizer(None)`` after the
    script ran. On Python < 3.11 that denies every later statement, including the
    parser's own ``SELECT ... FROM sqlite_master``.
    """

    def test_simulator_matches_the_documented_pre_3_11_behaviour(self):
        con = _legacy_connect(":memory:")
        con.set_authorizer(None)
        with self.assertRaises(sqlite3.DatabaseError) as cm:
            con.execute("SELECT name FROM sqlite_master").fetchall()
        self.assertIn("not authorized", str(cm.exception))

    def test_canary_what_set_authorizer_none_does_on_this_interpreter(self):
        con = sqlite3.connect(":memory:")
        con.set_authorizer(None)
        if sys.version_info >= (3, 11):
            con.execute("SELECT name FROM sqlite_master").fetchall()  # authorizer really removed
        else:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("SELECT name FROM sqlite_master").fetchall()  # the trap this module must avoid

    def test_ingestion_works_even_where_set_authorizer_none_denies_everything(self):
        with mock.patch.object(sqlite3, "connect", _legacy_connect):
            p = parse_sql_text(mkref(), TWO_TABLE_SCRIPT)
        # enumeration + row reading worked: both tables found, no statement or authorization error
        self.assertEqual(p.metadata["tables"], ["customer_data_primary", "extra_table"])
        self.assertEqual(p.metadata["statement_errors"], [])
        self.assertEqual({w.code for w in p.warnings}, {"SQL_UNKNOWN_TABLE"})  # extra_table is deliberately unknown -> PARTIAL, by design
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertEqual([(o.resource_id, o.kind) for o in p.observations if o.store == "customer_data_primary"], [("account_1", ObservationKind.RECORD)])
        self.assertEqual([o.kind for o in p.observations if o.store == "extra_table"], [ObservationKind.UNRECOGNIZED])

    def test_the_ingestion_source_never_calls_set_authorizer_with_none(self):
        """Static guard (comments/docstrings ignored): behaves the same on every interpreter."""
        tree = ast.parse(Path(sql_mod.__file__).read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "set_authorizer"]
        self.assertGreaterEqual(len(calls), 2, "expected the script-phase and the inspection-phase authorizer")
        for call in calls:
            arg = call.args[0]
            is_none = type(arg).__name__ in ("Constant", "NameConstant") and arg.value is None
            self.assertFalse(is_none, "line %d: set_authorizer(None) means 'remove' only on Python >= 3.11" % call.lineno)

    def test_tables_the_script_created_can_be_enumerated_and_read(self):
        con, counts, errors = sql_mod._execute_script(TWO_TABLE_SCRIPT)
        self.assertEqual(errors, [])
        self.assertEqual(sql_mod._table_names(con), ["customer_data_primary", "extra_table"])
        self.assertEqual(sql_mod._columns(con, "extra_table"), ["a", "b"])
        self.assertEqual(sql_mod._rows(con, "extra_table", ["a", "b"]), [(1, {"a": "x", "b": 1})])
        self.assertEqual({k: counts[k] for k in ("CREATE_TABLE", "INSERT")}, {"CREATE_TABLE": 2, "INSERT": 2})

    def test_connection_is_read_only_after_the_script_has_run(self):
        con, _counts, _errors = sql_mod._execute_script(TWO_TABLE_SCRIPT)
        con.execute("SELECT * FROM extra_table").fetchall()          # reads allowed
        con.execute('PRAGMA table_info("extra_table")').fetchall()   # introspection allowed
        for stmt in ("CREATE TABLE z (x)", "INSERT INTO extra_table VALUES('y', 2)", "UPDATE extra_table SET b = 9",
                     "DELETE FROM extra_table", "DROP TABLE extra_table", "CREATE INDEX i ON extra_table(a)",
                     "ATTACH DATABASE ':memory:' AS other", "PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=OFF", "VACUUM"):
            with self.subTest(stmt):
                with self.assertRaises(sqlite3.Error):
                    con.execute(stmt)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM extra_table").fetchone()[0], 1, "nothing was modified")

    def test_inspection_authorizer_decisions(self):
        ok, deny = sql_mod._OK, sql_mod._DENY
        allowed = [(20, "t", "c"), (21, None, None), (31, None, "like"), (33, None, None), (19, "table_info", "t"), (19, "TABLE_XINFO", "t")]
        denied = [(1, "i", "t"), (2, "t", None), (9, "t", None), (11, "t", None), (18, "t", None), (23, "t", "c"), (24, "f.db", None),
                  (25, "x", None), (29, "v", None), (19, "journal_mode", None), (19, "foreign_keys", "OFF"), (22, "BEGIN", None)]
        for args in allowed:
            self.assertEqual(sql_mod._inspection_authorizer(args[0], args[1], args[2], "main", None), ok, args)
        for args in denied:
            self.assertEqual(sql_mod._inspection_authorizer(args[0], args[1], args[2], "main", None), deny, args)

    def test_script_phase_still_blocks_dangerous_statements_and_creates_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            posix = Path(tmp).as_posix()
            attempts = {
                "ATTACH": "ATTACH DATABASE '%s/a.db' AS x;" % posix,
                "VACUUM INTO a file": "CREATE TABLE v0 (x); VACUUM INTO '%s/v.db';" % posix,
                "PRAGMA journal_mode": "PRAGMA journal_mode=WAL;",
                "PRAGMA writable_schema": "PRAGMA writable_schema=ON;",
                "PRAGMA temp_store_directory": "PRAGMA temp_store_directory='%s';" % posix,
                "virtual table": "CREATE VIRTUAL TABLE vt USING fts5(a);",
                "load_extension": "SELECT load_extension('nope');",
            }
            for label, stmt in attempts.items():
                with self.subTest(label):
                    p = parse_sql_text(mkref(), sql_script([GENERIC_DDL, stmt, "CREATE TABLE after_ok (x);"]))
                    errs = p.metadata["statement_errors"]
                    self.assertTrue(errs, "the statement must be refused")
                    self.assertTrue(any(("not authorized" in e["error"]) or ("authorization denied" in e["error"]) for e in errs),
                                    "refused by the authorizer, not by an unrelated error: %s" % errs)
                    self.assertIn("after_ok", p.metadata["tables"], "later legitimate statements still run")
            self.assertEqual(os.listdir(tmp), [])

    def test_foreign_keys_pragma_is_still_permitted(self):
        p = parse_sql_text(mkref(), sql_script(["PRAGMA foreign_keys=ON;", GENERIC_DDL]))
        self.assertEqual(p.metadata["statement_errors"], [])

    def test_script_cannot_read_or_modify_an_existing_external_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = Path(tmp) / "external.db"
            con = sqlite3.connect(str(ext))
            con.execute("CREATE TABLE secret (v TEXT)")
            con.execute("INSERT INTO secret VALUES ('do-not-leak')")
            con.commit()
            con.close()
            before = hashlib.sha256(ext.read_bytes()).hexdigest()
            script = sql_script(["ATTACH DATABASE '%s' AS ext;" % ext.as_posix(), "CREATE TABLE stolen AS SELECT * FROM ext.secret;",
                                 "INSERT INTO ext.secret VALUES ('injected');", "DELETE FROM ext.secret;"])
            p = parse_sql_text(mkref(), script)
            self.assertEqual(p.metadata["tables"], [], "nothing from the external database may appear")
            self.assertEqual(p.observations, [])
            self.assertEqual(len(p.metadata["statement_errors"]), 4)
            self.assertEqual(hashlib.sha256(ext.read_bytes()).hexdigest(), before, "external database untouched")


# =========================================================================== #
@needs_dataset
class TestRealJsonEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs = refs_by_format(SourceFormat.JSON)
        cls.parsed = {r.file_id: parse_evidence_file(r, DATASET) for r in cls.refs}
        cls.docs = {r.file_id: json.loads((DATASET / r.file_path).read_text(encoding="utf-8")) for r in cls.refs}

    def of_layout(self, layout: str):
        return [p for p in self.parsed.values() if p.layout == layout]

    def test_all_28_files_parse_with_only_the_known_timestamp_anomalies(self):
        self.assertEqual(len(self.parsed), 28)
        codes = Counter()
        for fid, p in self.parsed.items():
            self.assertEqual(p.status, ParseStatus.PARSED, fid)
            self.assertEqual(p.coverage.records_unrecognized, 0, fid)
            codes.update(w.code for w in p.warnings)
        self.assertEqual(set(codes), {"RECORD_TIMESTAMP_AFTER_FILE_CAPTURE"})

    def test_four_layouts_are_recognised_by_content_not_by_file_name(self):
        self.assertEqual(Counter(p.layout for p in self.parsed.values()), {
            "json:snapshot_bundle": 12, "json:service_resource_export": 11, "json:flat_ledger": 3, "json:single_collection": 2})

    def test_bundle_snapshots_keep_their_own_capture_time(self):
        earlier = 0
        for p in self.of_layout("json:snapshot_bundle"):
            doc = self.docs[p.file_id]
            self.assertEqual(len([s for s in p.scopes if s.kind is ScopeKind.JSON_SNAPSHOT]), len(doc["snapshots"]))
            self.assertEqual(p.coverage.records_seen, sum(len(s["records"]) for s in doc["snapshots"]))
            self.assertEqual(len(p.observations), p.coverage.records_seen)
            expected = {}
            for i, s in enumerate(doc["snapshots"]):
                for j in range(len(s["records"])):
                    expected["$.snapshots[%d].records[%d]" % (i, j)] = s["captured_at"]
            for o in p.observations:
                self.assertEqual(o.snapshot_captured_at, expected[o.provenance.locator])
                self.assertEqual(o.provenance.file_content_time, doc["exported_at"])
                if o.kind is ObservationKind.RECORD:
                    eff = o.effective_time()
                    self.assertEqual((eff.value, eff.source), (o.snapshot_captured_at, TimestampSource.SNAPSHOT_CAPTURED))
                    earlier += o.snapshot_captured_at < p.ref.captured_at
        self.assertGreater(earlier, 0, "some snapshots predate their file's manifest capture time and must keep their own time")

    def test_empty_snapshot_is_a_zero_count_scope(self):
        zero = [(p, s) for p in self.of_layout("json:snapshot_bundle") for s in p.scopes if s.record_count == 0]
        self.assertTrue(zero)
        for p, s in zero:
            self.assertFalse([o for o in p.observations if o.provenance.locator.startswith(s.locator + ".")])
            self.assertIsNotNone(s.captured_at)

    def test_operational_record_history_uses_the_records_own_system_and_time(self):
        n = 0
        for p in self.of_layout("json:snapshot_bundle"):
            for o in p.observations:
                if o.collection != "operational_record_history":
                    continue
                n += 1
                self.assertEqual(o.kind, ObservationKind.LOOKUP_RESULT)
                self.assertEqual((o.system_id, o.record_type, o.record_type_source), (o.fields["system"], o.fields["record_type"], "source"))
                self.assertNotEqual(o.store.split("/")[0], o.system_id, "the data_store is a container, not the record's system")
                self.assertEqual((o.state_field, o.state_value, o.record_observed_at), ("result", o.fields["result"], o.fields["recorded_at"]))
                self.assertEqual(o.effective_time().source, TimestampSource.RECORD_OBSERVED)
        self.assertGreater(n, 100)

    def test_service_export_search_hits_are_expanded_and_404_lookups_are_explicit(self):
        hits = lookups404 = 0
        for p in self.of_layout("json:service_resource_export"):
            doc = self.docs[p.file_id]
            n_docs = sum(len(r["hits"]["documents"]) for r in doc["service_exports"].get("search_service", {}).get("index_queries", []))
            self.assertEqual(sum(1 for o in p.observations if o.collection == "index_queries"), n_docs)
            self.assertEqual(p.coverage.records_seen, sum(len(r) for body in doc["service_exports"].values() for r in body.values()))
            for o in p.observations:
                self.assertEqual(o.record_observed_at, o.fields["observed_at"])
                self.assertEqual(o.effective_time().source, TimestampSource.RECORD_OBSERVED)
                self.assertEqual(o.provenance.file_content_time, doc["exported_at"])
                if o.collection == "index_queries":
                    hits += 1
                    doc_email = o.fields["document"].get("email")
                    if doc_email:
                        self.assertIn(("email", doc_email, "document.email"), [(i.kind, i.value, i.path) for i in o.identifiers.items])
                    self.assertEqual(o.fields["query"], rec_query_for(doc, o))
                if o.collection == "profile_lookups" and o.state_value == 404:
                    lookups404 += 1
                    self.assertIsNone(o.fields["profile"])
                    self.assertEqual(o.kind, ObservationKind.LOOKUP_RESULT)
        self.assertGreater(hits, 0)
        self.assertGreater(lookups404, 0)

    def test_service_sections_are_recorded_as_scopes_even_when_absent_sections_are_not(self):
        counts = Counter()
        for p in self.of_layout("json:service_resource_export"):
            sections = [s for s in p.scopes if s.kind is ScopeKind.JSON_SERVICE_SECTION]
            counts[len(sections)] += 1
            self.assertEqual({s.system_id for s in sections}, set(self.docs[p.file_id]["service_exports"]))
            for s in sections:
                self.assertEqual((s.captured_at, s.captured_at_source), (self.docs[p.file_id]["exported_at"], TimestampSource.FILE_EXPORTED))
        self.assertGreater(len(counts), 1, "files differ in which service sections they cover; that coverage must be visible")

    def test_flat_ledgers_preserve_record_times_even_after_the_file_capture_time(self):
        later = 0
        history: Dict[str, set] = {}
        for p in self.of_layout("json:flat_ledger"):
            doc = self.docs[p.file_id]
            self.assertEqual(len(p.observations), doc["record_count"])
            for o, rec in zip(p.observations, doc["records"]):
                self.assertEqual((o.record_observed_at, o.state_value, o.record_type, o.system_id, o.resource_id),
                                 (rec["recorded_at"], rec["result"], rec["record_type"], rec["system"], rec["resource_id"]))
                self.assertEqual(o.effective_time().source, TimestampSource.RECORD_OBSERVED)
                if rec["recorded_at"] > p.ref.captured_at:
                    later += 1
                    self.assertIn("record_time_after_file_capture", o.flags)
                    self.assertEqual(o.effective_time().value, rec["recorded_at"], "never replaced by the file capture time")
                history.setdefault(o.resource_id, set()).add((o.record_observed_at, o.state_value))
        self.assertEqual(later, 2)
        self.assertTrue(any(len({s for _t, s in h}) > 1 for h in history.values()),
                        "the same resource is reported in different states at different times inside one ledger; both must survive")

    def test_single_collection_files(self):
        for p in self.of_layout("json:single_collection"):
            doc = self.docs[p.file_id]
            self.assertEqual(len(p.observations), len(doc["records"]))
            self.assertTrue(all(o.snapshot_captured_at == doc["captured_at"] for o in p.observations))
            self.assertEqual({o.system_id for o in p.observations}, {p.scopes[0].system_id})

    def test_tombstones_expose_identifiers_only_when_the_source_contains_them(self):
        tomb = [o for p in self.of_layout("json:snapshot_bundle") for o in p.observations if o.record_type == "ACCOUNT_TOMBSTONE"]
        self.assertTrue(any(o.identifiers.emails and o.identifiers.names and o.identifiers.phones and o.identifiers.email_hashes for o in tomb))
        bare = [o for o in tomb if not (o.identifiers.emails or o.identifiers.names or o.identifiers.phones or o.identifiers.email_hashes)]
        self.assertTrue(bare)
        for o in bare:
            for k in ("name", "email", "phone", "email_hash"):
                self.assertIsNone(o.fields[k])  # NULLs preserved verbatim
            # the stable reference is still extracted: it is the one identifier a tombstone may keep
            self.assertEqual(o.identifiers.user_ids, (o.fields["subject_reference"],))

    def test_identity_fields_keep_their_original_case(self):
        mixed = [e for o in full_result().iter_observations() for e in o.identifiers.emails if e != e.lower()]
        self.assertTrue(mixed, "the evidence contains upper/mixed-case e-mail addresses")

    def test_payloads_are_preserved_verbatim(self):
        for p in self.of_layout("json:snapshot_bundle"):
            doc = self.docs[p.file_id]
            by_loc = {o.provenance.locator: o for o in p.observations}
            for i, s in enumerate(doc["snapshots"]):
                for j, rec in enumerate(s["records"]):
                    self.assertEqual(dict(by_loc["$.snapshots[%d].records[%d]" % (i, j)].fields), rec)


class TestSyntheticJson(unittest.TestCase):
    REF = mkref(SourceFormat.JSON, "evidence_901", "2026-09-01T12:00:00Z")

    def parse(self, doc, ref=None, raw: Optional[str] = None):
        return parse_json_text(ref or self.REF, raw if raw is not None else json.dumps(doc))

    def codes(self, p):
        return {w.code for w in p.warnings}

    def test_invalid_json_fails(self):
        p = self.parse(None, raw="{not json")
        self.assertEqual((p.status, self.codes(p), p.observations), (ParseStatus.FAILED, {"JSON_INVALID"}, []))

    def test_unknown_layout_is_not_silently_dropped(self):
        for doc in ({"hello": "world"}, [1, 2, 3], "text"):
            with self.subTest(repr(doc)):
                p = self.parse(doc)
                self.assertEqual((p.status, self.codes(p)), (ParseStatus.FAILED, {"JSON_UNKNOWN_LAYOUT"}))
                self.assertEqual((len(p.observations), p.observations[0].kind), (1, ObservationKind.UNRECOGNIZED))
                self.assertEqual((p.coverage.records_seen, p.coverage.records_unrecognized), (1, 1))

    def bundle(self, snapshots, exported="2026-09-01T12:00:00Z"):
        doc = {"source": "t", "snapshots": snapshots}
        if exported is not None:
            doc["exported_at"] = exported
        return doc

    def test_snapshot_without_captured_at_falls_back_to_file_time_and_says_so(self):
        p = self.parse(self.bundle([{"data_store": "account_service", "collection": "customer_profiles", "records": [{"resource_id": "a_1", "account_status": "ACTIVE"}]}]))
        self.assertIn("SNAPSHOT_CAPTURED_AT_MISSING", self.codes(p))
        eff = p.observations[0].effective_time()
        self.assertEqual((eff.value, eff.source), ("2026-09-01T12:00:00Z", TimestampSource.FILE_EXPORTED))

    def test_file_with_no_time_anywhere_falls_back_to_manifest_with_a_warning(self):
        p = self.parse(self.bundle([{"data_store": "account_service", "collection": "customer_profiles", "records": [{"resource_id": "a_1"}]}], exported=None))
        self.assertTrue({"FILE_TIME_MISSING", "SNAPSHOT_CAPTURED_AT_MISSING"} <= self.codes(p))
        self.assertEqual(p.observations[0].effective_time().source, TimestampSource.MANIFEST_CAPTURED)

    def test_malformed_snapshot_unknown_collection_and_non_object_record(self):
        p = self.parse(self.bundle([
            {"collection": "customer_profiles"},
            {"data_store": "x_service", "collection": "never_heard_of_it", "captured_at": "2026-09-01T10:00:00Z", "records": [{"resource_id": "x_1", "email": "e@f.gh"}]},
            {"data_store": "account_service", "collection": "customer_profiles", "captured_at": "2026-09-01T10:00:00Z", "records": ["oops", {"resource_id": "a_1"}]},
        ]))
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertTrue({"JSON_SNAPSHOT_MALFORMED", "UNKNOWN_COLLECTION", "JSON_RECORD_NOT_OBJECT"} <= self.codes(p))
        self.assertEqual(Counter(o.kind.value for o in p.observations), {"unrecognized": 3, "record": 1})
        self.assertEqual((p.coverage.containers_seen, p.coverage.containers_recognized), (3, 1))
        unknown = next(o for o in p.observations if o.collection == "never_heard_of_it")
        self.assertEqual((unknown.resource_id, unknown.identifiers.emails), ("x_1", ("e@f.gh",)))

    def test_data_store_mismatch_is_a_warning_and_the_source_system_wins(self):
        p = self.parse(self.bundle([{"data_store": "search_service", "collection": "customer_profiles", "captured_at": "2026-09-01T10:00:00Z", "records": [{"resource_id": "a_1"}]}]))
        self.assertIn("DATA_STORE_MISMATCH", self.codes(p))
        self.assertEqual(p.observations[0].system_id, "search_service")

    def ledger(self, records, count=None, exported="2026-09-01T12:00:00Z"):
        return {"exported_at": exported, "origin": "ledger_o", "record_count": len(records) if count is None else count, "records": records}

    def row(self, **over):
        base = {"recorded_at": "2026-09-01T09:00:00Z", "system": "account_service", "resource_id": "account_1", "record_type": "USER_PROFILE", "result": "NOT_FOUND", "subject_reference": "a@b.co"}
        base.update(over)
        return base

    def test_ledger_row_without_or_with_bad_timestamp(self):
        rec_missing = self.row()
        del rec_missing["recorded_at"]
        p = self.parse(self.ledger([rec_missing, self.row(recorded_at="2026-09-01 09:00")]))
        self.assertEqual(self.codes(p), {"RECORD_TIMESTAMP_MISSING", "TIMESTAMP_UNPARSEABLE"})
        for o in p.observations:
            self.assertIsNone(o.record_observed_at)
            self.assertEqual(o.effective_time().source, TimestampSource.FILE_EXPORTED)

    def test_ledger_incomplete_row_and_count_mismatch(self):
        bad = self.row()
        del bad["result"]
        p = self.parse(self.ledger([self.row(), bad], count=5))
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertEqual(self.codes(p), {"RECORD_COUNT_MISMATCH", "LEDGER_ROW_INCOMPLETE"})
        self.assertEqual([o.kind.value for o in p.observations], ["lookup_result", "unrecognized"])

    def test_ledger_record_after_file_capture_keeps_its_own_time(self):
        p = self.parse(self.ledger([self.row(recorded_at="2026-09-03T00:00:00Z")]))
        o = p.observations[0]
        self.assertEqual(self.codes(p), {"RECORD_TIMESTAMP_AFTER_FILE_CAPTURE"})
        self.assertEqual((o.record_observed_at, o.effective_time().value), ("2026-09-03T00:00:00Z", "2026-09-03T00:00:00Z"))
        self.assertIn("record_time_after_file_capture", o.flags)

    def export(self, **sections):
        return {"exported_at": "2026-09-01T12:00:00Z", "region": "global", "source": "t", "service_exports": sections}

    def test_search_query_with_no_hits_is_an_explicit_no_hit_observation(self):
        p = self.parse(self.export(search_service={"index_queries": [{"resource_id": "search_1", "query": "x@y.zz", "observed_at": "2026-09-01T08:00:00Z", "hits": {"total": 0, "documents": []}}]}))
        o = p.observations[0]
        self.assertEqual((len(p.observations), o.kind, o.state_field, o.state_value, "no_hits" in o.flags), (1, ObservationKind.LOOKUP_RESULT, "hits.total", 0, True))
        self.assertEqual(o.identifiers.emails, ("x@y.zz",))

    def test_search_query_with_several_hits_yields_one_observation_per_hit(self):
        docs = [{"resource_id": "search_%d" % i, "display_name": None, "email": "h%d@y.zz" % i, "customer_reference": None, "email_hash": None, "phone": None} for i in (1, 2)]
        p = self.parse(self.export(search_service={"index_queries": [{"resource_id": "search_1", "query": "h@y.zz", "observed_at": "2026-09-01T08:00:00Z", "hits": {"total": 2, "documents": docs}}]}))
        self.assertEqual((p.coverage.records_seen, len(p.observations)), (1, 2))
        self.assertEqual([o.resource_id for o in p.observations], ["search_1", "search_2"])
        self.assertTrue(all(o.provenance.locator.endswith("hits.documents[%d]" % k) for k, o in enumerate(p.observations)))
        self.assertEqual([o.fields["hit_index"] for o in p.observations], [0, 1])
        self.assertTrue(all(o.record_observed_at == "2026-09-01T08:00:00Z" for o in p.observations))

    def test_unknown_service_section_is_kept_and_reported(self):
        p = self.parse(self.export(mystery_service={"things": [{"resource_id": "m_1", "observed_at": "2026-09-01T08:00:00Z"}]}))
        self.assertEqual((p.status, self.codes(p)), (ParseStatus.PARTIAL, {"UNKNOWN_SECTION"}))
        self.assertEqual(p.observations[0].kind, ObservationKind.UNRECOGNIZED)

    def test_service_record_without_observed_at_or_resource_id(self):
        p = self.parse(self.export(account_service={"profile_lookups": [{"profile": None, "status_code": 404}]}))
        self.assertEqual(self.codes(p), {"RECORD_TIMESTAMP_MISSING", "RESOURCE_ID_MISSING"})
        self.assertEqual(p.observations[0].effective_time().source, TimestampSource.FILE_EXPORTED)

    def test_non_list_section_is_reported(self):
        p = self.parse(self.export(account_service={"profile_lookups": {"oops": 1}}))
        self.assertIn("JSON_SECTION_MALFORMED", self.codes(p))
        self.assertEqual(p.status, ParseStatus.PARTIAL)

    def test_cross_format_equivalence_for_the_same_payload(self):
        """A record parsed from a JSON bundle and from SQL record_json must yield the same observation content."""
        payloads = {
            "customer_profiles": ("account_service", {"resource_id": "r_1", "email": "A@B.co", "full_name": "N", "phone": "+1 202 555 0100", "account_status": "DELETION_PENDING", "customer_reference": "user_3", "signup_channel": "web"}),
            "connector_configurations": ("integration_service", {"resource_id": "r_2", "connector_name": "c", "destination": "d", "enabled": True, "mode": "continuous_sync", "subject_selector": "user_9"}),
            "backup_catalog": ("backup_service", {"resource_id": "r_3", "archive_path": "s3://x", "encryption": "AES-256", "restore_allowed": False, "subject_reference": "z@y.xx"}),
            "deleted_customer_references": ("identity_service", {"resource_id": "r_4", "subject_reference": "user_5", "name": None, "email": None, "phone": None, "email_hash": None, "account_status": "DELETED"}),
        }
        snaps = [{"data_store": sys_, "collection": coll, "captured_at": "2026-09-01T10:00:00Z", "records": [pl]} for coll, (sys_, pl) in payloads.items()]
        from_json = parse_json_text(self.REF, json.dumps(self.bundle(snaps))).observations
        rows = [generic_row("customer_data_primary", pl["resource_id"], sys_, coll, pl) for coll, (sys_, pl) in payloads.items()]
        from_sql = parse_sql_text(mkref(), sql_script([GENERIC_DDL] + rows, captured="2026-09-01T10:00:00Z")).observations

        def view(o):
            return (o.system_id, o.resource_id, o.record_type, o.collection, o.state_field, o.state_value, dict(o.fields),
                    [(i.kind, i.value, i.path) for i in o.identifiers.items], o.snapshot_captured_at, o.kind)
        self.assertEqual([view(o) for o in from_json], [view(o) for o in from_sql])


# =========================================================================== #
@needs_dataset
class TestRealActivityCsv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = full_result().activity
        with open(DATASET / "system_activity.csv", encoding="utf-8", newline="") as handle:
            cls.rows = list(csv.DictReader(handle))

    def test_every_row_becomes_an_unverified_claim(self):
        p = self.parsed
        self.assertEqual((p.status, p.layout, len(p.observations), p.coverage.records_unrecognized), (ParseStatus.PARSED, "csv:system_activity", len(self.rows), 0))
        for o, row in zip(p.observations, self.rows):
            self.assertEqual(o.kind, ObservationKind.CLAIM)
            self.assertIn("unverified_claim", o.flags)
            self.assertEqual((o.obs_id, o.provenance.citable_id, o.resource_id, o.event_type, o.state_value, o.state_field),
                             (row["activity_id"], row["activity_id"], row["resource_id"], row["event_type"], row["reported_result"], "reported_result"))
            self.assertEqual(dict(o.fields), row)
            self.assertIsNone(o.provenance.file_id)
            self.assertEqual(o.provenance.source_format, SourceFormat.CSV)
            self.assertRegex(o.provenance.locator, r"^row=\d+$")

    def test_reported_results_are_kept_verbatim_and_never_promoted_to_state(self):
        self.assertEqual({o.state_value for o in self.parsed.observations}, {"SUCCESS", "FAILED", "PARTIAL"})
        self.assertTrue(all(o.record_type is None for o in self.parsed.observations))

    def test_event_time_is_the_claim_time_and_file_order_is_preserved(self):
        times = [o.record_observed_at for o in self.parsed.observations]
        self.assertTrue(all(o.effective_time().source is TimestampSource.EVENT_TIME for o in self.parsed.observations))
        self.assertNotEqual(times, sorted(times), "system_activity.csv is not in time order; the parser must not reorder or assume it")
        self.assertEqual([o.provenance.ordinal for o in self.parsed.observations], list(range(len(times))))

    def test_activity_ids_satisfy_the_stage0_evidence_id_contract(self):
        for o in self.parsed.observations:
            self.assertTrue(C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(o.provenance.citable_id))

    def test_link_events_expose_identifiers_found_in_the_details_text(self):
        links = [o for o in self.parsed.observations if o.event_type == "LINK_RESOURCE_IDENTITY"]
        self.assertTrue(links)
        for o in links:
            self.assertTrue(o.identifiers.emails and o.identifiers.user_ids)
            self.assertTrue(all(i.free_text and i.path == "details" for i in o.identifiers.items))

    def test_system_id_is_the_rows_target_system_verbatim(self):
        for o, row in zip(self.parsed.observations, self.rows):
            self.assertEqual((o.system_id, o.fields["source_system"]), (row["target_system"] or None, row["source_system"]))


class TestSyntheticActivity(unittest.TestCase):
    HEAD = "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n"

    def test_missing_columns_fail(self):
        p = parse_activity_text("activity_id,event_time\nactivity_1,2026-01-01T00:00:00Z\n")
        self.assertEqual((p.status, [w.code for w in p.warnings], p.observations), (ParseStatus.FAILED, ["CSV_COLUMNS"], []))

    def test_short_row_duplicate_id_and_bad_time(self):
        text = self.HEAD + ("activity_1,2026-01-01T00:00:00Z,DELETE_RECORD,deletion_worker,account_service,account_1,SUCCESS,ok\n"
                            "activity_2,2026-01-01T00:00:00Z,DELETE_RECORD\n"
                            "activity_1,not-a-time,DELETE_RECORD,deletion_worker,account_service,account_2,FAILED,again\n")
        p = parse_activity_text(text)
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertEqual({w.code for w in p.warnings}, {"CSV_ROW_WIDTH", "ACTIVITY_DUPLICATE_ID", "TIMESTAMP_UNPARSEABLE", "RECORD_TIMESTAMP_MISSING"})
        self.assertEqual([o.kind.value for o in p.observations], ["claim", "unrecognized", "claim"])
        self.assertIsNone(p.observations[2].record_observed_at)
        self.assertEqual((p.coverage.records_seen, p.coverage.records_recognized, p.coverage.records_unrecognized), (3, 2, 1))


# =========================================================================== #
@needs_dataset
class TestIngestAll(unittest.TestCase):
    def test_every_manifest_file_is_accounted_for(self):
        r = full_result()
        self.assertEqual(len(r.files), 94)
        self.assertEqual(Counter(p.status.value for p in r.files), {"parsed": 52, "deferred": 42})
        self.assertEqual(Counter(p.source_format.value for p in r.files if p.status is ParseStatus.DEFERRED), {"log": 26, "image": 11, "pdf": 4, "text": 1})
        for p in r.files:
            if p.status is ParseStatus.DEFERRED:
                self.assertEqual([(w.code, w.level) for w in p.warnings], [("FORMAT_DEFERRED", "info")])
                self.assertEqual(p.observations, [])
        self.assertEqual(r.manifest_warnings, [])

    def test_no_unrecognized_records_anywhere_in_the_real_evidence(self):
        self.assertEqual(sum(p.coverage.records_unrecognized for p in full_result().all_parsed()), 0)
        self.assertEqual([o for o in full_result().iter_observations() if o.kind is ObservationKind.UNRECOGNIZED], [])

    def test_known_totals(self):
        r = full_result()
        self.assertEqual(sum(len(p.observations) for p in r.files), 1781)
        self.assertEqual(len(r.activity.observations), 4011)
        self.assertEqual(Counter(o.kind.value for o in r.iter_observations()), {"record": 1447, "lookup_result": 334, "claim": 4011})

    def test_ingestion_is_deterministic(self):
        a = json.dumps([o.to_dict() for o in ingest_dataset(DATASET).iter_observations()], sort_keys=True, default=str)
        b = json.dumps([o.to_dict() for o in ingest_dataset(DATASET).iter_observations()], sort_keys=True, default=str)
        self.assertEqual(a, b)

    def test_every_citable_id_is_valid_and_traceable(self):
        refs = {r.file_id for r in load_manifest(DATASET)[0]}
        for o in full_result().iter_observations():
            self.assertTrue(C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(o.provenance.citable_id), o.obs_id)
            if o.kind is not ObservationKind.CLAIM:
                self.assertIn(o.provenance.citable_id, refs)
        self.assertEqual(len({o.obs_id for o in full_result().iter_observations()}), 1781 + 4011)

    def test_every_observation_names_its_system_resource_and_a_time_source(self):
        for o in full_result().iter_observations():
            self.assertTrue(o.system_id and o.resource_id, o.obs_id)
            self.assertIsNotNone(o.effective_time().value, o.obs_id)
            self.assertNotEqual(o.effective_time().source, TimestampSource.MANIFEST_CAPTURED, "no observation should need the manifest fallback in the real data")

    def test_record_type_vocabulary_matches_the_repositorys_own(self):
        with open(DATASET / "deletion_rules.csv", encoding="utf-8", newline="") as h:
            categories = {r["data_category"] for r in csv.DictReader(h)}
        obs = [o for o in full_result().iter_observations() if o.kind is not ObservationKind.CLAIM]
        derived = {o.record_type for o in obs if o.record_type_source == "derived_from_layout"}
        stated = {o.record_type for o in obs if o.record_type_source == "source"}
        self.assertTrue(derived <= categories | {"DATA_FLOW"}, derived - categories)
        self.assertTrue(stated <= derived, stated - derived)

    def test_dataset_row_totals_match_independent_counts(self):
        r = full_result()
        sql_rows = sum(TestRealSqlEvidence.sqlite_rows(p.ref).get(t, 0) for p in r.files if p.source_format is SourceFormat.SQL
                       for t in TestRealSqlEvidence.sqlite_rows(p.ref) if t != "snapshot_scope")
        json_obs = sum(len(p.observations) for p in r.files if p.source_format is SourceFormat.JSON)
        self.assertEqual(sql_rows + json_obs, 1781)


# =========================================================================== #
class TestInspectCli(unittest.TestCase):
    SCRIPT = CODE_DIR / "inspect_evidence.py"

    def run_cli(self, *args: str):
        return subprocess.run([sys.executable, str(self.SCRIPT), *args], capture_output=True, text=True)

    @needs_dataset
    def test_table_report(self):
        proc = self.run_cli()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for token in ("file_id", "evidence_05", "(activity)", "Observations: 5792", "unrecognized: 0", "FORMAT_DEFERRED"):
            self.assertIn(token, proc.stdout)

    @needs_dataset
    def test_json_report_is_machine_readable(self):
        proc = self.run_cli("--json")
        data = json.loads(proc.stdout)
        self.assertEqual((data["totals"]["files"], data["totals"]["records_unrecognized"], data["totals"]["by_status"]),
                         (95, 0, {"parsed": 53, "deferred": 42}))

    @needs_dataset
    def test_filters_and_dump(self):
        proc = self.run_cli("--format", "sql", "--no-activity")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("json:", proc.stdout)
        self.assertIn("sql:inventory_snapshot", proc.stdout)
        proc = self.run_cli("--file", "evidence_05", "--dump", "1")
        self.assertIn("table=", proc.stdout)
        self.assertIn("effective=", proc.stdout)

    @needs_dataset
    def test_strict_passes_on_the_real_dataset(self):
        self.assertEqual(self.run_cli("--strict").returncode, 0)

    def test_strict_fails_on_a_dataset_with_a_malformed_file_and_bad_usage_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "broken.json").write_text("{nope", encoding="utf-8")
            (root / "evidence_files.csv").write_text("file_id,file_path,origin,captured_at\nevidence_1,evidence/broken.json,o,2026-01-01T00:00:00Z\n", encoding="utf-8")
            bad = self.run_cli("--dataset", tmp, "--no-activity", "--strict")
            self.assertEqual(bad.returncode, 1)
            self.assertIn("failed", bad.stdout)
            self.assertEqual(self.run_cli("--dataset", tmp, "--no-activity", "--file", "evidence_404").returncode, 2)
            self.assertEqual(self.run_cli("--dataset", str(root / "nope")).returncode, 2)


if __name__ == "__main__":
    unittest.main()
