"""Stage 1B tests: log and plain-text-record ingestion.

Run from the repository root:

    python -m unittest discover -s code/tests -t code -v

Principles (same as Stage 1A)
  * Real-evidence tests assert structural facts reconciled against INDEPENDENT counts taken
    straight from the raw files; no case IDs, resource IDs of a particular case, or deletion
    labels are hard-coded.
  * Malformed-input / edge-case / security tests use small synthetic logs held in memory or
    in temporary directories.
  * The dataset is hashed before and after the module; any write fails it.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET = REPO_ROOT / "dataset"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit import contracts as C  # noqa: E402
from ghost_audit.evidence import (  # noqa: E402
    EXTENDED_FORMATS,
    HANDLED_FORMATS,
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
from ghost_audit.evidence.log_ingest import parse_log_file, parse_log_text, tokenize_line  # noqa: E402
from ghost_audit.evidence.manifest import resolve_inside  # noqa: E402
from ghost_audit.evidence.model import ScopeKind  # noqa: E402
from ghost_audit.evidence.schema_maps import LOG_EVENT_SPECS  # noqa: E402
from ghost_audit.evidence.text_ingest import parse_text_file, parse_text_record  # noqa: E402

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
    if _tree_hash() != _BEFORE:
        raise AssertionError("log/TXT ingestion modified the dataset")


@lru_cache(maxsize=1)
def extended():
    return ingest_dataset(DATASET, formats=EXTENDED_FORMATS)


def refs(fmt: SourceFormat) -> List[EvidenceFileRef]:
    return [r for r in load_manifest(DATASET)[0] if r.source_format is fmt]


def raw_lines(ref: EvidenceFileRef) -> List[str]:
    return (DATASET / ref.file_path).read_text(encoding="utf-8").split("\n")


def mkref(fmt: SourceFormat = SourceFormat.LOG, file_id: str = "evidence_950", captured: str = "2026-09-01T12:00:00Z") -> EvidenceFileRef:
    return EvidenceFileRef(file_id, "evidence/test/%s.%s" % (file_id, "log" if fmt is SourceFormat.LOG else "txt"), "test_origin", captured, fmt)


def kvline(ts: str, event: str, service: str = "account_service", trace: Optional[str] = None, **kw: str) -> str:
    parts = ["%s level=INFO service=%s event=%s" % (ts, service, event)]
    if trace:
        parts.append("trace_id=%s" % trace)
    parts += ['%s="%s"' % (k, v) for k, v in kw.items()]
    return " ".join(parts)


def parse(*lines: str, ref: Optional[EvidenceFileRef] = None):
    return parse_log_text(ref or mkref(), "\n".join(lines) + "\n")


T0, T1, T2 = "2026-09-01T10:00:00Z", "2026-09-01T10:00:01Z", "2026-09-01T10:00:02Z"


# =========================================================================== #
class TestTokenizer(unittest.TestCase):
    """One line per grammar: every grammar yields the same normalized event."""

    LINES = {
        "json_lines": T0 + ' {"severity":"INFO","service":"account_service","trace_id":"tr-1","event":"profile_lookup_started","lookup_key":"a@b.co"}',
        "syslog_rfc5424": T0 + ' <14>1 node-1 account_service tr-1 - - level=INFO event="profile_lookup_started" lookup_key="a@b.co"',
        "bracketed": T0 + ' [INFO] [account_service] [tr-1] profile_lookup_started: lookup_key="a@b.co" attempt="1"',
        "pipe_delimited": T0 + ' | INFO | account_service | tr-1 | profile_lookup_started | lookup_key="a@b.co"',
        "cloud_runtime": T0 + ' requestId=tr-1 level=INFO function=account_service message="instance=\\"x\\" event=\\"profile_lookup_started\\" lookup_key=\\"a@b.co\\""',
        "key_value": T0 + ' level=INFO service=account_service event=profile_lookup_started trace_id=tr-1 lookup_key="a@b.co"',
    }

    def test_all_grammars_normalize_to_the_same_event(self):
        for grammar, line in self.LINES.items():
            with self.subTest(grammar):
                ev = tokenize_line(7, line)
                self.assertIsNotNone(ev)
                self.assertEqual((ev.grammar, ev.ts, ev.level, ev.service, ev.trace_id, ev.event, ev.fields["lookup_key"], ev.line_no),
                                 (grammar, T0, "INFO", "account_service", "tr-1", "profile_lookup_started", "a@b.co", 7))

    def test_bare_level_record_lookup_grammar(self):
        ev = tokenize_line(1, T0 + ' INFO service=downstream_delivery_service event=record_lookup seq=1 system="account_service" resource_id="account_1" '
                               'record_type="USER_PROFILE" result="NOT_FOUND" subject_reference="a@b.co"')
        self.assertEqual((ev.grammar, ev.event, ev.fields["result"], ev.trace_id), ("key_value_bare_level", "record_lookup", "NOT_FOUND", None))

    def test_quoted_values_with_spaces_equals_and_escapes_are_decoded(self):
        ev = tokenize_line(1, T0 + ' level=INFO service=s event=e note="a b=c \\"q\\"" bare=x')
        self.assertEqual((ev.fields["note"], ev.fields["bare"]), ('a b=c "q"', "x"))

    def test_a_trace_slot_that_repeats_the_instance_is_not_a_trace_id(self):
        ev = tokenize_line(1, T0 + ' [INFO] [log_router] [collector-3] export_started: instance="collector-3" expected_source_events="4"')
        self.assertIsNone(ev.trace_id)

    def test_unparseable_lines_return_none(self):
        for bad in ("", "garbage", "2026-09-01 10:00:00 level=INFO service=s", T0 + " {not json", T0 + " [1,2]", T0 + " totally unknown shape",
                    "2026-09-01T10:00:00+02:00 level=INFO service=s event=e"):
            with self.subTest(bad):
                self.assertIsNone(tokenize_line(1, bad))

    def test_very_long_line_does_not_break_parsing(self):
        ev = tokenize_line(1, T0 + ' level=INFO service=s event=e blob="%s"' % ("x" * 200000))
        self.assertEqual(len(ev.fields["blob"]), 200000)


# =========================================================================== #
@needs_dataset
class TestRealLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs = refs(SourceFormat.LOG)
        cls.parsed = {r.file_id: parse_evidence_file(r, DATASET, EXTENDED_FORMATS) for r in cls.refs}

    def test_all_26_logs_parse_with_no_unrecognized_lines_and_no_warnings(self):
        self.assertEqual(len(self.parsed), 26)
        for fid, p in self.parsed.items():
            with self.subTest(fid):
                self.assertEqual(p.status, ParseStatus.PARSED)
                self.assertEqual([str(w) for w in p.warnings], [])
                self.assertEqual(p.coverage.records_unrecognized, 0)
                self.assertEqual((p.coverage.containers_seen, p.coverage.containers_recognized), (1, 1))

    def test_seven_grammars_are_recognised_one_per_file(self):
        self.assertEqual(Counter(p.layout for p in self.parsed.values()), {
            "log:key_value": 14, "log:json_lines": 2, "log:key_value_bare_level": 2, "log:syslog_rfc5424": 2,
            "log:bracketed": 2, "log:pipe_delimited": 2, "log:cloud_runtime": 2})

    def test_every_non_blank_line_is_accounted_for(self):
        total = 0
        for r in self.refs:
            p = self.parsed[r.file_id]
            non_blank = [l for l in raw_lines(r) if l.strip()]
            total += len(non_blank)
            self.assertEqual(p.coverage.records_seen, len(non_blank), r.file_id)
            self.assertEqual(p.coverage.records_recognized + p.coverage.records_unrecognized, len(non_blank), r.file_id)
            self.assertEqual(sum(p.metadata["role_counts"].values()), len(non_blank), r.file_id)
        self.assertEqual(total, 2211)

    def test_observation_count_reconciles_with_an_independent_regex_count_of_fact_lines(self):
        names = [e for e, s in LOG_EVENT_SPECS.items() if s.role in ("fact", "ledger_row")]
        rx = re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])" % "|".join(map(re.escape, names)))
        for r in self.refs:
            expected = sum(1 for l in raw_lines(r) if rx.search(l))
            self.assertEqual(len(self.parsed[r.file_id].observations), expected, r.file_id)

    def test_observations_point_back_to_the_exact_source_line(self):
        for r in self.refs:
            lines = raw_lines(r)
            for i, o in enumerate(self.parsed[r.file_id].observations):
                pv = o.provenance
                n = int(re.fullmatch(r"line=(\d+)", pv.locator).group(1))
                self.assertEqual(lines[n - 1], o.fields["log"]["raw_line"])
                self.assertTrue(lines[n - 1].startswith(o.record_observed_at))
                self.assertEqual((pv.file_id, pv.citable_id, pv.file_path, pv.origin, pv.file_captured_at, pv.source_format, pv.ordinal),
                                 (r.file_id, r.file_id, r.file_path, r.origin, r.captured_at, SourceFormat.LOG, i))
                self.assertEqual(o.fields["log"]["line"], n)

    def test_time_is_the_lines_own_timestamp_never_the_file_capture_time(self):
        for p in self.parsed.values():
            for o in p.observations:
                eff = o.effective_time()
                self.assertEqual((eff.value, eff.source), (o.record_observed_at, TimestampSource.RECORD_OBSERVED))
                self.assertIsNone(o.snapshot_captured_at)
                self.assertEqual(o.record_timestamp_field, "log_timestamp")
        later = [o.obs_id for p in self.parsed.values() for o in p.observations if "record_time_after_file_capture" in o.flags]
        self.assertEqual(later, [], "no log line post-dates its file's manifest capture time (checked against the data, not assumed)")

    def test_logs_add_no_new_timestamp_anomalies_and_the_two_known_ones_are_preserved(self):
        r = extended()
        codes = Counter(w.code for p in r.all_parsed() for w in p.warnings)
        self.assertEqual(codes["RECORD_TIMESTAMP_AFTER_FILE_CAPTURE"], 2)
        self.assertEqual(codes["FORMAT_DEFERRED"], 15)
        self.assertEqual(set(codes), {"RECORD_TIMESTAMP_AFTER_FILE_CAPTURE", "FORMAT_DEFERRED"})
        late = [w for p in r.all_parsed() for w in p.warnings if w.code == "RECORD_TIMESTAMP_AFTER_FILE_CAPTURE"]
        json_ids = {ref.file_id for ref in refs(SourceFormat.JSON)}
        self.assertEqual(len(late), 2)
        self.assertTrue(all(w.file_id in json_ids for w in late), "both come from the supplied JSON ledgers, none from logs/TXT")

    def test_declared_event_counts_match_the_parsed_platform_events(self):
        declared_files = 0
        for p in self.parsed.values():
            (scope,) = [s for s in p.scopes if s.kind is ScopeKind.LOG_EXPORT]
            x = scope.extra
            if x["declared_source_events"] is not None:
                declared_files += 1
                self.assertEqual(x["declared_source_events"], x["parsed_platform_events"], p.file_id)
                self.assertEqual(scope.record_count, x["declared_source_events"])
            if x["dropped"] is not None:
                self.assertEqual(x["dropped"], 0, p.file_id)
        self.assertEqual(declared_files, 11)

    def test_readback_logs_reconcile_target_queries_and_started_lookups(self):
        readback = [p for p in self.parsed.values() if p.scopes[0].extra["mode"] == "point_in_time"]
        self.assertEqual(len(readback), 11)
        for p in readback:
            x = p.scopes[0].extra
            self.assertEqual((x["target_count"], x["queries"], p.metadata["starts"]), (x["queries"],) * 3, p.file_id)
            self.assertEqual(p.metadata["orphan_starts"], 0)

    def test_scope_window_is_recorded_without_inventing_a_capture_time(self):
        for p in self.parsed.values():
            s = p.scopes[0]
            self.assertEqual((s.captured_at, s.captured_at_source), (None, TimestampSource.NONE))
            self.assertLessEqual(s.extra["first_event_at"], s.extra["last_event_at"])

    def test_start_events_become_trace_context_on_the_following_fact_and_are_verified_against_the_file(self):
        paired = 0
        for r in self.refs:
            lines = raw_lines(r)
            for o in self.parsed[r.file_id].observations:
                ctx = o.fields.get("trace_context")
                if ctx is None:
                    self.assertNotIn("trace_context", o.flags)
                    continue
                paired += 1
                start_line = lines[ctx["started_line"] - 1]
                self.assertIn(ctx["started_event"], start_line)
                self.assertIn(o.fields["log"]["trace_id"], start_line)
                self.assertLess(ctx["started_line"], o.fields["log"]["line"])
                self.assertEqual(ctx["started_at"], start_line[:20])
                self.assertIn("trace_context", o.flags)
        self.assertGreater(paired, 400)

    def test_lookup_keys_from_the_trace_context_become_identifiers_of_the_result(self):
        n = 0
        for p in self.parsed.values():
            for o in p.observations:
                key = (o.fields.get("trace_context") or {}).get("lookup_key")
                if key and "@" in key:
                    n += 1
                    self.assertIn(key.lower(), o.identifiers.emails_normalized)
                    self.assertIn("trace_context.lookup_key", [i.path for i in o.identifiers.items])
        self.assertGreater(n, 50)

    def test_trace_ids_reused_across_files_are_never_paired_across_files(self):
        files_by_trace: Dict[str, set] = {}
        for r in self.refs:  # taken from the RAW lines of every event, not only those that became observations
            for n, line in enumerate(raw_lines(r), start=1):
                ev = tokenize_line(n, line) if line.strip() else None
                if ev is not None and ev.trace_id:
                    files_by_trace.setdefault(ev.trace_id, set()).add(r.file_id)
        # In the supplied data no real trace id appears in two files (the names that do, such as
        # `resolver-3`, are emitting INSTANCES and are deliberately not treated as traces). Cross-file
        # isolation is therefore proven by the synthetic test above; here we verify every pairing stays in-file.
        self.assertEqual([t for t, f in files_by_trace.items() if len(f) > 1], [])
        self.assertTrue(all(not re.fullmatch(r"(?:collector|resolver|ext|notify)-\d+", t) for t in files_by_trace),
                        "instance names must never be mistaken for trace ids")
        for p in self.parsed.values():
            lines = raw_lines(p.ref)
            for o in p.observations:
                ctx = o.fields.get("trace_context")
                if ctx:  # the start line it was paired with is in THIS file and carries the same trace id
                    self.assertEqual(tokenize_line(0, lines[ctx["started_line"] - 1]).trace_id, o.fields["log"]["trace_id"])

    def test_states_are_the_logs_own_strings_verbatim(self):
        vals: Dict[str, set] = {}
        for p in self.parsed.values():
            for o in p.observations:
                if o.state_field:
                    self.assertIsInstance(o.state_value, str)
                    self.assertEqual(o.state_value, o.fields[o.state_field])
                    vals.setdefault("%s.%s" % (o.collection, o.state_field), set()).add(o.state_value)
        self.assertEqual(vals["profile_lookup_completed.http_status"], {"200", "404"})
        self.assertEqual(vals["connector_config_read_completed.enabled"], {"true", "false"})
        self.assertEqual({flag_value(v) for v in vals["restore_policy_read_completed.restore_allowed"]}, {True, False})

    def test_the_log_spelling_of_missing_values_is_kept_but_is_not_an_identifier(self):
        nulls = [o for p in self.parsed.values() for o in p.observations if "null" in o.fields.values()]
        self.assertGreater(len(nulls), 20)
        for o in nulls:
            kinds = {i.value for i in o.identifiers.items}
            self.assertNotIn("null", kinds)
            for k, v in o.fields.items():
                if v == "null":
                    self.assertNotIn(k, [i.path for i in o.identifiers.items])

    def test_identifier_extraction_leaves_nothing_unclassified(self):
        unc = [(o.obs_id, i.path, i.value) for p in self.parsed.values() for o in p.observations for i in o.identifiers.items if i.kind == "unclassified"]
        self.assertEqual(unc, [])
        refs_ = {v for p in self.parsed.values() for o in p.observations for v in o.identifiers.resource_refs}
        self.assertTrue(refs_ and all(re.fullmatch(r"[a-z_]+_\d+", v) for v in refs_))

    def test_redaction_markers_are_recorded_not_treated_as_identifiers(self):
        red = [o for p in self.parsed.values() for o in p.observations if o.identifiers.redacted_paths]
        self.assertTrue(red)
        for o in red:
            self.assertIn("message_text", o.identifiers.redacted_paths)
            self.assertEqual(o.fields["message_text"], "[REDACTED]")

    def test_record_lookup_rows_use_the_ledger_vocabulary(self):
        rows = [o for p in self.parsed.values() for o in p.observations if o.collection == "record_lookup"]
        self.assertEqual(len(rows), 75)
        for o in rows:
            self.assertEqual((o.kind, o.record_type_source, o.state_field, o.state_value, o.system_id, o.resource_id),
                             (ObservationKind.LOOKUP_RESULT, "source", "result", o.fields["result"], o.fields["system"], o.fields["resource_id"]))

    # Documented exception (Stage 2): a `contact_lookup_completed` row (an e-mail opt-in contact) is a MARKETING_PROFILE although the
    # platform that hosts it numbers it `analytics_*`; the public sample answer for such a record is a whole-record deletion.
    CROSS_PREFIX_TYPES = {("contact_lookup_completed", "MARKETING_PROFILE")}

    def test_record_types_and_resource_prefixes_agree_with_the_sql_json_evidence(self):
        with open(DATASET / "deletion_rules.csv", encoding="utf-8", newline="") as h:
            categories = {r["data_category"] for r in csv.DictReader(h)} | {"DATA_FLOW"}
        base = ingest_dataset(DATASET, include_activity=False)
        prefix_types: Dict[str, set] = {}
        for o in base.iter_observations():
            if o.record_type and o.resource_id:
                prefix_types.setdefault(re.sub(r"\d+$", "", o.resource_id), set()).add(o.record_type)
        for p in self.parsed.values():
            for o in p.observations:
                if o.record_type:
                    self.assertIn(o.record_type, categories)
                    prefix = re.sub(r"\d+$", "", o.resource_id)
                    if (o.collection, o.record_type) in self.CROSS_PREFIX_TYPES:
                        continue
                    self.assertIn(o.record_type, prefix_types.get(prefix, {o.record_type}), "%s %s" % (o.collection, o.resource_id))

    def test_no_log_observation_claims_a_state_it_did_not_read(self):
        for p in self.parsed.values():
            for o in p.observations:
                self.assertIs(o.kind, ObservationKind.LOOKUP_RESULT)
                if o.state_field is None:
                    self.assertIsNone(o.state_value)

    def test_activity_style_claims_are_not_mixed_in(self):
        self.assertEqual({o.kind for p in self.parsed.values() for o in p.observations}, {ObservationKind.LOOKUP_RESULT})


# =========================================================================== #
@needs_dataset
class TestRealTextRecord(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (cls.ref,) = refs(SourceFormat.TEXT)
        cls.parsed = parse_evidence_file(cls.ref, DATASET, EXTENDED_FORMATS)
        cls.lines = (DATASET / cls.ref.file_path).read_text(encoding="utf-8").split("\n")

    def test_parses_every_bullet_row(self):
        rows = [l for l in self.lines if l.startswith("- ")]
        p = self.parsed
        self.assertEqual((p.status, p.layout, [str(w) for w in p.warnings]), (ParseStatus.PARSED, "text:shift_handover", []))
        self.assertEqual((len(p.observations), p.coverage.records_seen, p.coverage.records_unrecognized), (len(rows), len(rows), 0))
        self.assertEqual(p.metadata["title"], self.lines[0])

    def test_row_values_and_times_are_preserved(self):
        snapshot = re.match(r"Snapshot: (\S+)", self.lines[1]).group(1)
        rows = [[c.strip() for c in l[2:].split(" | ")] for l in self.lines if l.startswith("- ")]
        for o, row in zip(self.parsed.observations, rows):
            ts, system, rid, rtype, result, subject = row
            self.assertEqual((o.record_observed_at, o.system_id, o.resource_id, o.record_type, o.state_value, o.record_type_source),
                             (ts, system, rid, rtype, result, "source"))
            self.assertEqual((o.snapshot_captured_at, o.provenance.file_content_time, o.provenance.file_content_time_field), (snapshot, snapshot, "snapshot"))
            self.assertEqual(o.effective_time().source, TimestampSource.RECORD_OBSERVED)
            self.assertEqual(o.fields["subject_reference"], subject)

    def test_case_of_identifiers_is_preserved(self):
        raw = "\n".join(self.lines)
        upper = [e for o in self.parsed.observations for e in o.identifiers.emails if e != e.lower()]
        self.assertTrue(upper, "the handover record contains upper-case e-mail addresses")
        for e in upper:
            self.assertIn(e, raw)  # byte-for-byte as written, not normalised

    def test_no_direct_identifier_rows_contribute_no_identifier_and_are_flagged(self):
        marked = [o for o in self.parsed.observations if o.fields["subject_reference"].lower() == "no direct identifier"]
        self.assertTrue(marked)
        for o in marked:
            self.assertTrue(o.identifiers.is_empty())
            self.assertIn("no_direct_identifier_marker", o.flags)
            self.assertEqual(o.fields["subject_reference"], "no direct identifier")

    def test_scope_and_provenance(self):
        (scope,) = self.parsed.scopes
        self.assertEqual((scope.kind, scope.record_count, scope.captured_at_source), (ScopeKind.TEXT_SNAPSHOT, len(self.parsed.observations), TimestampSource.SNAPSHOT_CAPTURED))
        for i, o in enumerate(self.parsed.observations):
            self.assertEqual((o.provenance.file_id, o.provenance.source_format, o.provenance.ordinal), (self.ref.file_id, SourceFormat.TEXT, i))
            self.assertRegex(o.provenance.locator, r"^line=\d+$")


# =========================================================================== #
class TestSyntheticLogs(unittest.TestCase):
    def codes(self, p, level=None):
        return Counter(w.code for w in p.warnings if level is None or w.level == level)

    def test_fact_event_with_trace_context(self):
        p = parse(kvline(T0, "profile_lookup_started", trace="tr-1", lookup_key="Ana@Example.com", attempt="1"),
                  kvline(T1, "cache_lookup", trace="tr-1", result="miss", cache="c"),
                  kvline(T2, "profile_lookup_completed", trace="tr-1", resource_id="account_1", rows="0", http_status="404"))
        self.assertEqual((p.status, p.layout, len(p.observations), self.codes(p)), (ParseStatus.PARSED, "log:key_value", 1, Counter()))
        o = p.observations[0]
        self.assertEqual((o.kind, o.system_id, o.resource_id, o.record_type, o.state_field, o.state_value, o.collection),
                         (ObservationKind.LOOKUP_RESULT, "account_service", "account_1", "USER_PROFILE", "http_status", "404", "profile_lookup_completed"))
        self.assertEqual((o.record_observed_at, o.provenance.locator, o.flags), (T2, "line=3", ("trace_context",)))
        self.assertEqual(o.fields["trace_context"], {"lookup_key": "Ana@Example.com", "started_event": "profile_lookup_started", "started_at": T0, "started_line": 1})
        self.assertEqual(o.identifiers.emails, ("Ana@Example.com",))  # case preserved
        self.assertEqual(p.metadata["cache_lookup_results"], {"miss": 1})
        self.assertEqual((p.coverage.records_seen, p.coverage.records_recognized), (3, 3))

    def test_a_start_without_a_following_fact_is_kept_but_nothing_is_inferred(self):
        p = parse(kvline(T0, "connector_config_read_started", "integration_service", trace="tr-1", subject_key="a@b.co"))
        (o,) = p.observations
        self.assertEqual((o.flags, o.state_field, o.state_value, o.record_type), (("lookup_started_without_completion",), None, None, None))
        self.assertEqual(o.identifiers.emails, ("a@b.co",))
        self.assertEqual([(w.code, w.level) for w in p.warnings], [("LOG_TRACE_INCOMPLETE", "info")])
        self.assertEqual(p.metadata["orphan_starts"], 1)

    def test_start_is_not_paired_with_a_fact_that_comes_before_it_or_in_another_trace(self):
        p = parse(kvline(T0, "profile_lookup_completed", trace="tr-1", resource_id="account_1", rows="1", http_status="200"),
                  kvline(T1, "profile_lookup_started", trace="tr-1", lookup_key="a@b.co"),
                  kvline(T2, "profile_lookup_completed", trace="tr-2", resource_id="account_2", rows="1", http_status="200"))
        facts = [o for o in p.observations if "lookup_started_without_completion" not in o.flags]
        self.assertTrue(all("trace_context" not in o.fields for o in facts))
        self.assertEqual(p.metadata["orphan_starts"], 1)

    def test_trace_ids_are_never_paired_across_files(self):
        a = parse(kvline(T0, "profile_lookup_started", trace="tr-9", lookup_key="a@b.co"), ref=mkref(file_id="evidence_951"))
        # the fact is on line 3 of file B, i.e. AFTER line 1 where file A's start sits: if starts leaked
        # between files, the "earlier line" test would let it pair, so this really exercises isolation
        b = parse(kvline(T0, "connection_acquired"), kvline(T0, "connection_acquired"),
                  kvline(T1, "profile_lookup_completed", trace="tr-9", resource_id="account_1", rows="1", http_status="200"),
                  ref=mkref(file_id="evidence_952"))
        self.assertEqual(a.metadata["orphan_starts"], 1)
        self.assertEqual(b.observations[0].provenance.locator, "line=3")
        self.assertNotIn("trace_context", b.observations[0].fields)
        self.assertEqual(b.observations[0].identifiers.emails, ())

    def test_infrastructure_chatter_is_counted_not_dropped(self):
        p = parse(kvline(T0, "connection_acquired", pool="p"), kvline(T1, "dependency_retry", reason="read_timeout"),
                  kvline(T2, "cache_refresh", "dns_cache", entries="3"))
        self.assertEqual((len(p.observations), p.coverage.records_seen, p.coverage.records_recognized, p.coverage.records_unrecognized), (0, 3, 3, 0))
        self.assertEqual(p.metadata["role_counts"], {"diagnostic": 2, "auxiliary": 1})
        self.assertEqual(p.metadata["event_counts"], {"connection_acquired": 1, "dependency_retry": 1, "cache_refresh": 1})

    def test_unparseable_line_is_kept_as_unrecognized_with_a_warning(self):
        p = parse(kvline(T0, "profile_lookup_completed", resource_id="account_1", rows="1", http_status="200"), "this is not a log line")
        self.assertEqual((p.status, p.coverage.records_seen, p.coverage.records_unrecognized), (ParseStatus.PARTIAL, 2, 1))
        bad = p.observations[1]
        self.assertEqual((bad.kind, bad.fields["raw_line"], bad.fields["line"], bad.flags), (ObservationKind.UNRECOGNIZED, "this is not a log line", 2, ("unrecognized", "log_line_unparseable")))
        self.assertEqual(self.codes(p), Counter({"LOG_LINE_UNPARSEABLE": 1}))

    def test_unknown_event_from_a_platform_service_is_unrecognized_but_from_an_auxiliary_service_is_not(self):
        p = parse(kvline(T0, "brand_new_event", "account_service", resource_id="account_1", email="a@b.co"), kvline(T1, "brand_new_event", "thread_pool"))
        self.assertEqual((p.status, [o.kind for o in p.observations]), (ParseStatus.PARTIAL, [ObservationKind.UNRECOGNIZED]))
        self.assertEqual((p.observations[0].resource_id, p.observations[0].identifiers.emails, p.observations[0].collection), ("account_1", ("a@b.co",), "brand_new_event"))
        self.assertEqual(self.codes(p), Counter({"LOG_EVENT_UNKNOWN": 1}))
        self.assertEqual(p.metadata["role_counts"], {"unknown": 1, "auxiliary": 1})

    def test_empty_and_all_garbage_logs_fail_visibly(self):
        for text, code in (("", "LOG_EMPTY"), ("\n\n  \n", "LOG_EMPTY"), ("junk\nmore junk\n", "LOG_NO_RECOGNIZED_LINES")):
            with self.subTest(repr(text)):
                p = parse_log_text(mkref(), text)
                self.assertEqual(p.status, ParseStatus.FAILED)
                self.assertIn(code, self.codes(p))

    def test_blank_lines_and_crlf_do_not_change_the_result(self):
        lines = [kvline(T0, "profile_lookup_started", trace="tr-1", lookup_key="a@b.co"),
                 kvline(T1, "profile_lookup_completed", trace="tr-1", resource_id="account_1", rows="0", http_status="404")]
        lf = parse_log_text(mkref(), "\n".join(lines) + "\n")
        crlf = parse_log_text(mkref(), "\r\n".join(lines) + "\r\n\r\n")
        self.assertEqual([o.to_dict() for o in lf.observations], [o.to_dict() for o in crlf.observations])
        self.assertEqual((lf.coverage.records_seen, crlf.coverage.records_seen), (2, 2))

    def test_impossible_timestamp_is_reported_and_labelled_when_it_falls_back(self):
        p = parse(kvline("2026-13-45T10:00:00Z", "profile_lookup_completed", resource_id="account_1", rows="1", http_status="200"))
        o = p.observations[0]
        self.assertEqual(self.codes(p), Counter({"TIMESTAMP_UNPARSEABLE": 1}))
        self.assertIsNone(o.record_observed_at)
        eff = o.effective_time()
        self.assertEqual((eff.value, eff.source), ("2026-09-01T12:00:00Z", TimestampSource.MANIFEST_CAPTURED))

    def test_line_after_the_file_capture_time_keeps_its_own_time_and_is_warned_about(self):
        p = parse(kvline("2026-09-05T00:00:00Z", "profile_lookup_completed", resource_id="account_1", rows="1", http_status="200"))
        o = p.observations[0]
        self.assertEqual(self.codes(p), Counter({"RECORD_TIMESTAMP_AFTER_FILE_CAPTURE": 1}))
        self.assertEqual((o.record_observed_at, o.effective_time().value, "record_time_after_file_capture" in o.flags), ("2026-09-05T00:00:00Z", "2026-09-05T00:00:00Z", True))

    def test_missing_resource_id_is_warned_but_the_line_is_kept(self):
        p = parse(kvline(T0, "profile_lookup_completed", rows="1", http_status="200"))
        self.assertEqual(self.codes(p), Counter({"RESOURCE_ID_MISSING": 1}))
        self.assertEqual((len(p.observations), p.observations[0].resource_id), (1, None))

    def test_incomplete_record_lookup_is_unrecognized(self):
        bad = T0 + ' INFO service=svc event=record_lookup seq=1 system="account_service" resource_id="account_1"'
        good = kvline(T1, "profile_lookup_completed", resource_id="account_2", rows="1", http_status="200")
        p = parse(bad, good)
        self.assertEqual((p.status, [o.kind for o in p.observations]), (ParseStatus.PARTIAL, [ObservationKind.UNRECOGNIZED, ObservationKind.LOOKUP_RESULT]))
        self.assertEqual((p.coverage.records_recognized, p.coverage.records_unrecognized), (1, 1))
        self.assertIn("LEDGER_ROW_INCOMPLETE", self.codes(p))
        only = parse(bad)  # nothing usable at all -> FAILED, still visibly kept
        self.assertEqual((only.status, only.observations[0].kind), (ParseStatus.FAILED, ObservationKind.UNRECOGNIZED))

    def test_free_text_email_and_redaction_marker_in_message_text(self):
        p = parse(kvline(T0, "message_read", "support_platform", resource_id="support_1", message_text="Please contact Jo@X.org about user_5"),
                  kvline(T1, "message_read", "support_platform", resource_id="support_2", message_text="[REDACTED]"))
        a, b = p.observations
        self.assertEqual([(i.kind, i.value, i.free_text) for i in a.identifiers.items], [("email", "Jo@X.org", True), ("user_id", "user_5", True)])
        self.assertEqual((b.identifiers.items, b.identifiers.redacted_paths), ((), ("message_text",)))

    def test_code_like_content_is_inert_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pwned"
            payload = "__import__('os').system('touch %s'); DROP TABLE x; $(touch %s)" % (marker.as_posix(), marker.as_posix())
            p = parse(kvline(T0, "profile_lookup_completed", resource_id="account_1", rows="1", http_status="200", note=payload))
            self.assertEqual(p.observations[0].fields["note"], payload)
            self.assertFalse(marker.exists())
            self.assertEqual(os.listdir(tmp), [])

    def test_state_field_absent_from_the_line_is_none_not_invented(self):
        p = parse(kvline(T0, "profile_lookup_completed", resource_id="account_1", rows="1"))
        self.assertEqual((p.observations[0].state_field, p.observations[0].state_value), (None, None))


class TestSyntheticExportMetadata(unittest.TestCase):
    def meta(self, started: str, completed: str, n_platform: int = 2):
        lines = [kvline(T0, "export_started", "log_router", **dict(kv.split("=") for kv in started.split()))] if started else []
        lines += [kvline(T1, "connection_acquired", pool="p%d" % i) for i in range(n_platform)]
        lines += [kvline(T2, "export_completed", "log_router", **dict(kv.split("=") for kv in completed.split()))] if completed else []
        return parse(*lines)

    def codes(self, p):
        return Counter(w.code for w in p.warnings)

    def test_matching_declaration_is_silent(self):
        p = self.meta("expected_source_events=2", "source_events=2 dropped=0")
        self.assertEqual(self.codes(p), Counter())
        (s,) = p.scopes
        self.assertEqual((s.kind, s.record_count, s.extra["declared_source_events"], s.extra["parsed_platform_events"], s.extra["dropped"]), (ScopeKind.LOG_EXPORT, 2, 2, 2, 0))

    def test_count_mismatch_is_reported_and_both_numbers_are_kept(self):
        p = self.meta("expected_source_events=5", "", n_platform=2)
        self.assertEqual(self.codes(p), Counter({"LOG_EVENT_COUNT_MISMATCH": 1}))
        self.assertEqual((p.scopes[0].extra["declared_source_events"], p.scopes[0].extra["parsed_platform_events"]), (5, 2))

    def test_dropped_events_are_reported(self):
        self.assertEqual(self.codes(self.meta("expected_source_events=2", "source_events=2 dropped=3")), Counter({"LOG_EVENTS_DROPPED": 1}))

    def test_conflicting_or_malformed_declarations(self):
        self.assertIn("LOG_METADATA_CONFLICT", self.codes(self.meta("expected_source_events=2", "source_events=3")))
        self.assertIn("LOG_METADATA_MALFORMED", self.codes(self.meta("expected_source_events=many", "")))

    def test_readback_query_counters_must_match_started_lookups(self):
        lines = [kvline(T0, "export_started", "readback_collector", target_count="2", mode="point_in_time"),
                 kvline(T0, "profile_lookup_started", trace="tr-1", lookup_key="a@b.co"),
                 kvline(T1, "profile_lookup_completed", trace="tr-1", resource_id="account_1", rows="0", http_status="404"),
                 kvline(T2, "export_completed", "readback_collector", queries="2", dropped="0")]
        p = parse(*lines)
        self.assertEqual(self.codes(p), Counter({"LOG_QUERY_COUNT_MISMATCH": 1}))
        self.assertEqual(p.scopes[0].extra["mode"], "point_in_time")

    def test_log_without_export_metadata_has_an_undeclared_scope(self):
        p = parse(kvline(T0, "connection_acquired"))
        self.assertEqual((p.scopes[0].extra["declared_source_events"], p.scopes[0].record_count), (None, 1))


class TestSyntheticTextRecord(unittest.TestCase):
    HEAD = "CUSTOMER PLATFORM - SHIFT HANDOVER\nSnapshot: 2026-09-01T12:00:00Z\n\nSome prose.\n\n"
    ROW = "- 2026-09-01T12:00:00Z | account_service | account_1 | USER_PROFILE | NOT_FOUND | A@B.co\n"

    def parse(self, text):
        return parse_text_record(mkref(SourceFormat.TEXT, "evidence_960"), text)

    def test_well_formed_record(self):
        p = self.parse(self.HEAD + self.ROW)
        o = p.observations[0]
        self.assertEqual((p.status, [str(w) for w in p.warnings], o.identifiers.emails, o.snapshot_captured_at), (ParseStatus.PARSED, [], ("A@B.co",), "2026-09-01T12:00:00Z"))
        self.assertEqual((p.metadata["title"], p.metadata["prose_or_header_lines"]), ("CUSTOMER PLATFORM - SHIFT HANDOVER", 3))

    def test_malformed_rows_are_kept_as_unrecognized(self):
        text = self.HEAD + self.ROW + "- 2026-09-01T12:00:00Z | account_service | only | four\n" + "2026-09-01T12:00:00Z | a | b | c | d | e\n"
        p = self.parse(text)
        self.assertEqual((p.status, p.coverage.records_seen, p.coverage.records_recognized, p.coverage.records_unrecognized), (ParseStatus.PARTIAL, 3, 1, 2))
        self.assertEqual(Counter(w.code for w in p.warnings), Counter({"TXT_ROW_MALFORMED": 2}))
        self.assertEqual([o.kind for o in p.observations], [ObservationKind.LOOKUP_RESULT, ObservationKind.UNRECOGNIZED, ObservationKind.UNRECOGNIZED])

    def test_missing_snapshot_header_is_reported_and_no_time_is_assumed(self):
        p = self.parse("TITLE\n\n" + self.ROW)
        self.assertEqual(Counter(w.code for w in p.warnings), Counter({"TXT_SNAPSHOT_MISSING": 1}))
        o = p.observations[0]
        self.assertEqual((o.snapshot_captured_at, o.record_observed_at, o.effective_time().source), (None, "2026-09-01T12:00:00Z", TimestampSource.RECORD_OBSERVED))

    def test_row_with_empty_required_field_and_bad_timestamp(self):
        p = self.parse(self.HEAD + "- 2026-09-01T12:00:00Z |  | account_1 | USER_PROFILE | NOT_FOUND | x\n" + "- yesterday | account_service | account_2 | USER_PROFILE | FOUND | y\n")
        self.assertIn("LEDGER_ROW_INCOMPLETE", {w.code for w in p.warnings})
        self.assertIn("TIMESTAMP_UNPARSEABLE", {w.code for w in p.warnings})
        self.assertEqual(p.observations[1].effective_time().source, TimestampSource.SNAPSHOT_CAPTURED)

    def test_no_rows_fails_and_crlf_is_equivalent(self):
        self.assertEqual(self.parse("TITLE\nSnapshot: 2026-09-01T12:00:00Z\n").status, ParseStatus.FAILED)
        lf, crlf = self.parse(self.HEAD + self.ROW), self.parse((self.HEAD + self.ROW).replace("\n", "\r\n"))
        self.assertEqual([o.to_dict() for o in lf.observations], [o.to_dict() for o in crlf.observations])


# =========================================================================== #
class TestSecurityBoundaries(unittest.TestCase):
    def test_resolve_inside_rejects_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dataset"
            (root / "evidence").mkdir(parents=True)
            (root / "evidence" / "ok.log").write_text("x", encoding="utf-8")
            outside = Path(tmp) / "secret.txt"
            outside.write_text("do-not-read", encoding="utf-8")
            self.assertEqual(resolve_inside(root, "evidence/ok.log"), (root / "evidence" / "ok.log").resolve())
            for bad in ("../secret.txt", "evidence/../../secret.txt", outside.as_posix(), ".."):
                with self.subTest(bad):
                    with self.assertRaises(ValueError):
                        resolve_inside(root, bad)

    def test_new_readers_refuse_manifest_paths_outside_the_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dataset"
            root.mkdir()
            (Path(tmp) / "secret.log").write_text(kvline(T0, "profile_lookup_completed", resource_id="account_1", rows="1", http_status="200") + "\n", encoding="utf-8")
            for fmt, reader in ((SourceFormat.LOG, parse_log_file), (SourceFormat.TEXT, parse_text_file)):
                ref = EvidenceFileRef("evidence_970", "../secret.log", "o", "2026-09-01T12:00:00Z", fmt)
                p = reader(ref, root)
                self.assertEqual((p.status, p.observations, [w.code for w in p.warnings]), (ParseStatus.FAILED, [], ["FILE_UNREADABLE"]))
                self.assertIn("outside the dataset", p.warnings[0].message)

    def test_unreadable_and_non_utf8_files_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "evidence").mkdir()
            (Path(tmp) / "evidence" / "bad.log").write_bytes(b"\xff\xfe\x00bad")
            for rel in ("evidence/missing.log", "evidence/bad.log"):
                p = parse_log_file(EvidenceFileRef("evidence_971", rel, "o", "2026-09-01T12:00:00Z", SourceFormat.LOG), tmp)
                self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["FILE_UNREADABLE"]))

    def test_log_and_text_parsers_do_not_use_sqlite_so_the_sql_authorizer_is_untouched(self):
        for name in ("log_ingest.py", "text_ingest.py"):
            text = (CODE_DIR / "ghost_audit" / "evidence" / name).read_text(encoding="utf-8")
            self.assertNotIn("sqlite3", text, name)
            self.assertNotIn("authorizer", text.lower(), name)
            for dangerous in ("eval(", "exec(", "subprocess", "os.system", "__import__("):
                self.assertNotIn(dangerous, text, "%s must never execute log content" % name)


# =========================================================================== #
@needs_dataset
class TestBackwardCompatibilityAndIntegration(unittest.TestCase):
    def test_default_ingestion_is_unchanged_stage_1a_behaviour(self):
        r = ingest_dataset(DATASET)
        self.assertEqual(Counter(p.status.value for p in r.files), {"parsed": 52, "deferred": 42})
        self.assertEqual(sum(len(p.observations) for p in r.files), 1781)
        self.assertEqual(HANDLED_FORMATS, (SourceFormat.SQL, SourceFormat.JSON))
        log_ref = refs(SourceFormat.LOG)[0]
        self.assertEqual(parse_evidence_file(log_ref, DATASET).status, ParseStatus.DEFERRED)
        self.assertEqual(parse_evidence_file(log_ref, DATASET, HANDLED_FORMATS).status, ParseStatus.DEFERRED)

    def test_extended_ingestion_parses_logs_and_text_and_defers_only_pdfs_and_images(self):
        r = extended()
        self.assertEqual(Counter(p.status.value for p in r.files), {"parsed": 79, "deferred": 15})
        self.assertEqual(Counter(p.source_format.value for p in r.files if p.status is ParseStatus.DEFERRED), {"image": 11, "pdf": 4})
        self.assertEqual(sum(len(p.observations) for p in r.files), 1781 + 1113)
        self.assertEqual(sum(p.coverage.records_seen for p in r.all_parsed()), 8122)  # 5,870 (Stage 1A) + 2,211 log lines + 41 TXT rows
        self.assertEqual(sum(p.coverage.records_unrecognized for p in r.all_parsed()), 0)
        self.assertEqual(r.manifest_warnings, [])

    def test_stage_1a_observations_are_identical_in_both_modes(self):
        base = [o.to_dict() for p in ingest_dataset(DATASET).files if p.source_format in HANDLED_FORMATS for o in p.observations]
        ext = [o.to_dict() for p in extended().files if p.source_format in HANDLED_FORMATS for o in p.observations]
        self.assertEqual(json.dumps(base, sort_keys=True, default=str), json.dumps(ext, sort_keys=True, default=str))

    def test_extended_ingestion_is_deterministic_and_ids_are_unique_and_valid(self):
        a = json.dumps([o.to_dict() for o in ingest_dataset(DATASET, formats=EXTENDED_FORMATS).iter_observations()], sort_keys=True, default=str)
        b = json.dumps([o.to_dict() for o in extended().iter_observations()], sort_keys=True, default=str)
        self.assertEqual(a, b)
        obs = list(extended().iter_observations())
        self.assertEqual(len({o.obs_id for o in obs}), len(obs))
        for o in obs:
            self.assertTrue(C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(o.provenance.citable_id), o.obs_id)

    def test_every_extended_observation_has_a_system_resource_and_a_real_time(self):
        for p in extended().files:
            if p.source_format not in (SourceFormat.LOG, SourceFormat.TEXT):
                continue
            for o in p.observations:
                self.assertTrue(o.system_id and o.resource_id, o.obs_id)
                self.assertNotEqual(o.effective_time().source, TimestampSource.MANIFEST_CAPTURED)

    def test_registry_covers_every_event_in_the_real_logs(self):
        roles: Counter = Counter()
        events = set()
        for p in extended().files:
            if p.source_format is SourceFormat.LOG:
                roles.update(p.metadata["role_counts"])
                events.update(p.metadata["event_counts"])
        self.assertEqual(roles["unknown"], 0, "every event is either in the registry or emitted by an auxiliary service")
        self.assertGreaterEqual(len(events), 60)
        self.assertTrue(set(LOG_EVENT_SPECS) <= events, "no registry entry is speculative: each occurs in the evidence: %s" % (set(LOG_EVENT_SPECS) - events))


if __name__ == "__main__":
    unittest.main()
