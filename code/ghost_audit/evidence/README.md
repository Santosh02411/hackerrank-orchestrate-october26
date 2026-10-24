# Stage 1A - structured evidence ingestion (SQL, JSON, CSV)

Turns the supplied SQL snapshots, JSON exports and `system_activity.csv` into typed,
provenance-carrying `Observation` objects. It **does not** resolve identities, apply the
deletion policy, decide whether anything is deleted, plan remediation or write predictions.
Logs, PDFs, images and the TXT handover record are reported as `deferred` (Stage 1B).

```
evidence/model.py        dataclasses + enums (Observation, Provenance, Identifiers, SnapshotScope, ParsedFile, ...)
evidence/timestamps.py   strict ISO-8601 'Z' helpers
evidence/identifiers.py  find + label emails / hashes / phones / user ids / names (no matching)
evidence/schema_maps.py  static layout tables derived from the real files (collections, SQL tables, sections)
evidence/manifest.py     evidence_files.csv loader (+ duplicate / missing / unlisted-file warnings)
evidence/builders.py     FileContext (provenance, warnings, timestamp checks) + shared observation builders
evidence/sql_ingest.py   SQL -> observations   (isolated in-memory SQLite)
evidence/json_ingest.py  JSON -> observations  (4 layouts, detected by content)
evidence/csv_ingest.py   system_activity.csv -> CLAIM observations
evidence/ingest.py       dispatcher: ingest_dataset() -> IngestionResult
code/inspect_evidence.py read-only coverage CLI
```

## Observation schema (what later stages get)

| Field | Meaning |
|---|---|
| `obs_id` | deterministic: `<file_id>:<ordinal>` (activity rows: the `activity_id`) |
| `kind` | `record` (row/document in a snapshot), `lookup_result` (explicit FOUND / NOT_FOUND / 404 / query result), `claim` (activity event), `unrecognized` (kept, layout not understood) |
| `provenance` | `citable_id` (what a step may cite), `file_id`, manifest `file_path`, `origin`, `source_format`, `locator`, `ordinal`, manifest `file_captured_at`, in-file `file_content_time` |
| `system_id`, `resource_id` | as stated by the source (activity rows: `target_system`) |
| `record_type` + `record_type_source` | `source` when the record states it (ledgers), else `derived_from_layout` (static map in `schema_maps.py`) |
| `collection`, `store`, `store_role`, `replica_name` | which collection/table; `primary` vs `replica` (+ replica name) so drift stays visible |
| `state_field` / `state_value` | the source's own state/flag field and its **verbatim** value (`1`, `True`, `ACTIVE`, `404`, `NOT_FOUND`); never normalised |
| `record_observed_at` | the record's **own** observation/recording time (`observed_at`, `recorded_at`, activity `event_time`) |
| `snapshot_captured_at` | capture time of the enclosing snapshot (SQL header / `snapshot_scope`, bundle snapshot, single-collection file) |
| `record_updated_at` | `updated_at` / `indexed_at`: when the record was last *written* - **never** used as an observation time |
| `identifiers` | labelled items `(kind, value, path, free_text)` + `redacted_paths`; case preserved, `emails_normalized` helper |
| `fields` | the original record/row (NULLs kept as `None`) - treat as read-only |
| `flags` | e.g. `unverified_claim`, `record_time_after_file_capture`, `snapshot_time_missing`, `updated_after_snapshot`, `unrecognized` |

`Observation.effective_time()` returns `(value, source)` using the order
**record's own time > snapshot capture > time stated in the file > manifest capture**, and always
names the source (`record_observed` / `event_time` / `snapshot_captured` / `file_exported` /
`manifest_captured` / `none`). A finer time is never replaced by a coarser one, and a fallback to a
coarser one is labelled and warned about. In the real data no observation needs the manifest fallback.

`SnapshotScope` records what a source says it covered (per SQL table, per inventory `snapshot_scope`
system, per bundle snapshot, per service-export section) with its record count - including **zero**.
That is the raw material for "is absence meaningful here?"; Stage 1A itself never infers deletion from absence.

## Coverage semantics

* `containers` = SQL tables / JSON snapshots / service sections / the ledger; `records` = source-native rows.
* Inventory `snapshot_scope` rows count as records but become `SnapshotScope`s, not observations
  (`records_seen = observations + scope rows`). A search query with N hits is 1 record, N observations.
* Nothing is dropped silently: unrecognised rows/records/files stay as `unrecognized` observations
  with a structured warning (`code`, message, file, locator, level).

Warning codes: `SQL_STATEMENT_ERROR`, `SQL_NO_TABLES`, `SQL_UNKNOWN_TABLE`, `SQL_RECORD_JSON_INVALID`,
`SQL_SNAPSHOT_TIME_MISSING`, `SQL_CAPTURE_TIME_DISAGREES_WITH_MANIFEST`, `RECORD_UPDATED_AFTER_SNAPSHOT`,
`JSON_INVALID`, `JSON_UNKNOWN_LAYOUT`, `JSON_SNAPSHOT_MALFORMED`, `JSON_SECTION_MALFORMED`,
`JSON_RECORD_NOT_OBJECT`, `UNKNOWN_COLLECTION`, `UNKNOWN_SECTION`, `DATA_STORE_MISMATCH`,
`SYSTEM_MISMATCH`, `RESOURCE_ID_MISMATCH`, `RESOURCE_ID_MISSING`, `LEDGER_ROW_INCOMPLETE`,
`RECORD_COUNT_MISMATCH`, `RECORD_TIMESTAMP_MISSING`, `TIMESTAMP_UNPARSEABLE`, `FILE_TIME_MISSING`,
`SNAPSHOT_CAPTURED_AT_MISSING`, `RECORD_TIMESTAMP_AFTER_FILE_CAPTURE`, `CSV_COLUMNS`, `CSV_ROW_WIDTH`,
`ACTIVITY_DUPLICATE_ID`, `MANIFEST_*`, `FILE_UNREADABLE`, and `FORMAT_DEFERRED` (info).

## Run (Windows PowerShell, from the repository root)

```powershell
python -m unittest discover -s code/tests -t code -v          # Stage 0 + Stage 1A tests
python code/inspect_evidence.py                                # per-file counts, coverage, warnings
python code/inspect_evidence.py --format sql --no-activity     # only SQL files
python code/inspect_evidence.py --file evidence_05 --dump 3    # first 3 observations of one file
python code/inspect_evidence.py --json > coverage.json         # machine-readable
python code/inspect_evidence.py --strict                       # exit 1 on failed/partial/unrecognized
```

(Use `py -3` if `python` is not on PATH. Do not name a script or module `code.py`: it shadows Python's stdlib
`code` module; run unittest via `discover`, not `python -m unittest code.tests...`.)

## Design notes and known limitations

* **No CSV evidence files exist** under `dataset/evidence/`. CSV input = the manifest and `system_activity.csv`
  (claims only). `user_audit_log.csv` is identity history and is left to the identity stage.
* **SQL safety**: scripts run statement-by-statement in `:memory:` with `isolation_level=None`; an authorizer
  denies `ATTACH`/`DETACH`, virtual tables and any `PRAGMA` except `foreign_keys`. A failing statement is reported
  with its line and later statements still run. The real files contain only BEGIN/COMMIT, PRAGMA foreign_keys,
  CREATE TABLE/INDEX and INSERT, so UPDATE/DELETE semantics are exercised only by synthetic tests, not real data.
* **Layouts are detected by content**, not file name (`connector_configurations_20260812.json` is a lookup ledger).
* **Bundle snapshots carry their own `captured_at`**, which is often earlier than the file's manifest time; two ledger
  records are *later* than their file's manifest time (warned, kept). Whether eligibility for an `audit_at` is judged
  per file (manifest) or per snapshot/record is a Stage 2 decision; both are preserved.
* `record_type` for layouts that do not state it comes from a static map; the vocabulary is checked by tests against the
  ledgers' own `record_type` values and `deletion_rules.csv`. `SUPPORT_MESSAGE` vs `SUPPORT_ATTACHMENT` for `support_*`
  resources is only known where the collection says so.
* Activity `system_id` is the row's `target_system` (e.g. `archive_service` for `audit_record_*`), which is **not** always the
  `system_id` used in answers. Mapping belongs to the policy stage.
* Identifier extraction is shape-based and conservative; phone numbers are not normalised; historical identifiers are not
  resolved; names are collected (tombstone policy needs them) but never matched.
* Verified on Linux with Python 3.12.3 only; `vermin` reports 3.7 as the minimum for the code.
