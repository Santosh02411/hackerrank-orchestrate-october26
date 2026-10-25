# Stage 1A - structured evidence ingestion (SQL, JSON, CSV)

Turns the supplied SQL snapshots, JSON exports and `system_activity.csv` into typed,
provenance-carrying `Observation` objects. It **does not** resolve identities, apply the
deletion policy, decide whether anything is deleted, plan remediation or write predictions.
By default (Stage 1A behaviour) logs, PDFs, images and the TXT handover record are reported as `deferred`.
Logs and the TXT record can be parsed with `formats=EXTENDED_FORMATS` (Stage 1B, below); PDFs and screenshots
additionally with `formats=FULL_FORMATS` (Stage 1C, below; needs `pypdf`, Pillow and Tesseract).

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


---

# Stage 1B - logs and the plain-text handover record (opt-in)

"Stage 1B" is a label from this project's own plan, not from the challenge documents. It means: ingest the
formats Stage 1A reported as `FORMAT_DEFERRED` that need no new tooling decision, using the same `Observation`
model. **Opt-in, so Stage 1A results are byte-for-byte unchanged by default:**

```python
from ghost_audit.evidence import ingest_dataset, EXTENDED_FORMATS
result = ingest_dataset(dataset_dir, formats=EXTENDED_FORMATS)   # default (formats=None) = SQL + JSON
```
```powershell
python code/inspect_evidence.py --formats sql,json,log,text --strict   # Stage 1B only: needs no extra dependency
```

| Part | Module | What it does |
|---|---|---|
| 26 logs | `log_ingest.py` | 7 line grammars (`json_lines`, `syslog_rfc5424`, `bracketed`, `pipe_delimited`, `cloud_runtime`, `key_value`, `key_value_bare_level`), detected per line. Event roles come from `schema_maps.LOG_EVENT_SPECS`. |
| 1 TXT | `text_ingest.py` | `- <ts> \| system \| resource \| record_type \| result \| subject` rows through the same builder as the flat JSON ledgers. |

Behaviour that matters downstream:

* **Every non-blank line is accounted for.** `fact` events and `record_lookup` rows become `lookup_result`
  observations; `*_started` events become trace context; infrastructure chatter is counted in `metadata`;
  an unparseable line or an unregistered event from a platform service is kept as an `unrecognized`
  observation with a warning (`LOG_LINE_UNPARSEABLE`, `LOG_EVENT_UNKNOWN`).
* **Time is the line's own timestamp** (`record_observed_at`); no `snapshot_captured_at` is invented. Lines that
  post-date the manifest capture time keep their time and raise the existing `RECORD_TIMESTAMP_AFTER_FILE_CAPTURE`
  (none do in the supplied logs, so the two warnings that exist are still the two JSON ledger records).
* **Trace correlation is per file and per trace id.** The latest earlier `*_started` event of the same trace is
  attached as `fields["trace_context"]` (flag `trace_context`) and its keys (`lookup_key`, `subject_key`, ...)
  become identifiers with the path `trace_context.<key>`. A trace slot that merely repeats the emitting
  `instance` (`collector-3`, `resolver-3`) is not a trace id. A start with no later fact is kept
  (flag `lookup_started_without_completion`, info warning `LOG_TRACE_INCOMPLETE`); **nothing is inferred from it**
  (the supplied logs contain none).
* **Completeness is recorded, not assumed.** One `LOG_EXPORT` scope per log holds the declared
  `expected_source_events`/`source_events`, the parsed platform-event count, `dropped`, `queries`/`target_count`, `mode`
  and the first/last event time. Disagreements raise `LOG_EVENT_COUNT_MISMATCH`, `LOG_EVENTS_DROPPED`,
  `LOG_QUERY_COUNT_MISMATCH`, `LOG_METADATA_CONFLICT`, `LOG_METADATA_MALFORMED`. In the supplied data all 11 logs that
  declare a count match exactly and `dropped` is 0.
* **Values stay verbatim strings** (`"404"`, `"true"`); use `flag_value()` to read booleans. The log spelling of a
  missing value, the string `null`, is kept in `fields` but is not an identifier. `[REDACTED]` markers are recorded in
  `identifiers.redacted_paths`. Values shaped like `analytics_4800` (a lookup by resource) get the identifier kind `resource_ref`.
* `system_id` is the log's `service` verbatim (`profile_lookup_completed` is emitted by both `account_service` and
  `profile_service`; mapping to an answer's `system_id` is a later decision).
* The new readers refuse a manifest `file_path` that resolves outside the dataset directory (`FILE_UNREADABLE`).
  The Stage 1A SQL/JSON readers do not yet have this guard.

New warning codes: `LOG_LINE_UNPARSEABLE`, `LOG_EVENT_UNKNOWN`, `LOG_TRACE_INCOMPLETE` (info), `LOG_EVENT_COUNT_MISMATCH`,
`LOG_EVENTS_DROPPED`, `LOG_QUERY_COUNT_MISMATCH`, `LOG_METADATA_CONFLICT`, `LOG_METADATA_MALFORMED`, `LOG_EMPTY`,
`LOG_NO_RECOGNIZED_LINES`, `TXT_ROW_MALFORMED`, `TXT_SNAPSHOT_MISSING`, `TXT_NO_ROWS`.

Measured on the supplied evidence (`--formats sql,json,log,text`): 80 of 95 files parsed, 15 deferred (PDFs and images),
6,905 observations (1,781 SQL/JSON + 1,113 log/TXT + 4,011 activity claims), 427 scopes, 8,122 records seen, 0 unrecognized.

---

# Stage 1C - PDFs and screenshots (opt-in, offline)

```powershell
pip install pypdf Pillow
# Tesseract 5.x (needed for screenshots and scanned PDF pages). Windows installer:
#   https://github.com/UB-Mannheim/tesseract/wiki   then add its folder to PATH, or:
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
python code/inspect_evidence.py --extended --strict     # = formats sql,json,log,text,pdf,image
```
```python
from ghost_audit.evidence import ingest_dataset, FULL_FORMATS
result = ingest_dataset(dataset_dir, formats=FULL_FORMATS)
```
No model or network call is made at any point. A requested format whose tool is missing is reported as a **FAILED** file with
`DEPENDENCY_MISSING` and the install instruction (so `--strict` fails); it is never skipped silently. `--extended` therefore needs
the three dependencies; use `--formats sql,json,log,text` without them.

| Part | Module | How |
|---|---|---|
| 4 PDFs | `pdf_ingest.py` | text layer via `pypdf` (layout mode). All four supplied PDFs have one. Pages with no text layer but an embedded picture are OCR'd; pages with neither are reported. |
| 11 PNGs | `image_ingest.py`, `ocr.py` | Tesseract CLI, **two independent passes** (`psm 11` and `psm 6`, both 2x upscaled with Pillow), words regrouped into visual rows/cells. |
| both | `document_rows.py` | shared row/cell model, identifier anchors, uncertainty labelling. |

* **Row model.** A row is a PDF text line (cells split on 2+ spaces) or an OCR visual row (cells split at wide gaps, with boxes and word
  confidences). A row becomes an `Observation` (kind `record`, collection `pdf_row` / `screenshot_row`, locator `page=N;row=M`) only if it
  holds an e-mail, user id, resource ref (`backup_9287`), phone, e-mail hash, or a malformed identifier-like token. Every other row is kept
  verbatim in `metadata["unanchored_rows"]`; `rows == anchored + unanchored`, nothing is dropped.
* **Identifiers are read, never repaired.** Each carries the OCR word confidence. It is `uncertain` when the confidence is below 70 or the
  second pass did not reproduce it exactly; the row is flagged `ocr_uncertain_identifier` and the file gets `OCR_UNCERTAIN_IDENTIFIER`.
  Identifiers seen only by the second pass are listed in `metadata["extraction"]["identifiers_only_in_second_pass"]` and are not observations.
  Tokens such as `data_flow.1121` stay verbatim in `fields["malformed_identifier_tokens"]` (`OCR_MALFORMED_IDENTIFIER`). No snapping to
  known identifiers happens here; that is identity resolution.
* **Time.** Documents carry no machine-readable observation time, so the effective time is the manifest capture time, labelled
  `manifest_captured` (info `DOCUMENT_TIME_UNSTRUCTURED`). PDF generator metadata is recorded but never used. Times such as `10:24 UTC` are
  printed in the supplied PDFs as two cells (`... 10` | `24 UTC`, the colon was the generator's key/value separator); both cells are kept,
  the row is flagged `time_split_across_cells`, and the time is **not** reconstructed.
* **Rows spanning unrelated panels** (cells separated by more than 12% of the image width) are flagged `multi_region_row`; use the cell boxes in
  `fields["cells"]` before associating a resource with an e-mail on such a row.
* **Diagnostics** (`metadata["extraction"]`, also the `DOCUMENT` scope's `extra`): backend and version, passes with word counts, mean confidence and
  words below threshold, upscale applied, row counts, uncertain counts.
* **Safety.** PDFs are never executed; paths must stay inside the dataset; files over 50 MB (PDF) / 25 MB (image) or 200 pages are refused or
  truncated with a warning; the image must start with a PNG/JPEG signature; Tesseract runs with `shell=False`, an argument vector, an absolute
  path, a timeout and a name check on the executable (`tesseract[.exe]` from `$TESSERACT_CMD`, `PATH` or the standard Windows folders); upscaled
  copies exist only in a private temporary directory; Pillow's global limits are never modified.

New warning codes: `DEPENDENCY_MISSING`, `FILE_TOO_LARGE`, `PDF_NOT_A_PDF`, `PDF_UNREADABLE`, `PDF_ENCRYPTED`, `PDF_NO_TEXT`, `PDF_PAGE_NO_TEXT`,
`PDF_PAGE_UNREADABLE`, `PDF_PAGE_LIMIT`, `PDF_PAGE_IMAGE_UNREADABLE`, `PDF_READER_MESSAGES` (info), `IMAGE_UNSUPPORTED_FORMAT`, `OCR_FAILED`, `OCR_NO_TEXT`,
`OCR_UPSCALE_UNAVAILABLE`, `OCR_UNCERTAIN_IDENTIFIER`, `OCR_MALFORMED_IDENTIFIER`, `OCR_PASS_DISAGREEMENT` (info), `DOCUMENT_TIME_UNSTRUCTURED` (info).

Measured on the supplied evidence (Tesseract 5.3.4 / pypdf 5.9.0, Linux): all 95 files parse; 14 PDF observations; 44 screenshot observations
from 70 OCR identifiers, 7 of them flagged uncertain (6 low confidence, 1 not reproduced by the second pass); 6,963 observations, 442 scopes,
8,565 records, 0 unrecognized; a full OCR run takes about 36 s on one core. OCR-derived counts can differ with another Tesseract build, so the
tests pin only the PDF counts and invariants.

Known limits: scanned-PDF OCR is covered by synthetic tests only (no supplied PDF is a scan); screenshot cells are positional, so associating a
resource with an e-mail across panels needs the boxes; `system_id` and `record_type` of document rows are empty (a later stage decides them from
the identifiers); synthetic OCR fixtures drop underscores in some fonts, which is why tests avoid asserting on them.
