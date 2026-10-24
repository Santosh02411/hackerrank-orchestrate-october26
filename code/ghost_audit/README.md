# Stage 0 - output contract and validator

Scope: the *shape* of `output.csv`. There is no evidence parsing, identity
resolution or prediction logic in this stage.

```
code/
  ghost_audit/contracts.py   constants transcribed from the repository (statuses, phases,
                             15 operation/state pairs in table order, step keys, evidence rules)
  ghost_audit/ordering.py    SortStrategy: lexical | natural | either | none
  ghost_audit/validator.py   validate_csv / validate_rows / validate_steps_json
  validate_output.py         command-line wrapper
  tests/test_output_contract.py
```

The repository's starter files `code/main.py` and `code/evaluation/main.py` (both
empty) are untouched. Requires only the standard library. Static analysis
(`vermin`) reports Python 3.7 as the minimum; the repository itself names no
version, and the tests were executed on 3.12.3 only.

## Run (Windows PowerShell, from the repository root)

```powershell
# tests (unittest, no pip install needed)
python -m unittest discover -s code/tests -t code -v

# validate the public sample
python code/validate_output.py dataset/sample_output.csv --requests dataset/sample_deletion_requests.csv

# validate the final submission file (also checks it covers exactly the 518 requests)
python code/validate_output.py output.csv --requests dataset/deletion_requests.csv

# pin a sort strategy once you have decided
python code/validate_output.py output.csv --requests dataset/deletion_requests.csv --case-order natural --resource-order natural
```

If `python` is not on PATH use `py -3`. Exit codes: `0` no errors, `1` validation
errors (also for an unreadable/malformed output file), `2` bad command-line
input (e.g. unreadable `--requests`). Other flags: `--pairing off|warning|error`,
`--evidence-id-pattern REGEX|none`, `--expect-rows N`, `--max-issues N`,
`--fail-on-warning`.

Output shape on success:

```
Validating: <path>
Rows: <n> | Distinct cases: <n>
Ordering (case_id): <which sort strategies the file satisfies>
Ordering (resource_id): <...>
Result: PASS - 0 errors, 0 warnings, 0 notices
```

Each issue prints as `[SEVERITY] RULE_CODE (case_id=..., step N, line N): message`;
`step` is the 1-based position in the array and `line` the line in the CSV.

## What is checked now (implemented)

| Area | Rule codes | Source of the rule |
|---|---|---|
| File / CSV: exact header, 3 fields per row, UTF-8 without BOM, no blank rows | `FILE_*`, `CSV_*` | README "Output" |
| Case rows: unique non-blank IDs, valid status, exact expected case set and row count (when `--requests`/`--expect-rows`), sorted | `CASE_ID_*`, `ROW_COUNT`, `STATUS_INVALID`, `CASE_ORDER` | problem_statement "Required Output" |
| `steps_json`: valid JSON array, no duplicate keys, no `NaN` | `JSON_*` | problem_statement ("grader parses steps_json") |
| Step schema: exactly the 7 keys; `step_no` is a real integer; other fields strings | `STEP_NOT_OBJECT`, `STEP_KEYS`, `STEP_FIELD_*` | problem_statement "Required Output" |
| `step_no` = 1..n in array order | `STEP_NO_SEQUENCE` | problem_statement ("start at 1 and increase consecutively") |
| phase / operation / state valid and mutually consistent | `STEP_PHASE_INVALID`, `STEP_OPERATION_INVALID`, `STEP_STATE_INVALID`, `STEP_COMBINATION` | "Allowed Operations" table |
| Order: phase, then operation (table order), then system_id, then resource_id | `STEP_ORDER_PHASE`, `STEP_ORDER_OPERATION`, `STEP_ORDER_ID` | problem_statement "Rules" |
| `NOT_APPLICABLE` -> `[]`; `COMPLETE` -> non-empty, VERIFICATION only; `INCOMPLETE` -> all three phases | `STATUS_*` | problem_statement "Required Output" |
| `evidence_id`: COMPLETE verification and INCOMPLETE findings must cite; INCOMPLETE remediation and verification must be `""` | `EVIDENCE_REQUIRED`, `EVIDENCE_MUST_BE_EMPTY`, `EVIDENCE_FORMAT` | problem_statement "Rules"; AGENTS 6.3/6.6 |
| INCOMPLETE: every remediation has a VERIFICATION step on the same system_id/resource_id with the same state | `REL_VERIFY_MISSING` (error) | AGENTS 6.5 "Verification must cover the required final state for each remediated record or process" |
| INCOMPLETE: finding <-> remediation pairing (REMAINING->DELETE, EXPOSED_PII->REDACT/ANONYMIZE, ACTIVE_DATA_FLOW->DISABLE, RESTORE_RISK->BLOCK) | `REL_FINDING_UNREMEDIATED`, `REL_REMEDIATION_UNEXPLAINED` (warning by default) | implied by the "Meaning" column and true for all 22 INCOMPLETE sample rows, but not stated as a rule |
| Duplicate steps | `STEP_DUPLICATE` (warning) | contract is silent |

## What is NOT checked (needs evidence-aware validation, later stages)

* that a cited `evidence_id` exists in `evidence_files.csv` / `system_activity.csv` / `user_audit_log.csv` (only its *shape* is checked)
* that cited evidence was captured at or before the case's `audit_at`
* that the cited evidence actually shows the claimed state
* that `system_id` matches the `resource_id` prefix / data category
* that a resource belongs to the requester (current or historical identity)
* that `deletion_status` is correct, that findings are complete, that retained records are retained
* that `deletion_requests.csv` rows classified non-deletion really are `NOT_APPLICABLE`

## Sorting (explicitly configurable)

`--case-order` / `--resource-order` (API: `ValidatorConfig.case_id_order`,
`resource_order`) take `lexical`, `natural`, `either`, `none`.

**Default: `either`.** The repository says "sorted by case_id" and "ascending"
but not whether `case_100` precedes `case_33` (lexical) or follows it (natural).
The 518 request IDs are `case_33`..`case_550`, so the two orders really differ
for the final file. The 32 public samples cannot decide it (their IDs are
zero-padded and none of their multi-item groups differs between the orders;
`tests` asserts the validator reports "does not discriminate" on them). With
`either` the validator accepts a file that is wholly lexical *or* wholly
natural (each axis checked file-wide, never mixed within an axis), rejects a
file that is neither, and reports which one it satisfied (`Ordering (...)` line
and an `ORDER_AMBIGUITY` notice). Pin one strategy before submitting.
`system_id` is compared with the same strategy as `resource_id`.

## Ambiguities left open (not invented)

1. lexical vs natural order for `case_id` and `resource_id` (above).
2. Whether `COMPLETE` with `[]` is allowed. Rejected here because the contract says COMPLETE must "include ... verification steps proving the current state"; not stated as a prohibition.
3. Whether duplicate steps are allowed (warning only).
4. The evidence-ID *shape* `(evidence|activity|audit)_<digits>` comes from the dataset's three ID columns, not from the Markdown; it can be changed or disabled.
5. Whether INCOMPLETE verification must also cover already-compliant resources. The samples add only the account (absent) and the retained audit record (present), but no rule says so, so nothing is enforced.
6. Whether a finding must always be paired with a remediation (and vice versa): implied, warning by default (`--pairing error` to enforce).
7. Whether `README`'s `code/evaluation/` or the other docs' `evaluation/` is the report location (not a Stage 0 concern; recorded for later).
