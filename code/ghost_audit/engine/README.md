# Stage 2 - the deletion-audit decision engine

`python code/main.py` turns the 518 requests into `output.csv`. Everything is deterministic and offline.

```
request_text ──► applicability ──► identity ──► corpus (eligible evidence) ──► linking ──► assess ──► decide ──► writer
 (en es pt fr    authorizes        email → one   [requested_at, audit_at]       who owns    state +    status +    output.csv
  ja ko)         deletion?         user_id +     files and claims               each        rule →     ordered     + validator
                                   identifiers   (Stage 1 parsers, incl. OCR)   record?     verdict    steps
```

| Module | Role |
|---|---|
| `applicability.py` | Multilingual rules with negation masking: access, correction, export, login, marketing-only and "do not delete" requests are NOT_APPLICABLE; "please verify my account was deleted" is a deletion audit and is in scope. |
| `identity.py` | Request e-mail (current or historical) -> exactly one user, else `ambiguous`/`unresolved`; identifiers as of `audit_at` (later changes not applied; hashes derived from every held address; phone digits). Names only corroborate. |
| `corpus.py` | All parsed observations, indexed. **Eligibility**: file `captured_at` in `[requested_at, audit_at]` (inclusive) and record time `<= audit_at`; claims by `event_time`. 75/75 public-sample citations satisfy this. Also lists full account snapshots. |
| `linking.py` | Links records to the subject: `identifier`, `trace` (lookup key), `document` (PDF concerning only the subject), `catalog` (`LINK_RESOURCE_IDENTITY` naming only the subject), weak `claim_window` (single claim candidate within +-2 h, not tied to anyone else). OCR identifiers flagged uncertain never link. Records carrying another known user's identifiers are dropped as conflicts. |
| `assess.py` | Per-record state at `audit_at` and the verdict (`violation`, `compliant`, `retained`, `unknown`). State comes from the most recent eligible file, OR-ed across its stores so a ghost row in a replica still counts. |
| `policy.py` | `deletion_rules.csv` as data; resource-prefix conventions; action -> operations. |
| `decide.py` | Status policy and ordered steps (contract order; duplicates collapsed). |
| `writer.py`, `evaluate.py` | `output.csv` serialisation; status / step / field / sequence metrics. |

## Rules applied

| Category (rule) | Violation when | Finding / remediation / verification |
|---|---|---|
| `USER_PROFILE` (01) | a row exists in any store/replica, or a lookup returns 200/FOUND | `REPORT_REMAINING_RECORD` / `DELETE_RECORD` / `VERIFY_RECORD_ABSENT` |
| `SEARCH_INDEX_ENTRY` (03), `USER_EXPORT` (09), `MARKETING_PROFILE` (10), `SUPPORT_ATTACHMENT` (06) | the record exists (also a document printing its catalog alias; a replica copy with no deletion marker) | same as above |
| `ANALYTICS_PROFILE` (07) | still attributable: identifiers present, `IDENTIFIABLE`, `direct_identifiers>0` | `REPORT_EXPOSED_PII` / `ANONYMIZE_RECORD` / `VERIFY_RECORD_ANONYMIZED` |
| `SUPPORT_MESSAGE` (05) | name/e-mail/phone remain | `REPORT_EXPOSED_PII` / `REDACT_RECORD` / `VERIFY_RECORD_REDACTED` |
| `ACCOUNT_TOMBSTONE` (15) | anything but the stable `user_id` remains | same as above |
| `BACKUP_ARCHIVE` (14) | archive is retained; a restore path is open (`restore_allowed`, eligible without deletion block, `ACTIVE`) | `REPORT_RESTORE_RISK` / `BLOCK_RESTORE` / `VERIFY_RESTORE_BLOCKED` |
| data flows (no rule row) | enabled/active/continuous | `REPORT_ACTIVE_DATA_FLOW` / `DISABLE_DATA_FLOW` / `VERIFY_DATA_FLOW_DISABLED` |
| `SECURITY_AUDIT_LOG` (12), `LEGAL_HOLD_RECORD` (13) | never; retained while the retention/hold is in force | `VERIFY_RECORD_PRESENT` |

**Status.** `NOT_APPLICABLE` + `[]` if deletion is not authorized. `INCOMPLETE` if any violation is supported: findings cite their evidence; remediation and the matching verifications (plus "account stays absent" and retained records present) have an empty `evidence_id`. `COMPLETE` only if no violation is supported and at least one required final state is proven by cited evidence (each verification cites the proof). A case that is neither fails the output validator on purpose instead of being guessed.

## Assumptions and limitations

* **Claims are not state.** `system_activity.csv` rows, `reported_status` and `reported_result` never decide a state; they can only name a resource (weakly) for the account/analytics profile.
* **Later files are not used, even to learn a record exists.** Some retained audit records appear only in files captured after `audit_at`, so those `VERIFY_RECORD_PRESENT` steps are omitted.
* **Claim-only accounts** are named only when exactly one candidate exists (measured: 10 of 32 on the samples); otherwise the account verification is omitted rather than guessed.
* **`cache_*` / `email_delivery_*`** resources exist only in the activity stream and cannot be judged.
* **Screenshots**: positive evidence only; a listed backup archive is reported as a restore risk (`INFERRED`, no restore flag is shown); when a catalog link and a screenshot show different identities the mismatch is flagged and the catalog link kept.
* **Unverified system ids**: `legal_service`, `marketing_platform`, `object_storage` come from the evidence/catalog, not from a sample answer.
* **Sort order** of rows and resources is plain string order by default (`--case-order`, `--resource-order` switch it).
* The 32 public samples were studied while building the engine; see `evaluation/evaluation_report.md` for what that does and does not show.
