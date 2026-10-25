# Ghost Audit Evidence Explorer

A **read-only, offline** investigation page for the deletion-audit engine. It shows what the engine decided for each case and the recorded
evidence behind that decision. It never makes a decision of its own: it is a view of results the existing pipeline already produces
(`ghost_audit.engine` decisions, link methods, assessments, notes, provenance and the corpus' own eligibility rule).

## Launch

```bash
python code/build_explorer.py                 # writes explorer/ghost-audit-explorer.html (about 4 MB, ~1-2 minutes: it parses every PDF/screenshot)
# then simply open that file in a browser (double-click). No server, network or framework is needed.

python code/build_explorer.py --serve         # optional: build, then serve it at http://127.0.0.1:8765/ghost-audit-explorer.html
python code/build_explorer.py --run-tests     # optional: run the full test suite first (2-3 min) and record the REAL result in evaluation/test_results.json
python code/build_explorer.py --cache /tmp/ev.pkl   # developer convenience: reuse parsed evidence; never changes results
```

Requirements are the same as the engine (`pip install -r requirements.txt` plus Tesseract for screenshots). Playwright is **not** required;
it is only used by an optional browser smoke test (`pip install playwright && playwright install chromium`).

The built page embeds records derived from the dataset, so it is written to `explorer/` (git-ignored) and is deliberately **not** part of `code.zip`
(`code/package_submission.py` rejects any archive that contains one). The unfilled template and the Python that builds it are in `code.zip`.

## What you see

| Tab | Contents |
|---|---|
| **Cases** | Summary metric cards (click one to filter), search (case, e-mail, user, resource, evidence id), status and evidence-flag filters, sort, and a case detail with five views: Overview, Steps, Evidence lineage, Timeline, Integrity. Dataset overview charts sit below. |
| **Integrity** | Whether `output.csv` matches the decisions the engine produces *in this environment*; counts of cases touched by each integrity category; records cited for more than one person. |
| **Evaluation** | Public-sample metrics (clearly labelled as a development set), the omitted reference steps, the recorded regression-test result, participant-written cases, the limitations from the evaluation report (verbatim) and the model-usage report. |
| **How it works** | The pipeline, the engine's own definition of each link method, the evidence-state legend and a 3-minute walkthrough. |

The header toggle switches between the **518 evaluation cases** (no ground truth exists) and the **32 public samples** (a development set whose reference answers
give each sample a *Reference check* tab).

## Where every thing on screen comes from

| On screen | Source (nothing is computed from scratch) |
|---|---|
| Status, steps, evidence ids | `CaseDecision.status` / `.steps`, exactly as written to `output.csv` |
| Identity ("resolved via historical e-mail", held e-mails) | `Resolution`, `IdentitySet` as of `audit_at` |
| Link method and its explanation | `LinkedResource.methods`; the sentence is the definition from `engine/linking.py`; the listed items are the observations/claims that carry it |
| Record verdict and reason, rule id | `Assessment` (`assess_resource`) |
| Eligible / excluded-after-`audit_at` / excluded-before-request | the same time rule as `Corpus.eligible` (a test asserts they never disagree) |
| Observation card (file, locator, state field and value, time and its source, identifiers, OCR confidence) | `Observation` and `Provenance`, verbatim |
| Ambiguous link, "N candidates" | the engine's own note `claim_window ambiguous for <prefix>*: N candidates` |
| Missing evidence | a linked record with no eligible observation |
| Absence proof | `Assessment.proof_id` (the full account snapshot in which a claim-named record does not appear) |
| Integrity panel | existing assessments (data flows, backups, tombstones, retained audit/legal records), `LinkedResource.conflict`, OCR-uncertain identifiers, identifier-less observations |
| Sample metrics | `evaluate()` on the sample answers, recomputed at build time |
| Regression tests | `evaluation/test_results.json`, written only by a real run of the suite (`--run-tests`); empty state if absent |
| Limitations, model usage | parsed from `evaluation_report.md` / `usage_report.md` |

No confidence score is shown except the OCR word confidence the OCR engine itself reported. Nothing is estimated or invented, and no model or API is used.

## Reading the symbols

Meaning never depends on colour alone: each state has its own **shape and text label**. Filled circle = eligible evidence; diamond (shaded zone right of the dashed
`audit_at` line) = captured after the cutoff and ignored; hollow square = before the request; triangle = workflow claim (a claim, not state); dashed ring = ambiguous
link left unattributed; cross = missing evidence.

## A 3-minute walkthrough (for judges)

1. **Evaluation tab.** Read the banner first: the 32 samples are a *development set* and the 518 cases have *no ground truth*, so no accuracy is claimed for them.
2. **Cases tab.** Click the card *cases with evidence after audit_at*. These are cases where later-captured files were excluded rather than used.
3. Open **case_376** (a *featured* case, picked by a generic score of how many recorded behaviours it shows), then **Evidence lineage**: the request used a *historical* e-mail
   (resolved to `user_374`). Its account record `account_5454` is linked only by a **weak** time-window claim (`activity_1110`) and is proven absent by the snapshot `evidence_69`;
   the page says so and shows that no observation of the record itself exists.
4. **Timeline** on the same case: `evidence_70` (used) sits left of the dashed `audit_at` line; `evidence_35` was captured after it and is drawn in the shaded zone, not used.
   The ambiguous analytics candidates appear as a dashed ring.
5. Open **case_45** (COMPLETE): retained audit records read from a **screenshot** (`evidence_37`); each shows the OCR confidence and which identifier matched. This is also the one case whose result can differ between machines (OCR readings sit close to the confidence cutoff), so it is the case the Integrity tab flags if `output.csv` was produced elsewhere.
6. Open **Integrity**: the submission file is compared with the engine (one case may differ because OCR readings vary between machines), and records cited for two people are listed, not hidden.
7. Switch to **Samples**, open **case_21**, tab *Reference check*: the omitted `account_6440` step is explained from recorded facts only (no link method exists; 6 candidate records matched the window).

## Limitations (honest)

* It shows **this environment's** run. OCR-dependent details can differ on another machine; the Integrity tab reports when `output.csv` differs from the engine here.
* The 518-case view contains no accuracy figure because none can be computed. The sample figures are an upper bound (the engine was developed while studying those cases).
* Link explanations are the engine's recorded methods; the explorer does not add any reasoning beyond them. Where a link is weak or ambiguous it says so.
* The timeline places an ambiguous-link marker at `reported_at` purely to show that it exists; it carries no evidence time.
* Tested in headless **Chromium** (desktop and 390 px phone width). Firefox, Safari and screen-reader behaviour were **not** tested.
* The payload is about 4 MB for 550 cases; a very old browser or a low-memory phone may be slow to open it.
