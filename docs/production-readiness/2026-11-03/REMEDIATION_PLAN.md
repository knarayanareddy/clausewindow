# clausewindow — remediation plan

This is proposed future work, not a record of fixes or passing tests. Findings F01–F07 are defined in the [review](REVIEW.md). Use synthetic contracts until access, privacy and legal review are approved. No commands below were executed in this review.

## Phases and dependencies

| Phase | Entry and exit criteria | Tasks |
|---|---|---|
| 0 — Baseline | Entry: pinned prototype and owner scope. Exit: clean installation, real entry point and truthful CI status reproduced. | T01 |
| 1 — Legal correctness | Entry: T01 and lawyer-approved synthetic corpus. Exit: extraction gaps disclosed and independent evaluations recorded. | T02 |
| 2 — Confidentiality and integrity | Entry: T01 and chosen trust boundary; T02 informs privacy-safe outputs. Exit: authorization, signing and upload controls tested. | T03 |
| 3 — Operations and usability | Entry: T01–T03 and approved deployment/recovery objectives. Exit: observed restore, usable console and accountable release evidence. | T04 |
| 4 — Independent acceptance | Entry: T01–T04 evidence and owner approvals. Exit: negative controls and sign-off independently reviewed. | T05 |

T01 → T02; T01 + owner architecture → T03; T02 + T03 → T04; T01–T04 → T05. T03 may start alongside T02 after the trust boundary is chosen; production acceptance waits for both.

### T01 — Reproduce onboarding and establish a real gate (F01, F02, F06)
**Prerequisites:** approved isolated environment. **Observed paths:** `README.md`, `pyproject.toml`, `clausewindow/api.py`, `tests/`; **proposed:** `.github/workflows/ci.yml` and any new test files.
1. In an isolated environment, reproduce the documented missing-file commands; determine whether the API app or a new supported CLI is the intended entry point.
2. Replace onboarding with verified invocation and decide whether YAML is supported; declare its dependency if retained, or remove that promise. Test JSON, YAML and missing-dependency behavior independently.
3. Define an explicit test script or workflow, install the declared dev dependencies, run the existing tests and a synthetic API startup/review smoke test. Update or remove the badge only after confirming its target.

**Deliverable:** reproducible setup instructions, dependency decision and gate. **Verification:** repeat setup from a clean environment; break the entry point and YAML path separately and observe the relevant tests fail.
- [ ] Documented commands and clean-install formats match actual behavior.
- [ ] CI results are observed at the candidate revision, not inferred from a badge.

### T02 — Expose extraction gaps and measure legal performance (F03, F05)
**Prerequisites:** T01, lawyer-approved criteria and synthetic or properly authorized corpus. **Observed paths:** `clausewindow/pdf_engine.py`, `clausewindow/api.py`, `clausewindow/playbook_engine.py`, `fixtures/contracts/`; **proposed:** independent gold-standard cases and evaluation report.
1. Create mixed scanned/text, truly blank, malformed and oversized PDFs with independent page-level expected text; establish how gaps are surfaced and when review must stop or require manual confirmation.
2. Test long agreements, schedule contradictions and adversarial instructions against blinded lawyer-labeled findings, including false negatives and false positives; verify page/offset evidence independently of the production detector.
3. Change the extraction/response contract and wording to reflect observed coverage and limitations; retain mandatory lawyer review even for an apparently clean result.

**Deliverable:** page-level warning or fail-closed policy, evaluation corpus and qualified-reviewer report. **Verification:** remove one expected extracted page or detection and confirm the independent assertion fails; a blank-page exception must not suppress a real missing page.
- [ ] Incomplete extraction cannot be silently presented as a complete review.
- [ ] Lawyer signs criteria and observed results; claims do not promise perfect recall or injection immunity.

### T03 — Secure receipt access, resource boundaries and signing (F04, F07; preventive privacy)
**Prerequisites:** T01 and owner-selected single-user or tenant model. **Observed paths:** `clausewindow/api.py`, `clausewindow/storage.py`, `pyproject.toml`; **proposed:** authorization and adversarial API tests.
1. Map contract, findings, redlines, playbook snapshots, logs and backups; document legal basis, retention, deletion and any provider processing. Use only synthetic data during verification.
2. Apply authenticated identity and resource ownership to review/list/get routes, or document and independently test an equivalent trusted deployment boundary; bind any future sign-off to an authorized, verified lawyer rather than client-asserted fields.
3. Enforce request streaming/spooling and parser limits at appropriate layers; select signing-key custody, rotation and unsigned-legacy policy. Review dependency versions and generate a reproducible resolution and vulnerability gate.

**Deliverable:** threat/data-flow model, authorization boundary, key policy and abuse tests. **Verification:** attempt anonymous and cross-tenant reads, chunked oversized uploads, altered receipt and forged sign-off; bypass each control deliberately and confirm its independent test detects it. Inspect logs for synthetic sensitive markers.
- [ ] Unauthorized reads and sign-offs are rejected at the deployed boundary.
- [ ] Key rotation, legacy receipts and retention/deletion are explicitly approved and tested.

### T04 — Recovery and reviewer usability (preventive operations and UX)
**Prerequisites:** T01–T03, owner-approved hosting and recovery objectives. **Observed paths:** `clausewindow/storage.py`, `clausewindow/api.py`, `tests/test_storage_migration.py`; **proposed:** runbook, restore fixtures and accessibility tests.
1. Specify SQLite backup procedure that handles live WAL state, encryption, access, retention, migrations and rollback; document RPO/RTO and key recovery.
2. Restore a synthetic pre-migration database into an isolated environment, migrate it and compare receipt contents and audit verification against independent expected records; time recovery and inspect errors.
3. Exercise the fallback console with keyboard and screen reader, including errors, extraction gaps and disclaimer; make output understandable without representing an unverified sign-off as completed.

**Deliverable:** observed recovery drill, migration evidence and usability report. **Verification:** restore a deliberately incomplete or altered backup and confirm comparison/integrity checks fail; record keyboard and screen-reader observations at supported viewport sizes.
- [ ] Recovery meets approved targets and restores receipt/signing state.
- [ ] Reviewer can understand gaps, errors and decision-support limits.

### T05 — Independent acceptance and release (all findings)
**Prerequisites:** completed T01–T04 evidence; owner and qualified lawyer available. **Observed paths:** prior task outputs; **proposed:** acceptance record and release checklist.
1. Have an independent reviewer trace each finding to its implementation, tests, deployment boundary and residual risk; reproduce representative failures from the original findings.
2. Run negative controls that break access checks, extraction completeness, evaluation expectations and restoration; confirm each corresponding gate fails and then restore the candidate state.
3. Record exact revision, observed CI/deployment/restore results, unresolved limitations and authorized sign-offs; release only after owners accept remaining risk.

**Deliverable:** revision-bound acceptance record. **Verification:** independent reviewer inspects results and negative-control failures; a test count or signed checklist alone is not proof.
- [ ] F01–F07 resolved or explicitly accepted with accountable owner.
- [ ] Deployment and restore were observed; legal and privacy limitations remain visible.

## Production acceptance, approvals and rollback
- [ ] Owner approves users, exposure, data handling, external processing, deployment and incident response.
- [ ] Qualified lawyer approves use, reviewer authentication, evaluation scope and wording; this is not certification.
- [ ] Dependency resolution, security checks, synthetic end-to-end review and accessibility observations are recorded at the release revision.
- [ ] An isolated backup restore and migration verify contents and audit integrity, with recovery targets met.

Changes to legal claims, production data flows, retention, credentials, external services, deployment or irreversible migrations require owner approval. Keep a prior release artifact and verified, access-controlled SQLite-consistent backup; stop writes before rollback, restore into isolation, verify data and audit state, then switch traffic under the approved runbook. Record any lost writes and recheck the running revision. No deployment or rollback occurred here.
