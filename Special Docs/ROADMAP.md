# ROADMAP.md — Delivery Roadmap for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` · `design.md` · `CLAUDE.md` · `ROADMAP.md` · `design.md` · `design.md`
**Timeline:** July–Dec 2026 (one academic semester, ~24 weeks)
**Team:** Ashish Bhardwaj (2300344) · Arvinder Singh (2300343) · Ayushi Kumari (2300346) · Balraj Singh (2300349) — guided by Prof. Rupinder Kaur

**Purpose:** map the 10 phases in `ROADMAP.md` onto real calendar weeks, with review checkpoints, so the team and guide can track progress against a schedule rather than an open-ended checklist. Dates are planning targets, not contractual — if a phase slips, update this file rather than letting the schedule silently drift out of sync with reality.

---

## 1. Milestone summary

| Milestone | Target | What it proves |
|---|---|---|
| **M0 — Synopsis approved** | Week 1 (already complete) | Problem, objectives, and methodology are locked (`PRD.md` Sections 1–5) |
| **M1 — Foundations ready** | Week 4 | Repo, schema, and skeleton API exist and run locally |
| **M2 — Evidence pipeline working** | Week 9 | Upload → extraction works end to end for all 6 evidence types |
| **M3 — Mid-semester review** | Week 12 | AI Analysis producing explainable findings on real synthetic evidence |
| **M4 — Investigation core complete** | Week 17 | Correlation, timeline, threat scoring, and assistant all functional |
| **M5 — Reporting complete** | Week 19 | Full evidence-to-report flow works end to end |
| **M6 — Pre-final review / hardening** | Week 21 | Security/performance pass done, E2E test passing |
| **M7 — Final submission & demo** | Week 24 | Documentation finalized, demo case rehearsed, project defended |

---

## 2. Phase-to-timeline mapping

Maps directly onto the 10 phases defined in `ROADMAP.md`. "Week" numbers are relative to semester start (Week 1 = first week of July 2026).

| Phase (`ROADMAP.md`) | Weeks | Calendar (approx.) | Owner focus |
|---|---|---|---|
| Phase 0 — Project setup | 1–3 | Early–mid July | Whole team: repo, schema, base FastAPI app |
| Phase 1 — Auth & case management | 4–5 | Late July | Backend pair |
| Phase 2 — Evidence ingestion | 6–7 | Early August | Backend pair + one frontend dev |
| Phase 3 — Extractors (preprocessing) | 7–9 | Mid–late August | Split: 2 extractors per person |
| Phase 4 — AI Analysis (Analyzer) | 10–12 | Early–mid September | ML-focused pair, XAI helper built first |
| **Mid-semester review (M3)** | **12** | **mid-September** | Demo: upload → extract → explainable findings |
| Phase 5 — Correlation & Timeline | 13–14 | Late September | Backend/ML pair |
| Phase 6 — Threat scoring | 15 | Early October | ML-focused pair |
| Phase 7 — NLP/LLM assistant | 15–17 | Early–mid October | LLM-focused pair, resolve open design questions first |
| Phase 8 — Report generation | 17–19 | Mid–late October | Full-stack pair |
| Phase 9 — Hardening & polish | 19–21 | Early November | Whole team: security pass, perf, E2E test |
| **Pre-final review (M6)** | **21** | **mid-November** | Demo: full flow, security checklist reviewed |
| Phase 10 — Documentation & demo prep | 21–23 | Mid–late November | Whole team: docs, demo case, dry runs |
| Buffer / contingency | 23–24 | Early December | Absorb slippage from any earlier phase |
| **Final submission & demo (M7)** | **24** | **early–mid December** | Viva / final defense |

**Note on parallelism:** phases 5–8 have real dependencies (correlation needs analysis output, reports need everything upstream) but within a phase, tasks split across evidence types or endpoints can run in parallel across the 4-person team — see `ROADMAP.md` for the exact task list to divide.

---

## 3. Review checkpoints — what must be demonstrable

### M1 — Foundations ready (Week 4)
- Repo structure matches `design.md` Section 3.
- SQLite schema created with `Finding.confidence_score`/`explanation` constraints in place (`ROADMAP.md` Phase 0).
- Base FastAPI app runs locally with router stubs responding.

### M2 — Evidence pipeline working (Week 9)
- All 6 Extractors (log, browser history, document/metadata, image, memory, network) pass their unit tests against `design.md` Section 2 fixtures.
- Malformed-file handling verified (`design.md` Section 4.2).
- `POST /evidence/upload` and `GET /evidence/{case_id}` match `design.md`.

### M3 — Mid-semester review (Week 12)
- Live demo: upload a synthetic evidence set → see extracted artifacts → see at least one AI finding with a real confidence score and explanation (`design.md` Section 3.1–3.2).
- Guide sign-off that the explainability approach (Section 6, `design.md`) is on track.
- **Decision needed by this checkpoint:** final model choice(s) for the Analyzer and LLM backend (`design.md` Section 10, open question #1) — do not enter Phase 5 without this resolved.

### M4 — Investigation core complete (Week 17)
- Timeline reconstruction demonstrably merges related artifacts across evidence types (`design.md` Section 3.3).
- Threat score is traceable to contributing findings (`design.md` Section 3.4).
- Assistant answers are cited and case-scoped, with a passing cross-case isolation test (`design.md` Sections 3.5, 4.5).

### M5 — Reporting complete (Week 19)
- Full report (evidence summary → timeline → findings → threat score → recommendations) generated for a synthetic case with no data dropped in formatting.
- Export format(s) finalized (`design.md` open question #2, `design.md` Section 9) and working.

### M6 — Pre-final review (Week 21)
- Full `[SEC]` test suite from `design.md` Section 4 passing.
- E2E test from `design.md` Section 5 passing.
- Performance sanity checks (`design.md` Section 6) meet the minimum hardware spec from `PRD.md` Section 13.
- Guide review of security posture and any remaining open risks (`PRD.md` Section 15).

### M7 — Final submission & demo (Week 24)
- `PRD.md`, `design.md`, `ROADMAP.md` updated to reflect what was actually built (per `ROADMAP.md` Phase 10).
- README / setup instructions verified by a fresh clone-and-run.
- Demo case rehearsed at least once against the full checklist in `design.md` Section 5.
- Final report/synopsis submission and viva.

---

## 4. Risk-driven schedule notes

Tied to the risks already identified in `PRD.md` Section 15:

- **AI/LLM inaccuracy risk** → front-loaded: the XAI helper and model-choice decision are pulled into Phase 4 / M3 (Week 12) rather than left late, so there's time to iterate on model quality before Phase 5 depends on it.
- **Hardware constraint risk (no dedicated GPU)** → CPU-only fallback should be validated by M3, not discovered at M6; if inference is too slow, that's a Week 12 problem to solve, not a Week 21 one.
- **Format/parser complexity risk** → Phase 3 (extractors) is given a full 3 weeks with per-person ownership of specific evidence types, rather than compressed into a shared sprint.
- **Buffer** → Week 23–24 is intentionally unallocated to absorb slippage. If Phase 9 or 10 overruns, it eats this buffer first — the final submission date does not move.

---

## 5. What "on track" looks like at each checkpoint

If, at any milestone, the corresponding bullet list in Section 3 isn't demonstrable, treat that as a signal to re-scope rather than to silently extend the timeline — cut features from "in scope" toward `PRD.md` Section 7's "out of scope" list before cutting corners on the `[XAI]`/`[SEC]` requirements in `CLAUDE.md`, which are non-negotiable per project rules.


---

# ROADMAP.md — Build Plan for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` (what/why) · `design.md` (technical design) · `CLAUDE.md` (agent rules)
**Timeline:** July–Dec 2026 (academic major project)
**Purpose of this doc:** break the design into sequenced, checkable tasks. Work top-to-bottom within a phase; later phases assume earlier ones are done. Each task should be small enough to finish, test, and commit independently.

---

## How to use this doc

- Check a box only when the task is actually done **and** tested (per `CLAUDE.md` Section 7) — not when code is written but unverified.
- If a task turns out to depend on an "Open design question" from `design.md` Section 10, stop and resolve that question first (with the team/guide) rather than guessing.
- Tasks tagged **[XAI]** must not be marked done without a working confidence score + explanation — see `CLAUDE.md` Section 4.
- Tasks tagged **[SEC]** touch evidence integrity or security and should get extra review.

---

## Phase 0 — Project setup

- [ ] Initialize repo structure: `frontend/`, `backend/` (with `routers/`, `services/`, `models/`), `ai_engine/` (with `extractor/`, `analyzer/`, `correlator/`, `nlp_llm/`, `xai/`, `scorer/`), `reports/`, `tests/`
- [ ] Set up Python virtual environment; pin dependencies (FastAPI, PyTorch, Scikit-learn, Transformers, SQLite driver, pydantic) in `requirements.txt`
- [ ] Set up `.env`/config handling for paths and secrets — nothing hardcoded (per `CLAUDE.md` Section 6)
- [ ] Create SQLite schema migration for all tables in `design.md` Section 4 (`Case`, `EvidenceItem`, `Artifact`, `Finding`, `TimelineEvent`, `ThreatScore`, `Report`)
- [ ] Enforce `NOT NULL` on `Finding.confidence_score` and `Finding.explanation` at the schema level **[XAI] [SEC]**
- [ ] Set up base FastAPI app with router registration stubs for `cases`, `evidence`, `analysis`, `timeline`, `reports`, `assistant`, `auth`
- [ ] Set up test runner (`pytest`) and a CI-less local test-run script

---

## Phase 1 — Auth & case management

- [ ] `auth` router: investigator registration/login with hashed passwords, session handling **[SEC]**
- [ ] Session-required dependency applied to all non-auth routers **[SEC]**
- [ ] `cases` router: create case, list cases, get case detail, update case status
- [ ] `case_service`: business logic backing the above, with unit tests
- [ ] Frontend: login screen + case dashboard (list/create case)
- [ ] Test: create case → appears in list → fetch by id round-trip

---

## Phase 2 — Evidence ingestion

- [ ] Read-only file store: write-once storage layout, path convention per case/evidence item **[SEC]**
- [ ] `POST /evidence/upload`: server-side type/size validation, SHA-256 hashing, `EvidenceItem` row insert (`ingestion_status = pending`) **[SEC]**
- [ ] `GET /evidence/{case_id}`: list evidence items + ingestion status
- [ ] Frontend: multi-file upload UI with progress and validation feedback
- [ ] Test: upload → hash recorded → file never mutated after upload → bad file type/size rejected

---

## Phase 3 — Extractors (Preprocessing)

Build one Extractor per evidence type. Each takes a raw `EvidenceItem` and produces normalized `Artifact` rows.

- [ ] Log file extractor (system logs)
- [ ] Browser history extractor
- [ ] Document/metadata extractor (file metadata, basic doc parsing)
- [ ] Image metadata extractor (EXIF etc.)
- [ ] Memory artifact extractor
- [ ] Network log extractor
- [ ] Shared `Artifact` normalization interface all extractors conform to (per `design.md` Section 3.3)
- [ ] Per-item failure isolation: one bad file fails only its own `EvidenceItem`, not the whole case **[SEC]**
- [ ] Update `ingestion_status` to `parsed`/`failed` per item
- [ ] Unit tests: one synthetic sample per extractor type (per `CLAUDE.md` Section 7)
- [ ] `POST /analysis/{case_id}/run` (preprocessing stage) wired to run relevant extractors over pending evidence

---

## Phase 4 — AI Analysis (Analyzer)

- [ ] Build shared `xai.explain(model_output, features_used) -> (confidence, explanation)` helper **[XAI]** — build this before any model that needs it
- [ ] Anomaly detection model (Scikit-learn) over `Artifact` features
- [ ] Artifact classification model
- [ ] Wire Analyzer outputs through the XAI helper into `Finding` rows (confidence + explanation always populated) **[XAI]**
- [ ] `GET /analysis/{case_id}/findings`: list findings with confidence + explanation
- [ ] Unit tests: known synthetic anomaly → detected with a non-empty explanation; known-normal sample → not flagged
- [ ] Decide and document exact model choice(s) here before building (resolves `design.md` open question #1)

---

## Phase 5 — Correlation & Timeline

- [ ] Correlator: link `Artifact`/`Finding` rows across evidence items via shared identifiers (timestamp proximity, IP, user account, file hash, hostname)
- [ ] Produce `TimelineEvent` rows, chronologically ordered, each with `source_artifact_ids` and a confidence score **[XAI]**
- [ ] `GET /timeline/{case_id}`: fetch reconstructed timeline
- [ ] Frontend: timeline view component
- [ ] Test: two artifacts sharing an identifier across different evidence items → correctly merged into one `TimelineEvent`

---

## Phase 6 — Threat scoring

- [ ] Scorer: combine `Finding` confidence scores + correlation density into a case-level `ThreatScore` (0–100) and `risk_level`
- [ ] `ThreatScore.contributing_findings` populated so the score is itself explainable **[XAI]**
- [ ] Test: case with high-confidence findings → high score; case with no findings → low score

---

## Phase 7 — NLP/LLM assistant

- [ ] Decide LLM approach: local Transformers model vs. hosted API (resolves `design.md` open question #1, LLM half)
- [ ] Decide chat statefulness: stateless per-query vs. session history (resolves `design.md` open question #3)
- [ ] `POST /assistant/{case_id}/query`: build case-scoped context (only this case's `Artifact`/`Finding`/`TimelineEvent`) into the prompt **[SEC]**
- [ ] Reject/strip any attempt to pull in another case's data or system config into the prompt **[SEC]**
- [ ] Auto-detect cryptographic hash types (MD5: 32 chars, SHA-1: 40 chars, SHA-256: 64 chars) and enforce collision guardrails **[SEC]**
- [ ] Frontend: assistant chat panel in the case workspace
- [ ] Test: query answered only from in-scope case data; cross-case leakage test (assistant must not answer using another case's evidence)

---

## Phase 8 — Report generation

- [ ] Report module: assemble `Report` from `TimelineEvent`, `Finding`, `ThreatScore` — no re-running analysis, formatting only (per `design.md` Section 3.4)
- [ ] Report sections: Evidence Summary → Timeline → Findings (with confidence/justification) → Threat Score → Recommendations
- [ ] Decide export format(s): PDF, HTML, or both (resolves `design.md` open question #2)
- [ ] `GET /reports/{case_id}` and `GET /reports/{case_id}/export`
- [ ] Frontend: report viewer/export screen
- [ ] Test: generated report includes every finding's confidence + explanation (nothing dropped in formatting)

---

## Phase 9 — Hardening & polish

- [ ] Full security pass: parameterized queries everywhere, no evidence content in logs, session checks on every route **[SEC]**
- [ ] Performance: move Extractor/Analyzer runs to background tasks so upload doesn't block on full analysis (per `design.md` Section 9)
- [ ] Error handling pass: every user-facing failure gives a clear message, not a raw stack trace
- [ ] UI polish: loading states for upload/analysis/report generation, responsive layout check (Bootstrap)
- [ ] End-to-end test: upload evidence → run analysis → view timeline → query assistant → generate report, on one synthetic case

---

## Phase 10 — Documentation & demo prep

- [ ] Update `PRD.md`/`design.md` if implementation diverged from the original plan
- [ ] Write a short setup/run README (env setup, how to launch backend + frontend, sample data)
- [ ] Prepare a demo case with representative synthetic evidence (no real/sensitive data)
- [ ] Dry-run the SIH/major-project demo end to end against the checklist in Phase 9's E2E test

---

## Backlog / explicitly out of scope for v1

(Per PRD Section 7 — do not pull these into a phase without updating the PRD first)

- Live/remote forensic acquisition from third-party devices
- Court-certified legal chain-of-custody workflow / multi-jurisdiction compliance certification
- Real-time network intrusion prevention or active incident response actions
- Mobile-device physical/chip-off forensic acquisition
