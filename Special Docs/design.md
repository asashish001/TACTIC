# design.md — Technical Design for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` (what/why) · `CLAUDE.md` (agent rules) · `ROADMAP.md` (build plan)
**Purpose of this doc:** translate the PRD into a concrete technical design — modules, data model, API contracts, algorithms, and data flow — detailed enough to start implementation from.

---

## 1. Design goals

- **Modularity** — evidence ingestion, AI analysis, correlation, and reporting must be independently testable and replaceable.
- **Explainability by construction** — every AI output carries its evidence trail from the moment it's produced, not bolted on afterward.
- **Evidence integrity** — original uploads are immutable; every derived artifact is traceable back to its source file and hash.
- **Small-footprint deployment** — SQLite + FastAPI + local PyTorch/Transformers models, runnable on the hardware specified in the PRD (Section 13) without external cloud dependencies.

---

## 2. High-level architecture

```
┌─────────────┐      HTTPS       ┌──────────────────────┐
│  Frontend   │ ───────────────▶ │   FastAPI Backend     │
│ (HTML/JS/   │ ◀─────────────── │  (routers + services)  │
│  Bootstrap) │                  └──────────┬────────────┘
└─────────────┘                             │
                                             ▼
                              ┌──────────────────────────┐
                              │        AI Engine          │
                              │ ┌────────┐ ┌────────────┐ │
                              │ │Extractor│ │ Correlator │ │
                              │ └────────┘ └────────────┘ │
                              │ ┌────────┐ ┌────────────┐ │
                              │ │NLP/LLM │ │    XAI     │ │
                              │ └────────┘ └────────────┘ │
                              └──────────┬────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │      SQLite (metadata,          │
                         │  artifacts, correlations,       │
                         │  timelines, reports)            │
                         └───────────────────────────────┘
                                         ▲
                         ┌───────────────────────────────┐
                         │   File store (raw evidence,     │
                         │   read-only, content-hashed)    │
                         └───────────────────────────────┘
```

The Report module sits alongside the AI Engine and reads its outputs (artifacts, correlations, timeline, scores) plus DB metadata — it does not re-run analysis.

---

## 3. Module breakdown

### 3.1 Frontend
- Case dashboard (list/create investigations)
- Evidence upload screen (multi-file, progress, type/size validation client-side)
- Investigation workspace: artifact browser, timeline view, AI-assistant chat panel, threat-score summary
- Report viewer/export screen

### 3.2 Backend (FastAPI)
The backend architecture has expanded to **21 modular routers** (handling 72+ endpoints) rather than the initial 7. Key functional areas include:

- **Core Case & Evidence**: `cases`, `evidence`, `artifacts`, `browser`, `network`, `forensic_records`
- **Analysis & AI**: `analysis`, `correlation`, `timeline`, `intelligence`, `chat`, `evaluation`, `model_management`
- **System & Admin**: `auth`, `users`, `admin`, `jobs`, `reports`, `settings`, `system`, `assets`

Each router calls a corresponding **service** module (e.g., in `services/`) that contains the actual logic; routers stay thin (parse request → call service → shape response).

### 3.3 AI Engine
- **Extractor** — per-evidence-type parsers (log parser, browser-history parser, metadata/EXIF reader, memory-artifact reader, network-log parser) that normalize raw evidence into a common `Artifact` structure.
- **Analyzer (ML)** — anomaly detection and artifact classification (Scikit-learn for classical models; PyTorch for any deep models).
- **Correlator** — cross-source correlation using shared identifiers (timestamps, IPs, user accounts, file hashes, hostnames) to link artifacts into events and build the timeline.
- **NLP/LLM** — Transformers-based summarization, entity extraction, and the conversational assistant used to query a case in natural language.
- **XAI** — wraps every Analyzer/Correlator output with a confidence score and a feature-level or rule-level justification (see Section 6).
- **Scorer** — combines correlated findings into a case-level threat/risk score.

### 3.4 Report module
Formats AI Engine output (artifacts, correlations, timeline, threat score, explanations) into a structured report (on-screen + exportable, e.g. PDF/HTML) with sections mirroring the PRD's expected-output pipeline: Evidence Summary → Timeline → Findings (with confidence/justification) → Threat Score → Recommendations.

---

## 4. Data model (SQLite)

The data model has evolved to include **15 SQLAlchemy ORM models** with cascade integrity. The core tables structure is conceptually:

```text
Core Entities:
- User (investigator accounts and RBAC)
- Case (investigation containers)
- EvidenceItem (uploaded files, hashes, status)

Artifact Subtypes:
- ExtractedArtifact (base entity for parsed evidence)
- BrowserArtifact (specialized for web history)
- NetworkArtifact (specialized for PCAP/net logs)
- ForensicRecord (system logs, event records)

Analysis & Results:
- Finding (AI-flagged anomalies with confidence/explanation)
- ArtifactCorrelation (graph edges linking artifacts)
- TimelineEvent (chronological reconstruction)
- ThreatScore (case-level risk metric)
- Report (generated output)

System & Orchestration:
- ForensicJob (async pipeline tracking)
- Intelligence (threat intel lookups)
- ModelRegistry & ModelEvaluation (AI model lifecycle)
- SystemSetting (global configuration)
```

**Rules enforced by this schema:**
- `Finding.confidence_score` and `Finding.explanation` are `NOT NULL` — the DB itself rejects an unexplained finding (see `CLAUDE.md` Section 4).
- `EvidenceItem.file_path` never changes after ingestion; re-processing creates new `Artifact`/`Finding` rows, it never mutates the original.
- All foreign keys cascade on `Case` deletion only — evidence and findings are never orphaned silently.

---

## 5. Core data flow (matches PRD Section 10 methodology)

1. **Evidence Collection** — `POST /evidence/upload` stores the file in the read-only store, computes `sha256_hash`, inserts an `EvidenceItem` row (`ingestion_status = pending`).
2. **Preprocessing** — the appropriate Extractor parses the file into normalized `Artifact` rows; `ingestion_status` becomes `parsed` or `failed` (failure isolated to that item, per `CLAUDE.md` Section 5).
3. **AI Analysis** — Analyzer runs anomaly/classification models over new `Artifact`s, producing `Finding` rows with `confidence_score` + `explanation` from the XAI wrapper.
4. **Evidence Correlation** — Correlator links `Artifact`/`Finding` rows across evidence items into `TimelineEvent` rows, ordered chronologically.
5. **Report Generation** — Scorer computes `ThreatScore`; Report module assembles `Report` from `TimelineEvent`, `Finding`, and `ThreatScore`.
6. **Web Implementation** — Frontend renders the case workspace and report via the API; `assistant` router lets the investigator query the case in natural language, grounded only in that case's `Artifact`/`Finding`/`TimelineEvent` data (see Section 8 on prompt scoping).

---

## 6. Explainability design (XAI wrapper)

Every function in Analyzer/Correlator that produces a `Finding` or `TimelineEvent` must call through a shared `xai.explain(model_output, features_used) -> (confidence, explanation)` helper rather than writing scores by hand. This keeps the explanation format consistent and prevents ad-hoc, unimplemented "TODO" scores from slipping through review.

- **Classical ML (Scikit-learn)**: use feature importances / decision-path inspection to build the explanation string (e.g. "flagged due to unusual login hour [feature: hour=03:00] and new source IP [feature: ip_seen_before=False]").
- **Deep models (PyTorch)**: use attention weights or a simple saliency method over model inputs where feasible; otherwise fall back to the nearest interpretable proxy (e.g. a shadow decision-tree trained on the same features) rather than shipping a black-box score with no justification.
- **LLM outputs**: explanations must cite which artifacts/fields the model was given in its context, not just repeat the model's own free-text reasoning uncritically.

---

## 7. API surface (representative endpoints)

*Note: The platform exposes 72 endpoints across 21 routers. Below is a representative sample of the core flow. See `http://127.0.0.1:8000/docs` (Swagger UI) for the complete, live specification.*

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/cases` | create a new investigation case |
| `GET` | `/cases/{case_id}` | fetch case summary |
| `POST` | `/evidence/upload` | upload evidence file(s) to a case |
| `GET` | `/evidence/{case_id}` | list evidence items + ingestion status |
| `POST` | `/analysis/{case_id}/run` | trigger AI Engine analysis for a case |
| `GET` | `/analysis/{case_id}/findings` | list findings with confidence + explanation |
| `GET` | `/timeline/{case_id}` | fetch reconstructed timeline |
| `GET` | `/reports/{case_id}` | fetch/generate the structured report |
| `GET` | `/reports/{case_id}/export` | export report (PDF/HTML) |
| `POST` | `/assistant/{case_id}/query` | ask the AI assistant a natural-language question scoped to this case |

All request/response bodies use `pydantic` schemas (per `CLAUDE.md` Section 6) — no bare dicts.

---

## 8. Security & scoping design

- Investigator auth via session-based login (FastAPI + hashed passwords); every non-auth endpoint requires a valid session.
- `assistant` queries are scoped by injecting only the current case's `Artifact`/`Finding`/`TimelineEvent` records into the LLM prompt/context — never another case's data, never system configuration or secrets (per `CLAUDE.md` Section 8).
- Uploaded file type/size are validated server-side (not just client-side) before being written to the file store.
- All DB access uses parameterized queries/ORM — no raw string-built SQL.

---

## 9. Non-functional design notes

- **Performance**: Extractor and Analyzer steps run as background tasks (FastAPI `BackgroundTasks` or a simple task queue) so evidence upload doesn't block on full-case analysis; `ingestion_status`/analysis status is polled or pushed via a status endpoint.
- **Scalability**: SQLite is sufficient for the academic project's data volumes (per PRD Section 15 assumptions); the service-layer boundary between routers and business logic keeps a future move to PostgreSQL low-risk if needed later.
- **Portability**: no cloud-only dependencies — the AI Engine must run fully on the local hardware specified in PRD Section 13 (CPU-only fallback for all models, GPU optional acceleration).

---

## 10. Resolved design decisions (Updated)

- **Exact model choices**: Analyzer uses Scikit-Learn Isolation Forest for outlier analysis. NLP/LLM uses a configurable API provider (Gemini, OpenAI, Ollama) along with a local fallback using `Snowflake/snowflake-arctic-embed-xs` for semantic search.
- **Export format(s)**: Reports are exported as both PDF and DOCX (using `reportlab` and `python-docx`).
- **Chat statefulness**: The AI assistant chat is stateless per-query, relying strictly on the grounded evidence context without persisting conversation history.
- **API divergence**: The final implemented endpoints diverge slightly from the original spec (e.g., `/api/chat` instead of `/assistant/{case_id}/query`). See `README.md` and the live Swagger documentation (`/docs`) for the final deployed API surface.


---

# design.md — API Specification for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` · `design.md` (Section 7 lists these endpoints at a high level) · `CLAUDE.md` · `ROADMAP.md`
**Purpose:** the concrete request/response contract for every endpoint, so frontend and backend work can proceed in parallel against a fixed interface. Field types are Python/pydantic-style. This is the source of truth — FastAPI's auto-generated OpenAPI docs should match it; if they diverge, this file wins and the code should be fixed.

**Base URL:** `/api/v1`
**Format:** all requests/responses are JSON except file upload (`multipart/form-data`) and report export (binary).
**Auth:** every endpoint except `POST /auth/login` and `POST /auth/register` requires a valid session (cookie or bearer token — see Section 0). Unauthenticated requests return `401`.

---

## 0. Auth

### `POST /auth/register`
Create an investigator account.

**Request**
```json
{
  "username": "string, required, unique",
  "password": "string, required, min 8 chars",
  "full_name": "string, required"
}
```

**Response `201`**
```json
{
  "id": "int",
  "username": "string",
  "full_name": "string",
  "created_at": "datetime (ISO 8601)"
}
```

**Errors:** `409` username already exists · `422` validation failure (weak password, missing field)

---

### `POST /auth/login`
Authenticate and start a session.

**Request**
```json
{
  "username": "string, required",
  "password": "string, required"
}
```

**Response `200`**
```json
{
  "session_token": "string",
  "expires_at": "datetime"
}
```
Sets a session cookie if cookie-based auth is chosen (see `design.md` Section 8 — implementation detail to confirm during Phase 1).

**Errors:** `401` invalid credentials

---

### `POST /auth/logout`
Invalidate the current session.

**Response `204`** — no body.

---

## 1. Cases

### `POST /cases`
Create a new investigation case.

**Request**
```json
{
  "title": "string, required",
  "description": "string, optional"
}
```

**Response `201`**
```json
{
  "id": "int",
  "title": "string",
  "investigator": "string (username of creator)",
  "status": "open",
  "created_at": "datetime"
}
```

**Errors:** `401` no session · `422` missing title

---

### `GET /cases`
List cases belonging to (or visible to) the current investigator.

**Query params:** `status` (optional filter: `open` | `analyzing` | `reported` | `closed`), `limit` (default 50), `offset` (default 0)

**Response `200`**
```json
{
  "total": "int",
  "items": [
    {
      "id": "int",
      "title": "string",
      "status": "string",
      "created_at": "datetime",
      "evidence_count": "int"
    }
  ]
}
```

---

### `GET /cases/{case_id}`
Fetch full detail for one case.

**Response `200`**
```json
{
  "id": "int",
  "title": "string",
  "description": "string | null",
  "investigator": "string",
  "status": "string",
  "created_at": "datetime",
  "evidence_count": "int",
  "finding_count": "int",
  "threat_score": "float | null"
}
```

**Errors:** `404` case not found · `403` case belongs to another investigator (if per-investigator isolation is enforced)

---

### `PATCH /cases/{case_id}`
Update case status/metadata.

**Request**
```json
{
  "title": "string, optional",
  "description": "string, optional",
  "status": "open | analyzing | reported | closed, optional"
}
```

**Response `200`** — same shape as `GET /cases/{case_id}`.

**Errors:** `404` case not found · `422` invalid status value

---

## 2. Evidence

### `POST /evidence/upload`
Upload one or more evidence files to a case.

**Request:** `multipart/form-data`
```
case_id: int, required
files: file[], required
evidence_type: string, optional (log | browser_history | document | image | memory | network) — inferred from file if omitted
```

**Response `201`**
```json
{
  "uploaded": [
    {
      "id": "int",
      "original_filename": "string",
      "evidence_type": "string",
      "sha256_hash": "string",
      "ingestion_status": "pending",
      "uploaded_at": "datetime"
    }
  ],
  "rejected": [
    {
      "original_filename": "string",
      "reason": "string (e.g. 'unsupported file type', 'exceeds max size')"
    }
  ]
}
```

**Errors:** `404` case not found · `413` file too large · `422` no files provided
**Notes:** server-side type/size validation is mandatory even if the frontend already validated (`CLAUDE.md` Section 8). Each file is hashed (SHA-256) before storage; the stored file is never modified after this point (`CLAUDE.md` Section 5).

---

### `GET /evidence/{case_id}`
List evidence items for a case with ingestion status.

**Response `200`**
```json
{
  "items": [
    {
      "id": "int",
      "original_filename": "string",
      "evidence_type": "string",
      "sha256_hash": "string",
      "ingestion_status": "pending | parsed | failed",
      "uploaded_at": "datetime",
      "artifact_count": "int"
    }
  ]
}
```

**Errors:** `404` case not found

---

### `GET /evidence/{case_id}/{evidence_id}`
Fetch detail for a single evidence item, including its extracted artifacts.

**Response `200`**
```json
{
  "id": "int",
  "original_filename": "string",
  "evidence_type": "string",
  "sha256_hash": "string",
  "ingestion_status": "string",
  "uploaded_at": "datetime",
  "artifacts": [
    {
      "id": "int",
      "artifact_type": "string",
      "timestamp": "datetime",
      "raw_fields": "object (parsed key/value fields)"
    }
  ]
}
```

**Errors:** `404` evidence item or case not found

---

## 3. Analysis

### `POST /analysis/{case_id}/run`
Trigger the AI Engine pipeline (preprocessing → AI analysis → correlation) for a case's pending evidence. Runs as a background task (`design.md` Section 9); returns immediately with a job reference.

**Request**
```json
{
  "stages": ["preprocessing", "ai_analysis", "correlation"],
  "// optional — omit to run all pending stages"
}
```

**Response `202`**
```json
{
  "job_id": "string (UUID)",
  "case_id": "int",
  "status": "queued"
}
```

**Errors:** `404` case not found · `409` analysis already running for this case

---

### `GET /analysis/{case_id}/status`
Poll the status of the most recent (or a specific) analysis run.

**Query params:** `job_id` (optional — defaults to latest)

**Response `200`**
```json
{
  "job_id": "string",
  "status": "queued | running | completed | failed",
  "stage": "preprocessing | ai_analysis | correlation | done",
  "progress": "float (0.0–1.0)",
  "started_at": "datetime",
  "completed_at": "datetime | null",
  "error": "string | null"
}
```

---

### `GET /analysis/{case_id}/findings`
List AI-generated findings for a case. **Every item is guaranteed to include `confidence_score` and `explanation`** (`CLAUDE.md` Section 4 — enforced at the DB level per `design.md` Section 4).

**Query params:** `finding_type` (optional filter), `min_confidence` (optional float)

**Response `200`**
```json
{
  "items": [
    {
      "id": "int",
      "finding_type": "anomaly | suspicious_pattern | correlation",
      "related_artifact_ids": ["int"],
      "confidence_score": "float (0.0–1.0)",
      "explanation": "string",
      "created_at": "datetime"
    }
  ]
}
```

**Errors:** `404` case not found

---

## 4. Timeline

### `GET /timeline/{case_id}`
Fetch the reconstructed, chronologically ordered timeline for a case.

**Query params:** `start`, `end` (optional ISO 8601 datetime bounds)

**Response `200`**
```json
{
  "case_id": "int",
  "events": [
    {
      "id": "int",
      "timestamp": "datetime",
      "description": "string",
      "source_artifact_ids": ["int"],
      "confidence_score": "float"
    }
  ]
}
```

**Errors:** `404` case not found · `409` timeline not yet generated (analysis not run)

---

## 5. Threat score

### `GET /threat-score/{case_id}`
Fetch the current case-level threat score.

**Response `200`**
```json
{
  "case_id": "int",
  "score": "float (0–100)",
  "risk_level": "low | medium | high | critical",
  "contributing_findings": ["int (Finding ids)"],
  "computed_at": "datetime"
}
```

**Errors:** `404` case not found · `409` score not yet computed

---

## 6. Reports

### `GET /reports/{case_id}`
Fetch (generating on first request if needed) the structured report for a case.

**Response `200`**
```json
{
  "id": "int",
  "case_id": "int",
  "generated_at": "datetime",
  "sections": {
    "evidence_summary": "string",
    "timeline": "array (same shape as GET /timeline/{case_id} events)",
    "findings": "array (same shape as GET /analysis/{case_id}/findings items)",
    "threat_score": "object (same shape as GET /threat-score/{case_id})",
    "recommendations": "string"
  }
}
```

**Errors:** `404` case not found · `409` case has no completed analysis to report on
**Notes:** the Report module only formats existing `Finding`/`TimelineEvent`/`ThreatScore` data — it never re-runs analysis (`design.md` Section 3.4).

---

### `GET /reports/{case_id}/export`
Export the report as a downloadable file.

**Query params:** `format` (`pdf` | `html`, required — exact supported set to be finalized per `design.md` Section 10 open question)

**Response `200`** — binary file, `Content-Type: application/pdf` or `text/html`, `Content-Disposition: attachment; filename="TACTIC_report_{case_id}.{ext}"`

**Errors:** `404` case not found · `400` unsupported format · `409` report not yet generated

---

## 7. Assistant

### `POST /assistant/{case_id}/query`
Ask the AI assistant a natural-language question, scoped strictly to this case's data (`CLAUDE.md` Section 8, `design.md` Section 8).

**Request**
```json
{
  "question": "string, required",
  "conversation_id": "string, optional — omit for a stateless query (see design.md open question #3)"
}
```

**Response `200`**
```json
{
  "answer": "string",
  "cited_artifact_ids": ["int"],
  "confidence_score": "float",
  "conversation_id": "string"
}
```

**Errors:** `404` case not found · `422` empty question · `503` LLM backend unavailable
**Security note:** the backend must build the LLM's context exclusively from this case's `Artifact`/`Finding`/`TimelineEvent` records — never another case's data or system configuration. Requests attempting to reference another `case_id` in the question text do not expand the context beyond the current case.

---

## 8. Common error shape

All non-2xx responses share this body shape:

```json
{
  "error": "string (machine-readable code, e.g. 'case_not_found')",
  "message": "string (human-readable)",
  "details": "object | null (field-level validation errors, when applicable)"
}
```

| Status | Meaning |
|---|---|
| `400` | Malformed request (e.g. unsupported query param value) |
| `401` | No valid session |
| `403` | Authenticated but not authorized for this resource |
| `404` | Resource not found |
| `409` | Conflict with current state (e.g. analysis already running, report not yet ready) |
| `413` | Payload too large (evidence upload) |
| `422` | Validation error (pydantic schema failure) |
| `503` | Downstream dependency unavailable (e.g. LLM backend) |

Per `CLAUDE.md` Section 9, error responses must never include raw stack traces or internal file paths — only the shape above.

---

## 9. Open items to confirm before/during implementation

- Session mechanism: cookie vs. bearer token (Section 0) — pick one during Phase 1 and update this doc.
- Whether cross-investigator case visibility is scoped (i.e. can Investigator A see Investigator B's cases) — affects `403` usage in Section 1/2.
- Final export format set for `GET /reports/{case_id}/export` (PDF only, HTML only, or both) — tied to `design.md` open question #2.
- Whether `conversation_id` statefulness is implemented in v1 or the assistant stays fully stateless — tied to `design.md` open question #3.

These should not be guessed at silently — resolve and update this file, per `CLAUDE.md` Section 10.


---

# design.md — Test Plan for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` · `design.md` · `CLAUDE.md` · `ROADMAP.md` · `design.md`
**Purpose:** define what "tested" actually means for this project — test levels, required synthetic data, and concrete test cases for every `[XAI]` and `[SEC]` tagged task in `ROADMAP.md`. `ROADMAP.md` says "add a test" repeatedly; this doc says exactly what that test must check.

---

## 1. Test levels

| Level | Tool | Scope | When it runs |
|---|---|---|---|
| Unit | `pytest` | A single function/module (one Extractor, one Analyzer model, the XAI helper, one service function) | On every change to that module |
| Integration | `pytest` + test DB | A router + its service + a real (test) SQLite DB | Before merging a feature |
| End-to-end (E2E) | `pytest` + `httpx`/`TestClient` | Full flow: upload → analyze → timeline → assistant → report | Before each phase sign-off, and before the demo (Phase 10) |
| Manual/exploratory | Human, using the UI | Frontend interactions, visual QA, demo dry-run | Before each milestone review |

**Rule:** a task in `ROADMAP.md` is not checked off until it has at least a unit test (per `CLAUDE.md` Section 7). `[XAI]`-tagged and `[SEC]`-tagged tasks additionally need the specific tests defined in Sections 3 and 4 below — a generic "it doesn't crash" test is not sufficient for those tags.

---

## 2. Synthetic test data

**No real evidence, real names, or real case data is ever used in tests or the demo.** All test fixtures are synthetic, generated or hand-crafted specifically for this project, and stored under `tests/fixtures/`.

| Fixture set | Contents | Used by |
|---|---|---|
| `fixtures/logs/` | Small synthetic system log files — a "normal" set and a "contains anomaly" set (e.g. login at 3 AM from a new IP) | Log extractor, Analyzer anomaly tests |
| `fixtures/browser_history/` | Synthetic browser history exports with a mix of benign and suspicious-looking URLs/timestamps | Browser history extractor tests |
| `fixtures/documents/` | A few small documents with varied metadata (author, created/modified timestamps) | Document/metadata extractor tests |
| `fixtures/images/` | Small images with and without EXIF data | Image metadata extractor tests |
| `fixtures/memory/` | Small synthetic memory-artifact sample files | Memory extractor tests |
| `fixtures/network/` | Synthetic network log samples, including one with a clear exfiltration-like pattern (large outbound transfer to an unfamiliar IP outside business hours) | Network extractor + correlation tests |
| `fixtures/malformed/` | Deliberately corrupt/truncated/wrong-extension files, one per evidence type | Failure-isolation tests (Section 4) |
| `fixtures/cases/case_a/`, `fixtures/cases/case_b/` | Two complete, independent synthetic cases with no overlapping identifiers | Cross-case isolation tests (Section 4) |

Each fixture set should be small (a handful of files, not gigabytes) — big enough to exercise real logic, small enough to run fast in CI-less local test runs.

---

## 3. `[XAI]`-tagged tasks — required tests

Any task in `ROADMAP.md` marked `[XAI]` is not complete until all of the following pass for the relevant module:

### 3.1 Explanation is never empty
For every `Finding` and `TimelineEvent` produced in a test run:
- `confidence_score` is present, is a float, and is within `[0.0, 1.0]`.
- `explanation` is present, is a non-empty string, and is not a generic placeholder (assert it doesn't equal boilerplate like `"flagged"`, `"anomaly detected"`, or the empty string).
- `explanation` references at least one concrete feature or artifact field (e.g. contains a timestamp, an IP, a field name) — a purely generic sentence with no case-specific detail fails this check.

### 3.2 Known-anomaly detection with correct confidence direction
- Feed the Analyzer the `fixtures/logs/` "contains anomaly" set → assert at least one `Finding` is produced with `confidence_score >= 0.6` (threshold to be tuned once the real model is chosen — see `design.md` open question #1).
- Feed the Analyzer the `fixtures/logs/` "normal" set → assert no `Finding` is produced above `confidence_score = 0.3`, or none at all.
- This pair (positive case + negative case) is required for **every** Analyzer/Correlator model added, not just the first one.

### 3.3 Correlation produces a justified timeline event
- Feed the Correlator two artifacts from different evidence items sharing an identifier (e.g. same IP appearing in both a log and a network capture from `fixtures/network/`) → assert they merge into one `TimelineEvent` whose `source_artifact_ids` includes both, and whose implicit explanation (via the contributing findings) names the shared identifier.
- Feed the Correlator two artifacts with no shared identifier → assert they do **not** get merged into a single event.

### 3.4 Threat score is traceable
- Given a case with N findings of known confidence scores, assert `ThreatScore.contributing_findings` is non-empty and every id in it corresponds to a real `Finding` on that case.
- Given a case with zero findings, assert the threat score is low/zero and `contributing_findings` is empty (not null, not omitted).

### 3.5 LLM assistant answers cite real data
- Ask the assistant a question against `fixtures/cases/case_a/` whose answer is derivable from that case's artifacts → assert `cited_artifact_ids` is non-empty and every cited id belongs to `case_a`.
- Ask a question with no answer in the evidence (e.g. about a topic not present in any artifact) → assert the assistant says it cannot find supporting evidence rather than fabricating an answer with fake citations.

---

## 4. `[SEC]`-tagged tasks — required tests

### 4.1 Evidence integrity
- Upload a file from `fixtures/logs/` → assert the stored file's SHA-256 hash matches what's recorded in `EvidenceItem.sha256_hash`.
- Attempt to overwrite/modify the stored file path directly (simulating a bug or bad actor) → re-checking the hash must detect the mismatch (this test validates that an integrity check exists, not just that ingestion succeeds).
- Re-run analysis on the same evidence item twice → assert no existing `Artifact`/`Finding` row is mutated; only new rows are added (or the old run's results are versioned, per whatever design is chosen).

### 4.2 Per-item failure isolation
- Upload a normal file (`fixtures/logs/`) and a malformed file (`fixtures/malformed/`) to the same case in one request → assert:
  - The malformed item's `ingestion_status` becomes `failed` with a logged reason.
  - The normal item's `ingestion_status` still reaches `parsed` and produces artifacts.
  - The case as a whole does not error out or block further processing.

### 4.3 Upload validation
- Attempt to upload a file above the configured max size → assert `413` and no `EvidenceItem` row is created.
- Attempt to upload an unsupported file type → assert it's rejected server-side (per `design.md` Section 2) even if a test deliberately bypasses client-side validation.
- Attempt to upload a file with a script/executable payload disguised with a benign extension → assert the system never executes or evaluates evidence content (static parsing only).

### 4.4 SQL injection / query safety
- For every endpoint accepting a string parameter that reaches a DB query (case title, search filters, etc.), send a classic injection payload (e.g. `' OR '1'='1`) → assert it's treated as literal data, not executed as SQL, and no unexpected rows are returned.

### 4.5 Cross-case isolation
- Load `fixtures/cases/case_a/` and `fixtures/cases/case_b/` as two separate cases.
- Query the assistant on `case_a` with a question that references details only present in `case_b` → assert the answer does not leak `case_b` content and `cited_artifact_ids` contains no `case_b` artifact ids.
- Call `GET /timeline/{case_a_id}` and `GET /analysis/{case_a_id}/findings` → assert no `case_b` records appear in either response.
- (If cross-investigator visibility is scoped, per `design.md` Section 9 open item) Attempt to fetch Investigator A's case while authenticated as Investigator B → assert `403` or `404`, not case data.

### 4.6 Auth
- Call any non-auth endpoint without a session → assert `401`.
- Call any non-auth endpoint with an expired/invalid session token → assert `401`.
- Register with a weak password (below the minimum length) → assert `422` and no account is created.

### 4.7 No sensitive data in logs
- Trigger a full ingestion + analysis run against synthetic evidence containing an obviously sensitive-looking value (e.g. a fake credit-card-shaped number in a test log) → grep application logs and assert the raw evidence content does not appear, only metadata/identifiers (per `CLAUDE.md` Section 8).

### 4.8 Cryptographic Hash & Signature Verification
- Submit valid 32-character hexadecimal string → assert identified as MD5 with legacy collision risk advisory.
- Submit valid 40-character hexadecimal string → assert identified as SHA-1 with legacy collision risk advisory.
- Submit valid 64-character hexadecimal string → assert identified as SHA-256 with cryptographically secure verification status.
- Submit invalid string (non-hex characters such as G-Z, or invalid length) → assert rejection with invalid hash format error.
- Assert that neither the AI nor backend ever concludes file identity or whitelisting based solely on MD5 or SHA-1 without mandatory SHA-256 confirmation.

---

## 5. End-to-end test (required before each phase sign-off from Phase 5 onward)

One scripted E2E test covering the full flow, run against `fixtures/cases/case_a/`:

1. Register/login a test investigator.
2. Create a case.
3. Upload the full `case_a` evidence set (mix of log, browser history, document, image, memory, network fixtures — including one deliberately malformed file per Section 4.2).
4. Trigger analysis; poll status until `completed`.
5. Assert: the malformed file is `failed`, all others are `parsed`.
6. Fetch findings → assert every finding has `confidence_score` + non-empty `explanation` (Section 3.1).
7. Fetch the timeline → assert events are chronologically ordered and reference real artifacts.
8. Fetch the threat score → assert it's consistent with the findings present (Section 3.4).
9. Query the assistant with a question answerable from the case data → assert a correctly cited answer (Section 3.5).
10. Fetch and export the report → assert it contains the same findings/timeline/score as the individual endpoints (no data dropped in formatting, per `design.md` Section 3.4).

This is the test referenced in `ROADMAP.md` Phase 9 ("upload evidence → run analysis → view timeline → query assistant → generate report").

---

## 6. Performance sanity checks (not full load testing — v1 is an academic project, not production)

- Uploading and preprocessing the `fixtures/cases/case_a/` set (a realistic but small case) should complete within a few minutes on the minimum hardware spec from `PRD.md` Section 13.
- Analysis should not block the upload endpoint — assert `POST /analysis/{case_id}/run` returns `202` immediately (per `design.md` Section 3), not after the full pipeline finishes.

---

## 7. What this test plan does NOT cover (explicitly out of scope, matches `PRD.md` Section 7)

- Legal-admissibility validation of evidence handling.
- Load/stress testing at production scale.
- Adversarial red-teaming of the LLM beyond the basic leakage/hallucination checks in Sections 3.5 and 4.5.
- Automated UI/visual regression testing (frontend QA stays manual per Section 1, given team size and timeline).

---

## 8. Test data hygiene

- Fixture files must never contain real personal data, real credentials, or anything resembling an actual person's information — everything is fabricated for testing.
- Test databases are separate from any development/demo database; tests must not run against the demo data prepared for Phase 10.
- Clean up (or use a fresh temp DB/file store per test run) so tests are repeatable and don't leave stale evidence behind.
