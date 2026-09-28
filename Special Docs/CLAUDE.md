# CLAUDE.md — Agent Rules for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — an AI Digital Forensics Assistant.
**Audience:** any AI coding agent (Claude Code or otherwise) working in this repository.
**Read this file before writing or modifying any code.** It defines non-negotiable rules, not suggestions. If a request conflicts with this file, follow this file and flag the conflict instead of silently picking one.

---

## 1. What this project is

TACTIC is a web-based platform that lets an investigator upload digital evidence (logs, browser history, documents, images, metadata, memory artifacts, network data), then uses AI/ML/NLP/LLM/XAI to extract artifacts, correlate evidence, reconstruct a timeline, score threat/risk, and generate an explainable forensic report.

Full requirements live in `PRD.md` (or `TACTIC_PRD.docx`) — read it before implementing a new feature. This file only covers **how** to build, not **what** to build.

---

## 2. Tech stack — do not substitute without asking

| Layer | Required technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, Bootstrap |
| Backend | FastAPI (Python) |
| AI / ML | PyTorch, Scikit-learn, Transformers (Hugging Face) |
| Database | SQLite |
| Core language | Python 3.9+ |
| Dev environment | VS Code |

Do not introduce a new database engine, backend framework, or ML framework without explicit approval — this is an academic major project with a fixed stack the team is graded against.

---

## 3. Architecture — respect the layers

The system is layered and each layer has one job. Code must stay inside its layer; don't reach across layers directly.

```
User → Frontend → Backend (FastAPI) → AI Engine (AI/ML/NLP/LLM/XAI) → Database (SQLite)
                                    ↘ Report module
```

- **Frontend**: upload evidence, display results, manage investigations. No business logic, no direct DB access — everything goes through the backend API.
- **Backend**: request handling, workflow orchestration, calls into the AI Engine and Database. This is the only layer allowed to talk to the database directly.
- **AI Engine**: artifact extraction, anomaly detection, correlation, timeline reconstruction, NLP/LLM reasoning, XAI explanation generation. Must be callable independently of the web layer (e.g. from a script or test) — don't couple model code to FastAPI request objects.
- **Database**: evidence metadata, analysis results, correlations, investigation data. Never store raw evidence files in the DB — store a path/reference and hash instead.
- **Report**: consumes AI Engine output and produces the structured, explainable report. Report generation must not re-run analysis; it only formats what the AI Engine already produced.

The six-stage investigation flow (Evidence Collection → Preprocessing → AI Analysis → Evidence Correlation → Report Generation → Web Implementation) should map cleanly onto this architecture. If a change makes that mapping fuzzy, reconsider the change.

---

## 4. Explainability is a hard requirement, not a nice-to-have

Every AI/ML output that reaches an investigator must carry:

1. A **confidence score** (0–1 or 0–100%).
2. A **human-readable justification** — which artifacts, features, or rules drove the finding.

If you add a new detection/classification/correlation model, you must also add the code that produces its explanation. A finding with no explanation is not shippable — do not merge it, do not mark the task complete.

Do not fabricate confidence scores or explanations as placeholders and leave them unimplemented ("TODO: add real score"). If the real score isn't ready, the feature isn't ready.

---

## 5. Evidence integrity rules

TACTIC's credibility depends on not corrupting or silently mutating evidence.

- Treat uploaded evidence as **read-only** once ingested. Never overwrite an original file; derived/processed data goes in separate storage.
- Hash every uploaded file on ingestion (e.g. SHA-256) and store the hash alongside the metadata. Any later integrity check compares against this hash.
- Never conclude file identity, whitelist a file, or match an incident based solely on an MD5 or SHA-1 hash due to known collision vulnerabilities. Always require and verify via SHA-256 before concluding identity.
- Log every processing step performed on an evidence item (what ran, when, on which artifact) — this is the basis for chain-of-custody, even though full legal chain-of-custody is out of scope for v1.
- Never let a parsing failure on one artifact silently drop or corrupt other artifacts in the same case — fail that item, log it, continue with the rest.

---

## 6. Coding standards

- **Python**: follow PEP 8. Type hints on all new function signatures. Use `pydantic` models for FastAPI request/response schemas — no bare dicts crossing the API boundary.
- **FastAPI**: one router per functional area (evidence, analysis, timeline, reports, auth). Don't dump every endpoint into a single `main.py`.
- **AI Engine code**: keep model loading, inference, and explanation logic in separate, testable functions. No inference code embedded inside route handlers.
- **Frontend**: keep JS unobtrusive — no inline `onclick=` handlers in new code, use Bootstrap components rather than hand-rolled CSS where a Bootstrap component already covers the case.
- **Secrets/config**: never hardcode file paths, API keys, or model paths — use environment variables or a config file that's excluded from version control.
- **Naming**: match the domain language already used in the PRD (evidence, artifact, correlation, timeline, threat score, report) — don't invent parallel terminology for the same concept.

---

## 7. Testing expectations

- New AI Engine functions (extraction, correlation, scoring) need at least one unit test with a small synthetic evidence sample.
- New API endpoints need at least one test covering the success path and one covering a bad-input/failure path.
- Don't mark a task "done" if the only verification was a manual print statement — add an actual test or a reproducible check.

---

## 8. Security baseline

- Validate and sanitize every uploaded file's type/size before processing; never execute or `eval` content extracted from evidence.
- Parameterize all SQL — no string-concatenated queries against SQLite.
- Investigation data is sensitive by nature: don't log full evidence contents to console/application logs, only metadata and identifiers.
- Any LLM prompt that includes evidence content must not also include unrelated system secrets or other cases' data — scope prompts to the current case only.

---

## 9. What NOT to do

- Don't add a new major dependency (a different web framework, ORM, vector DB, cloud service) without flagging it first — this is a fixed-scope academic project on a deadline (July–Dec 2026).
- Don't silently expand scope past what's in the PRD's "In scope (v1)" list (Section 7). If a task implies something in "Out of scope" (e.g. live remote acquisition, court-certified chain of custody), stop and ask.
- Don't generate placeholder/mock AI results that look real (e.g. hardcoded "confidence: 0.92") and leave them in place after the corresponding model isn't actually implemented — this misleads whoever reviews the demo.
- Don't remove or weaken the confidence-score/explanation output to "simplify" a feature — see Section 4.

---

## 10. When in doubt

Prefer asking a clarifying question over guessing when a change touches: evidence handling/integrity, the confidence-score/explanation contract, the fixed tech stack, or scope boundaries. For everything else (styling, minor refactors, non-forensic utility code), use best judgment and proceed.
