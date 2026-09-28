# T.A.C.T.I.C. — Product Requirements Document

**Trace Analysis & Cyber Timeline Investigation Core**
*(AI Digital Forensics Assistant)*

Major Project — Bachelor of Technology, Computer Science Engineering
Baba Banda Singh Bahadur Engineering College, Fatehgarh Sahib | July–Dec 2026

**Prepared for Team**
Ashish Bhardwaj (2300344) · Arvinder Singh (2300343) · Ayushi Kumari (2300346) · Balraj Singh (2300349)
Guided by: Prof. Rupinder Kaur

Document Version 1.0 | Status: Draft

---

## 1. Overview

T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) is an AI-powered Digital Forensics Assistant proposed as a web-based platform that automates and simplifies digital forensic investigations. It integrates Artificial Intelligence (AI), Machine Learning (ML), Natural Language Processing (NLP), Large Language Models (LLMs), and Explainable AI (XAI) into a single, unified system that helps investigators collect, analyze, correlate, and report on digital evidence faster and with greater confidence.

The rapid growth of digital technologies, cloud computing, IoT, and online communication has increased both the volume of digital evidence and the sophistication of cybercrime. Traditional forensic tools remain largely manual, fragmented across specialized utilities, and dependent on expert interpretation. T.A.C.T.I.C. is designed to close that gap by combining evidence analysis, timeline reconstruction, and explainable, evidence-backed reporting inside one platform.

> **One-line summary:** TACTIC brings AI, ML, NLP, LLM, and XAI together in one platform to deliver faster, smarter, and reliable digital forensics investigations.

---

## 2. Problem Statement

The rapid growth of cybercrime and the increasing volume of digital evidence have made forensic investigations more complex and time-consuming. Traditional tools require extensive manual analysis, deep technical expertise, and considerable effort to examine evidence spread across multiple, heterogeneous sources. While AI, ML, XAI, and LLMs have improved isolated parts of the workflow, most existing solutions address only individual forensic tasks and stop short of an integrated investigation platform. Challenges around evidence correlation, explainability, evidence integrity, and legal admissibility remain largely unresolved.

**Major problems identified**

- Manual analysis is time-consuming, error-prone, and requires expert knowledge.
- The large volume of digital evidence is difficult to process and analyze at scale.
- Evidence originates from multiple, heterogeneous sources and formats (logs, browser history, documents, images, memory artifacts, network data).
- No integrated AI-powered platform exists for automated correlation, detection, and reporting — tools are specialized and fragmented.
- Existing AI-based solutions lack explainability and transparency, reducing trust and legal admissibility of AI-driven forensic decisions.
- Limited support exists for identifying AI-generated artifacts and AI-assisted cybercrime.
- Open questions remain around evidence integrity, chain of custody, privacy, and AI governance.

---

## 3. Research Gap

Existing research and tooling in AI-assisted digital forensics tends to solve one problem at a time rather than the investigation lifecycle as a whole. The table below summarizes the gap between current research/tools and the solution TACTIC proposes to build.

| Existing Research | Missing Features | TACTIC's Solution |
|---|---|---|
| Tools are specialized and fragmented | No integrated platform | Integrated AI-powered forensic platform |
| Mostly manual analysis and rule-based | No explainability | Explainable AI with evidence-backed results |
| Limited use of AI / LLMs | No AI artifact detection | AI-driven artifact detection & correlation |
| Siloed modules with limited correlation | Limited timeline reconstruction | Automated timeline reconstruction |
| Incomplete reporting & explainability | Lack of automated report generation | Smart, structured report generation |

---

## 4. Goals & Objectives

The primary goal is to develop an AI-powered Digital Forensics Assistant that simplifies investigations by automating evidence analysis and helping investigators reach faster, more accurate, and explainable conclusions. Specific objectives:

- **AI Assistant** — Develop an intelligent AI-powered assistant that guides users through forensic tasks and surfaces contextual insights.
- **Evidence Analysis** — Enable automated analysis of diverse digital evidence, including files, logs, metadata, memory, and network artifacts.
- **Timeline Reconstruction** — Reconstruct accurate event timelines by correlating artifacts from multiple sources to establish what happened and when.
- **Report Generation** — Automatically generate clear, structured, and evidence-backed forensic reports to support efficient documentation.
- **Accuracy** — Improve the accuracy and reliability of forensic investigations by leveraging AI and advanced analytical techniques.
- **User-Friendly** — Provide an intuitive interface usable by investigators of all experience levels for complex forensic tasks.

---

## 5. Target Users & Use Cases

**Primary users**

- Digital forensics investigators and cybersecurity analysts handling multi-source evidence.
- Undergraduate students and researchers using TACTIC as an educational forensics platform.
- Small security teams / SOC analysts who need a lightweight, explainable triage assistant.

**Representative use cases**

- Upload logs, browser history, and memory artifacts from an incident and receive a correlated timeline of events.
- Ask the AI assistant natural-language questions about the evidence ("What happened between 2 AM and 4 AM?").
- Generate a structured, evidence-backed forensic report with a threat/risk score suitable for documentation.
- Review confidence scores and explanations behind an AI-flagged artifact before including it in a final report.

---

## 6. Proposed Solution

TACTIC unifies evidence analysis, timeline reconstruction, and report generation into a single platform, built on five cooperating AI capabilities:

| Capability | Role in the Platform |
|---|---|
| AI | Provides intelligent automation to analyze digital evidence, recognize patterns, and assist investigators with accurate insights and recommendations. |
| ML | Utilizes machine learning algorithms to detect anomalies, classify artifacts, and continuously improve analysis accuracy from data. |
| NLP | Enables natural language interaction, allowing users to query evidence, summarize findings, and generate insights in plain language. |
| LLM | Leverages large language models for advanced reasoning, context understanding, Q&A support, and intelligent assistance across investigations. |
| XAI | Ensures explainability by showing how conclusions are reached, building trust, transparency, and supporting legal admissibility. |
| One Platform | An all-in-one integrated experience that unifies evidence analysis, timeline reconstruction, and report generation into a single workflow. |

---

## 7. Scope

**In scope (v1)**

- Ingestion of system logs, browser history, documents, images, metadata, memory artifacts, and network logs.
- AI/ML-based artifact extraction, anomaly detection, and pattern discovery across ingested evidence.
- Cross-source evidence correlation and automated timeline reconstruction.
- LLM-assisted natural-language querying and investigation support.
- Explainable AI outputs — confidence scores and rationale attached to AI findings.
- Automated, structured, exportable forensic report generation with a threat/risk score.
- Secure, web-based interface for uploading evidence, reviewing results, and managing investigations.

**Out of scope (v1)**

- Live/remote forensic acquisition from third-party devices (evidence is uploaded, not remotely collected).
- Court-certified legal chain-of-custody workflows and multi-jurisdiction compliance certification.
- Real-time network intrusion prevention or active incident response actions.
- Mobile-device physical/chip-off forensic acquisition.

---

## 8. Features & Functional Requirements

| Feature | Description |
|---|---|
| Evidence Analysis | Automatically extract, classify, and analyze digital artifacts from multiple sources with high accuracy. |
| Timeline Reconstruction | Reconstruct precise chronological timelines by correlating artifacts across devices and data sources. |
| AI-Generated Reports | Generate clear, structured, professional forensic reports with key findings and visualizations. |
| Explainable Results | Provide explainable AI insights with confidence scores and justifications for every finding. |
| Improved Efficiency | Reduce manual effort and investigation time through automated workflows and intelligent assistance. |
| AI Assistant / Q&A | Conversational assistant for querying evidence and getting contextual, investigation-specific guidance. |

**Expected output pipeline**

The platform takes an investigator from raw evidence to a finished report through five stages:

1. **Upload** — Upload digital evidence from multiple sources.
2. **AI Analysis** — AI models analyze artifacts and detect patterns/anomalies.
3. **Timeline** — Build a chronological timeline of events and activities.
4. **Threat Score** — Calculate a threat score and risk level for the case.
5. **Generated Report** — Produce a comprehensive forensic report with evidence and insights.

---

## 9. System Architecture

TACTIC uses a modular, layered architecture so that evidence intake, AI processing, storage, and reporting can evolve independently.

| Layer | Responsibility |
|---|---|
| User | Investigator interacts with the system through a web interface. |
| Frontend | User interface for uploading evidence, viewing results, and managing investigations. |
| Backend | Handles requests, manages workflows, and communicates between modules. |
| AI Engine | AI, ML, NLP, LLM, and XAI models analyze evidence and generate insights. |
| Database | Stores evidence metadata, analysis results, correlations, and investigation data securely. |
| Report | Generates clear, structured, explainable reports for investigators. |

**Investigation flow**

The same six-stage flow underlies both the architecture and the day-to-day investigation methodology described in Section 10: Digital Evidence → Preprocessing → AI Analysis → Evidence Correlation → Report → Investigation Support.

---

## 10. Methodology

TACTIC follows a systematic six-step methodology to automate and simplify digital forensics investigations using AI-powered techniques.

| # | Step | Description |
|---|---|---|
| 1 | Evidence Collection | Digital evidence such as logs, browser history, metadata, documents, images, memory artifacts, and network logs is collected and uploaded while preserving evidence integrity. |
| 2 | Preprocessing | Evidence is cleaned, organized, and converted into a structured format; relevant forensic artifacts are extracted for analysis. |
| 3 | AI Analysis | AI, ML, NLP, and LLM techniques analyze extracted artifacts to detect suspicious activity, anomalies, and hidden patterns. |
| 4 | Evidence Correlation | Artifacts are correlated across sources and timelines to reconstruct user activity and relationships between events. |
| 5 | Report Generation | Findings are summarized into a structured, explainable forensic report with evidence summaries, threats, and timelines. |
| 6 | Web Implementation | All features are delivered through a secure, user-friendly web platform for upload, analysis, visualization, and reporting. |

---

## 11. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend | HTML, CSS, JavaScript, Bootstrap | Responsive, user-friendly web interface. |
| Backend | FastAPI (Python) | Handles APIs, business logic, and secure data processing. |
| AI / ML | PyTorch, Scikit-learn, Transformers (Hugging Face) | Deep learning, traditional ML, and NLP / LLM capabilities. |
| Database | SQLite | Lightweight, reliable storage for investigation data and metadata. |
| Core Language | Python | Powers the entire platform and all integrated modules. |
| Digital Forensics Libraries | Python forensics modules | Specialized parsing, extraction, and analysis of forensic artifacts. |
| Development Tools | VS Code | Primary development environment. |

---

## 12. Non-Functional Requirements

- **Accuracy & Reliability** — AI findings should be reproducible and consistent across repeated runs on the same evidence.
- **Explainability** — Every AI-generated finding must carry a confidence score and a human-readable justification.
- **Security & Integrity** — Uploaded evidence and derived artifacts must be stored securely, with integrity preserved end to end.
- **Usability** — The interface should be usable by investigators of varying technical skill without specialist training.
- **Scalability** — The architecture should tolerate growing volumes and varieties of digital evidence without redesign.
- **Performance** — Preprocessing, AI analysis, and report generation should complete within practical time bounds for typical case sizes.

---

## 13. Hardware & Software Requirements

**Hardware requirements**

| Component | Minimum | Recommended |
|---|---|---|
| Processor | Intel Core i5 (6th Gen or above) | Intel Core i7 |
| RAM | 8 GB | 16 GB |
| Storage | 20 GB free space (256 GB SSD baseline) | 512 GB SSD |
| GPU | Optional | NVIDIA GTX 1050 or above (4 GB VRAM) for AI model training |

**Software requirements**

| Component | Requirement |
|---|---|
| Operating System | Windows 10 / 11 (64-bit) |
| Programming Language | Python 3.9 or above |
| AI Framework | PyTorch (latest stable, CPU/GPU) |
| ML Library | Scikit-learn |
| NLP Framework | Transformers (Hugging Face) |
| Web Framework | FastAPI (latest stable) |
| Database | SQLite (built in with Python) |
| Development Tools | VS Code (latest stable) |

---

## 14. Success Metrics / Expected Outcomes

- Reduction in manual investigation time compared to a fully manual workflow on the same evidence set.
- High accuracy in artifact extraction, classification, and anomaly detection, validated against labeled test cases.
- Every AI-flagged finding includes a confidence score and explanation reviewers can audit.
- Investigators can go from evidence upload to a structured report without leaving the platform.
- Positive usability feedback from investigators/students of varying experience levels during evaluation.

---

## 15. Risks & Assumptions

**Risks**

- AI/LLM outputs may be inaccurate or hallucinate on ambiguous or low-quality evidence, requiring human review before findings are relied upon.
- Explainability techniques add engineering overhead and may not fully satisfy legal-admissibility expectations in v1.
- Diverse evidence formats (logs, memory dumps, images, network captures) increase parser and preprocessing complexity.
- Local hardware constraints (no dedicated GPU) may slow model inference during development and demos.

**Assumptions**

- Evidence is uploaded by the investigator rather than acquired live from a remote/target device.
- The system is positioned as an educational/research-oriented platform first, with production-forensic certification as a future extension.
- SQLite is sufficient for the project's data volumes during the academic project timeline (July–Dec 2026).

---

## 16. References

*Selected literature that informed this proposal (see the accompanying project synopsis for the complete list):*

- S. Rani et al., "Artificial Intelligence in Digital Forensics: A Review of Cyber-Attack Detection Models and Frameworks," Springer, 2026.
- J. van Beek et al., "Practitioner-driven Framework for AI Adoption in Digital Forensics," Forensic Science International: Digital Investigation, 2025.
- J. Kim, B. Jeong, S. Park, S. Lee, and J. Park, "Your Forensic AI-Assistant, SERENA: Systematic Extraction and Reconstruction for Enhanced A2P Message Forensics," FSI: Digital Investigation, vol. 53, 2025.
- Z. Khalid, F. Iqbal, and M. Saqib, "Bridging Knowledge Gaps in Digital Forensics Using Unsupervised Explainable AI," FSI: Digital Investigation, vol. 53, 2025.
- M. Chernyshev, Z. Baig, and R. R. M. Doss, "Towards LLM Forensics Using LLM-based Invocation Log Analysis," Proceedings of ACM LAMPS, 2024.
- C. Walker, T. Gharaibeh, R. Alsmadi, C. Hall, and I. Baggili, "Forensic Analysis of Artifacts from Microsoft's Multi-Agent LLM Platform AutoGen," ARES, ACM, 2024.
- A. Almutairi et al., "Forensic Investigations in the Age of AI: Identifying and Examining AI-generated Evidence," ISDFS, IEEE, 2025.
- M. Younes et al., "The Role of AI Governance in Digital Forensics: A Framework for Ethical and Reliable Investigations," IEEE CIKE, 2025.
- A. Almutairi et al., "AI-Driven Digital Evidence Triage in Digital Forensics: A Comprehensive Review," ISDFS, IEEE, 2025.
- D. Dunsin, M. C. Ghanem, K. Ouazzane, and V. Vassilev, "A Comprehensive Analysis of the Role of AI and ML in Modern Digital Forensics and Incident Response," FSI: Digital Investigation, vol. 48, 2024.
- N. M. Karie et al., "Digital Forensics and Strong AI: A Structured Literature Review," FSI: Digital Investigation, 2023.


---

# PRD.md — Terminology for T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` · `design.md` · `CLAUDE.md` · `ROADMAP.md`
**Purpose:** a single reference for terms used across the project docs, so the team, guide, and any new contributor use the same vocabulary consistently. Terms are grouped by theme; within a theme they're alphabetical.

---

## Core domain terms

**Artifact**
A single normalized unit of evidence extracted from an `EvidenceItem` — e.g. one login event, one URL visit, one file-access record. Produced by an Extractor. See `design.md` Section 4.

**Case**
One investigation in TACTIC. Contains evidence items, artifacts, findings, a timeline, a threat score, and a report. Maps to the `Case` table in the data model.

**Chain of custody**
The documented, unbroken history of who handled a piece of evidence and what was done to it, from collection to presentation. TACTIC logs processing steps toward this (per `CLAUDE.md` Section 5) but does **not** implement a court-certified chain-of-custody workflow — that's explicitly out of scope for v1 (`PRD.md` Section 7).

**Correlation**
The process of linking artifacts from different evidence items using shared identifiers (timestamps, IPs, user accounts, file hashes, hostnames) to determine they relate to the same event or activity. Performed by the Correlator module.

**Digital evidence**
Any data collected from a digital source that may be relevant to an investigation — logs, browser history, documents, images, memory artifacts, network data, metadata.

**Digital forensics**
The discipline of identifying, acquiring, preserving, examining, analyzing, and presenting digital evidence while maintaining its integrity and (where applicable) legal admissibility.

**Evidence integrity**
The guarantee that evidence has not been altered after collection. In TACTIC, enforced by treating uploads as read-only and hashing every file on ingestion (`CLAUDE.md` Section 5).

**Evidence item**
One uploaded file (a log file, a document, an image, etc.) before it has been parsed into artifacts. Maps to the `EvidenceItem` table.

**Finding**
An AI-generated conclusion about the evidence — an anomaly, a suspicious pattern, or a correlation — that always carries a confidence score and explanation. Maps to the `Finding` table. See "Explainability" below.

**Investigation timeline**
A chronologically ordered sequence of `TimelineEvent` records reconstructed from correlated artifacts, showing what happened and when across the case's evidence.

**Legal admissibility**
Whether evidence and the conclusions drawn from it would hold up as valid in a legal proceeding. TACTIC v1 is an educational/research platform and does not claim legal admissibility (`PRD.md` Section 15, Assumptions).

**Threat score / risk level**
A case-level 0–100 score (and a low/medium/high/critical label) summarizing overall risk, computed by the Scorer from the case's findings. Maps to the `ThreatScore` table.

---

## AI / ML terms

**Anomaly detection**
An ML technique that flags data points (artifacts) that deviate from expected/normal patterns — used by the Analyzer to surface suspicious activity without needing a labeled example of every possible threat.

**Confidence score**
A numeric value (0.0–1.0, or shown as 0–100%) attached to every AI-generated finding, indicating how strongly the model supports that conclusion. Mandatory on every `Finding` and `TimelineEvent` — see `CLAUDE.md` Section 4.

**Explainability**
The property of an AI system's output being understandable to a human — in TACTIC, every finding must state *why* it was flagged (which features/artifacts drove it), not just *that* it was flagged. See "XAI" below.

**Explanation**
The human-readable justification accompanying a confidence score — e.g. "flagged due to unusual login hour and new source IP." Required, not optional, on every finding.

**Extractor**
The AI Engine component that parses a raw evidence file into normalized `Artifact` records. There is one Extractor per evidence type (log, browser history, document/metadata, image, memory, network).

**Hallucination**
When an LLM generates plausible-sounding but false or unsupported output. A known risk for the NLP/LLM assistant, listed in `PRD.md` Section 15 (Risks) — mitigated by scoping the assistant's context to only the current case's real data.

**LLM (Large Language Model)**
A large, pretrained language model (via Hugging Face Transformers in TACTIC's stack) used for natural-language querying, summarization, and reasoning over case evidence.

**ML (Machine Learning)**
Algorithms that learn patterns from data. In TACTIC, primarily Scikit-learn models used for anomaly detection and artifact classification.

**NLP (Natural Language Processing)**
Techniques for working with human language — used in TACTIC to let investigators query evidence and get findings summarized in plain language.

**XAI (Explainable AI)**
The set of techniques used to make AI/ML outputs interpretable — feature-importance inspection for classical models, attention/saliency methods or interpretable proxies for deep models, and context citation for LLM outputs. Implemented via the shared `xai.explain()` helper (`design.md` Section 6).

---

## System / architecture terms

**AI Engine**
The layer of the system containing the Extractor, Analyzer, Correlator, NLP/LLM, XAI, and Scorer components. Callable independently of the web layer.

**Analyzer**
The AI Engine component that runs anomaly detection and classification models over artifacts.

**Assistant (AI Assistant)**
The conversational, LLM-backed feature that lets an investigator ask natural-language questions about a specific case, scoped only to that case's data.

**Backend**
The FastAPI application layer that handles requests, orchestrates the AI Engine, and is the only layer permitted to access the database directly.

**Correlator**
The AI Engine component that links artifacts/findings across evidence items into timeline events.

**Frontend**
The HTML/CSS/JavaScript/Bootstrap web interface investigators use to upload evidence, review results, and read reports.

**Report module**
The component that formats AI Engine output (findings, timeline, threat score) into the final structured, exportable forensic report. Does not perform its own analysis — formatting only.

**Scorer**
The AI Engine component that combines findings into a case-level threat/risk score.

**Service layer**
The business-logic modules (e.g. `evidence_service.py`) called by FastAPI routers, kept separate from route-handling code so logic stays testable independent of the web framework.

---

## Process / project terms

**[SEC] tag**
Used in `ROADMAP.md` to flag a task that touches evidence integrity or security and needs extra review.

**[XAI] tag**
Used in `ROADMAP.md` to flag a task that must not be marked complete without a working confidence score and explanation.

**Investigation methodology (six-step)**
TACTIC's defined process: Evidence Collection → Preprocessing → AI Analysis → Evidence Correlation → Report Generation → Web Implementation. Described in `PRD.md` Section 10 and mirrored in the architecture (`design.md` Section 5).

**Out of scope (v1)**
Features explicitly excluded from the current build — live/remote evidence acquisition, court-certified chain of custody, real-time intrusion prevention, and mobile chip-off forensics. See `PRD.md` Section 7 and the `ROADMAP.md` backlog.

**Phase**
A stage of implementation in `ROADMAP.md` (Phase 0 through Phase 10), each building on the previous and containing a checklist of concrete tasks.

**Team**
The project team building TACTIC: Ashish Bhardwaj, Arvinder Singh, Ayushi Kumari, and Balraj Singh, guided by Prof. Rupinder Kaur.

---

## Acronyms quick reference

| Acronym | Meaning |
|---|---|
| AI | Artificial Intelligence |
| DB | Database |
| DFIR | Digital Forensics and Incident Response |
| ERD | Entity-Relationship Diagram |
| LLM | Large Language Model |
| ML | Machine Learning |
| NLP | Natural Language Processing |
| PRD | Product Requirements Document |
| SIH | Smart India Hackathon |
| SOC | Security Operations Center |
| TACTIC | Trace Analysis & Cyber Timeline Investigation Core |
| XAI | Explainable Artificial Intelligence |


---

# PRD.md — Ethics & Limitations of T.A.C.T.I.C.

**Project:** T.A.C.T.I.C. (Trace Analysis & Cyber Timeline Investigation Core) — AI Digital Forensics Assistant
**Companion docs:** `PRD.md` (Section 15 — Risks & Assumptions) · `design.md` · `CLAUDE.md` · `design.md`
**Purpose:** state plainly what TACTIC does and does not guarantee, and the ethical considerations that come with building an AI system that produces conclusions about people's digital activity. This document should be read alongside the demo/viva — panels evaluating a forensics-adjacent AI tool will ask about exactly these points, and having them written down in advance is stronger than answering from memory under pressure.

---

## 1. Purpose and intended use

TACTIC is an **educational and research-oriented platform**, built as a B.Tech major project (`PRD.md` Section 15, Assumptions). It is intended to:

- Demonstrate how AI/ML/NLP/LLM/XAI techniques can assist — not replace — a human investigator in digital forensics.
- Give investigators, students, and researchers a faster starting point for evidence review, not a final verdict.
- Serve as a foundation that could, with substantial further validation, evolve toward more operational use.

TACTIC is **not**:

- A certified forensic tool for use in active law enforcement investigations.
- A system whose output is legally admissible evidence in a court proceeding.
- A replacement for a qualified digital forensics investigator's judgment.

Any use of TACTIC or its outputs in a real investigation, legal proceeding, or decision with consequences for a real person should be treated as informational input to a human expert, never as a standalone conclusion.

---

## 2. Known limitations

### 2.1 AI/ML accuracy limitations
- Anomaly detection and classification models can produce **false positives** (flagging normal activity as suspicious) and **false negatives** (missing genuine suspicious activity), especially on evidence patterns not represented in training/validation data.
- Model performance is only as good as the synthetic/labeled test data used to validate it (`design.md` Section 2) — real-world evidence is messier and more varied than any fixture set the team can build in one semester.
- Confidence scores indicate model certainty, not ground truth. A high confidence score is not proof; it's a signal for a human to prioritize review.

### 2.2 LLM-specific limitations
- The NLP/LLM assistant can **hallucinate** — generate plausible-sounding but unsupported or incorrect statements (`PRD.md` Section 15, Risks). This is mitigated by requiring cited artifact IDs on every answer (`design.md` Section 7, `design.md` Section 3.5), but citation reduces the risk, it does not eliminate it — a citation can still be misapplied or a claim can subtly extend beyond what the cited artifact actually supports.
- LLM outputs are more fluent than they are reliable. A well-written explanation can create false confidence in a wrong conclusion. Investigators should verify LLM-derived claims against the underlying artifacts before relying on them.

### 2.3 Explainability limitations
- XAI techniques (feature importances, attention/saliency methods, interpretable proxies) approximate *why* a model produced an output — they are not a perfect window into the model's internal reasoning, particularly for deep models (`design.md` Section 6).
- "Explainable" in this project means "the investigator gets a specific, checkable reason," not "the explanation is guaranteed complete or causally exact."

### 2.4 Legal and evidentiary limitations
- TACTIC does **not** implement a court-certified chain-of-custody workflow or multi-jurisdiction compliance certification (`PRD.md` Section 7, Out of scope). Processing logs are kept for traceability, but this falls short of what legal admissibility typically requires.
- Terms like "threat score" and "risk level" are analytical aids produced by the system's own scoring logic, not legal determinations of guilt, intent, or wrongdoing.

### 2.5 Data and evidence limitations
- Evidence is investigator-uploaded, not remotely/forensically acquired (`PRD.md` Section 7, Out of scope) — TACTIC has no way to independently verify that uploaded evidence is complete, unaltered before upload, or representative of the full incident.
- Extractors are built for the evidence formats explicitly listed in the PRD; evidence in formats or from sources outside that list will not be correctly parsed and may be silently skipped or fail ingestion (per the per-item failure isolation behavior in `CLAUDE.md` Section 5).
- **Cryptographic hash limitations**: MD5 and SHA-1 are cryptographically broken for collision resistance and are maintained solely for historical baseline tracking and legacy threat-intel lookups. The system and AI must never conclude file identity, match an incident, or whitelist an artifact based solely on an MD5 or SHA-1 hash; verification via SHA-256 is mandatory before establishing identity.

### 2.6 Bias considerations
- Any ML/LLM component can encode biases present in its training data or in the synthetic data used for local validation. For example, an anomaly-detection model tuned mostly on one type of activity pattern may under- or over-flag activity that looks different but is equally (ab)normal.
- The team has not conducted a formal fairness/bias audit — this is acknowledged as a limitation, not something claimed to be solved. Any operational deployment beyond this academic project would need dedicated bias evaluation before being trusted.
- Because TACTIC produces conclusions that could implicate a specific individual's digital activity, biased or overconfident output has real potential for harm if ever taken as a final answer rather than an investigative lead.

---

## 3. Ethical considerations

### 3.1 Human-in-the-loop is a requirement, not a preference
TACTIC is designed so that every AI output — finding, timeline event, threat score, assistant answer — comes with a confidence score and explanation specifically so a human can evaluate it (`CLAUDE.md` Section 4). The system is built on the premise that **a human investigator makes the final call**, and no part of the design should be read as encouraging fully automated decision-making about a person's conduct.

### 3.2 Privacy of evidence subjects
- Evidence processed by TACTIC may relate to real individuals (in a real deployment) even though the project itself uses only synthetic data (`design.md` Section 8). The architecture (read-only storage, hashing, no raw evidence content in application logs — `CLAUDE.md` Sections 5 and 8) is designed with that eventual sensitivity in mind, even during an academic project that never touches real personal data.
- The assistant's case-scoping rules (`design.md` Section 8) exist specifically so that one case's — and by extension, one person's — data cannot leak into analysis of an unrelated case.

### 3.3 Dual-use awareness
A tool that reconstructs timelines and detects "suspicious" digital activity is inherently dual-use: the same capability that helps an investigator find a genuine threat could, if misapplied, be used to over-surveil or wrongly implicate someone. TACTIC's scope is intentionally limited (evidence the investigator already possesses and uploads, not live monitoring or interception — `PRD.md` Section 7) to reduce this risk, and the team should not extend the project toward real-time surveillance or non-consensual monitoring use cases.

### 3.4 Accountability and transparency
- Every AI-generated conclusion is traceable to the artifacts and model logic that produced it (Sections 2.3, `design.md` Section 6). This is a deliberate design choice to support accountability: if a finding is wrong, it should be possible to see why the system produced it.
- The team accepts responsibility for clearly communicating these limitations (this document) rather than overstating what the system can reliably do, in any demo, report, or future extension of the project.

### 3.5 Governance alignment
This document's structure — explainability, evidence integrity, human review, bias acknowledgment, dual-use awareness — is informed by the forensic-AI governance principles discussed in the literature review underlying this project (see `PRD.md` Section 16 references, particularly the work on Forensic AI Governance Frameworks and XAI in digital forensics). TACTIC does not claim to fully implement a governance framework, but its design choices are made in that direction.

---

## 4. Recommendations for anyone extending this project beyond the academic scope

- Conduct a formal accuracy and bias evaluation on real (properly consented/authorized) or more representative benchmark data before any operational use.
- Engage legal/compliance expertise before claiming any output is admissible or before deploying in a real investigative context.
- Extend the chain-of-custody logging into a full, auditable, tamper-evident record if moving toward production use.
- Periodically re-evaluate the LLM/ML components for hallucination rate and bias as models and evidence patterns evolve — this is not a one-time check.
- Keep the human-in-the-loop principle (Section 3.1) as a hard requirement in any future version, not just this one.

---

## 5. Summary statement

TACTIC is built to assist, explain, and accelerate — never to replace human judgment or to serve as an unquestionable authority on what happened. Every design decision that adds friction (mandatory explanations, case-scoped context, read-only evidence, per-item failure isolation) exists to keep a human investigator in control of the actual conclusion. The team presents TACTIC's outputs as investigative leads worth checking, not as verdicts.
