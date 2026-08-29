# AI Digital Forensics Assistant (AIDFA)

An AI-powered digital forensics investigation web application designed to help investigators, students, and cybersecurity professionals automate evidence upload, extract metadata, detect anomalous log entries, reconstruct chronological timelines, correlate entities (IPs, emails, usernames, hashes), and compile publication-quality forensic audit reports.

---

## Technical Stack & Architecture

### Backend (FastAPI & Python AI)
* **Web Services**: FastAPI, Uvicorn
* **Database & ORM**: SQLite & SQLAlchemy Core (User, Case, Evidence, Finding, and Report schemas)
* **Security & Auth**: JWT tokens (jose), password hashing (passlib/bcrypt), role check credentials guards
* **AI Analysis Engines**:
  * **PyTorch classification model**: Linear classification mapping tf-idf bag-of-words keyword logs to MITRE attack categories (Credential Access, Command & Control, Defense Evasion, etc.).
  * **Scikit-learn Isolation Forest model**: Unsupervised outlier analysis fitted on EVTX system log records to identify suspicious security events.
* **Metadata Extractors**: Pillow (Images with Exif GPS decimal parsing), PyPDF2 (PDF properties), python-docx (Word document core properties), python-evtx (raw Windows event records).
* **Forensic Exporters**: ReportLab (Helvetica styled tables & grid layout PDFs) and python-docx.

### Frontend (React & Cybersecurity UI)
* **Core Logic**: React 18, React Router 6, Axios API, Context API (AuthContext, CaseContext)
* **Visual Engine**: Tailwind CSS (dark mode, glassmorphism, glowing indicator borders), Lucide Icons, pure React SVG network link mapper.
* **Decoupled serving**: Runs as modern ESM modules loaded dynamically in-browser (requires zero node compilation on developer end). Served directly from the backend via FastAPI's `StaticFiles`.

---

## Project Structure

```text
Program/
  ├── backend/
  │    ├── app/
  │    │    ├── api/           # Endpoints (auth, users, cases, evidence, analysis, timeline, correlation, chat, reports, admin)
  │    │    ├── models/        # SQLAlchemy tables (user, case, evidence, finding, report)
  │    │    ├── schemas/       # Pydantic serialization models
  │    │    ├── database/      # SQLite session config
  │    │    ├── auth/          # JWT and role check guards
  │    │    ├── services/      # evidence_processor, correlation mapper
  │    │    ├── ai/            # anomaly_detector, threat_classifier, risk_analyzer
  │    │    ├── utils/         # report_generator utils
  │    │    └── main.py        # FastAPI launcher bootstrap
  │    ├── Dockerfile
  │    └── requirements.txt
  │
  ├── frontend/
  │    ├── src/
  │    │    ├── components/    # Reusable widgets
  │    │    ├── layouts/       # Sidebar layout template
  │    │    ├── pages/         # Dashboard, Login, Cases, CaseDetail, Upload, Timeline, Correlation, Chat, Admin
  │    │    ├── context/       # AuthContext, CaseContext state
  │    │    ├── services/      # Axios api config
  │    │    └── main.js        # React DOM mount entry point
  │    └── index.html
  │
  ├── docker-compose.yml
  └── README.md
```

---

## Local Setup & Quickstart

### Prerequisites
* Python 3.10+
* SQLite3

### 1. Configure Environment Variables
Create a `backend/.env` file with:
```env
SECRET_KEY=prod-only-secure-key-11223344
AI_PROVIDER=disabled
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=ChangeMe123!
DATABASE_URL=sqlite:///app/database/forensics.db
```

### 2. Ingest Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 3. Launch Application Server
```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser. 
Default credentials: `admin` / `ChangeMe123!` (Change through environment configs prior to staging deployment).

The project uses **FastAPI only** at runtime. The previous Flask implementation
is retained in the repository as a legacy reference, but it is not installed or
started by the root launcher. You can also launch FastAPI from the project root:

```bash
python app.py
```

---

## Docker Deployment

To launch isolated instances with persistent SQLite storage:
```bash
docker-compose up --build -d
```
FastAPI endpoints will bind to host port `8000`.

---

## API Documentation Reference

Swagger UI dashboard docs map to: **`http://127.0.0.1:8000/docs`**

| Route | Method | Access | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/register` | POST | Public | Register new investigator account |
| `/api/auth/login` | POST | Public | Authenticate credentials & return JWT token |
| `/api/users/me` | GET | Authenticated | Fetch active user credentials info |
| `/api/cases` | GET/POST | Investigator/Admin | List or initialize case file records |
| `/api/cases/{id}` | GET/PUT/DELETE | Investigator/Admin | Audit, edit, or purge case records |
| `/api/evidence/upload`| POST | Investigator/Admin | Upload evidence files for analysis |
| `/api/analyze` | POST | Investigator/Admin | Trigger PyTorch & Isolation Forest models |
| `/api/timeline/{id}` | GET | Authenticated | Build chronological events list |
| `/api/correlation/{id}`| GET | Authenticated | Generate network relationship link map |
| `/api/chat` | POST | Authenticated | Prompt context-bounded AI chatbot |
| `/api/report` | GET/POST | Investigator/Admin | Compile formal PDF or Word files |
| `/api/report/download/{id}`| GET | Authenticated | Download compiled document binaries |
| `/api/admin/stats` | GET | Admin | Access global system metrics and sizes |
| `/api/intelligence/cases/{id}/analyze` | POST | Investigator/Admin | Extract software and IOCs, then correlate CVEs when remote intelligence is enabled |
| `/api/intelligence/cases/{id}/vulnerabilities` | GET | Authenticated | List stored CVE matches with CVSS, EPSS, and CISA KEV status |
| `/api/intelligence/cases/{id}/indicators` | GET | Authenticated | List extracted IP, URL, and hash indicators |

### CVE and Threat-Intelligence Module

The FastAPI CVE & Threat Intelligence engine detects conservative software/version
indicators and IOCs from uploaded evidence. It stores case-scoped indicators and
CVE correlations, and surfaces CVE matches as regular investigation findings.

Set `THREAT_INTEL_REMOTE_LOOKUPS=true` in `backend/.env` to enable remote queries
to NVD, CISA KEV, and EPSS. It is disabled by default so evidence-derived strings
are not sent to external services without an investigator's decision.
