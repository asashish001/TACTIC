"""Full API integration test suite using FastAPI TestClient."""
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.main import app

client = TestClient(app)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
pytestmark = pytest.mark.integration

@pytest.fixture(scope="module")
def registered_user():
    username = f"testinv_{uuid.uuid4().hex[:6]}"
    password = "SecurePassword123!"
    res = client.post("/api/auth/register", json={
        "username": username, "full_name": "Integration Test Investigator",
        "password": password, "role": "investigator",
    })
    assert res.status_code == 201, f"Registration failed: {res.status_code} {res.text}"
    return username, password

@pytest.fixture(scope="module")
def auth_token(registered_user):
    username, password = registered_user
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    return res.json()["access_token"]

@pytest.fixture(scope="module")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

@pytest.fixture(scope="module")
def created_case(auth_headers):
    case_no = f"CASE-{uuid.uuid4().hex[:6].upper()}"
    res = client.post("/api/cases", json={
        "case_number": case_no, "name": "Integration Test Case",
        "description": "Automated integration test.", "incident_date": "2026-08-02",
    }, headers=auth_headers)
    assert res.status_code == 201
    return res.json()["id"]

@pytest.mark.integration
class TestAuth:
    def test_register(self, registered_user):
        assert registered_user[0].startswith("testinv_")
    def test_login_returns_token(self, auth_token):
        assert len(auth_token) > 20
    def test_login_wrong_password(self, registered_user):
        res = client.post("/api/auth/login", json={"username": registered_user[0], "password": "WrongPassword!"})
        assert res.status_code == 401
    def test_refresh_token(self, registered_user):
        username, password = registered_user
        res = client.post("/api/auth/login", json={"username": username, "password": password})
        refresh = res.json().get("refresh_token")
        assert refresh
        new_res = client.post("/api/auth/refresh", json={"refresh_token": refresh})
        assert new_res.status_code == 200
        assert "access_token" in new_res.json()

@pytest.mark.integration
class TestCaseManagement:
    def test_create_case(self, created_case):
        assert created_case > 0
    def test_list_cases(self, auth_headers, created_case):
        res = client.get("/api/cases", headers=auth_headers)
        assert res.status_code == 200
        assert any(c["id"] == created_case for c in res.json())

@pytest.mark.integration
class TestEvidenceUpload:
    def test_upload_evidence(self, auth_headers, created_case):
        content = b"2026-08-02T10:15:00Z - Authorized admin login successful."
        res = client.post("/api/evidence/upload",
            files=("file", ("security_alert.log", content, "text/plain")),
            data={"case_id": str(created_case)}, headers=auth_headers)
        assert res.status_code == 201
        body = res.json()
        assert "sha256" in body and len(body["sha256"]) == 64
    def test_list_evidence(self, auth_headers, created_case):
        res = client.get(f"/api/evidence?case_id={created_case}", headers=auth_headers)
        assert res.status_code == 200
        assert len(res.json()) >= 1

@pytest.mark.integration
class TestAnalysis:
    def test_timeline(self, auth_headers, created_case):
        res = client.get(f"/api/timeline/{created_case}", headers=auth_headers)
        assert res.status_code == 200
        assert "events" in res.json()
    def test_correlation(self, auth_headers, created_case):
        res = client.get(f"/api/correlation/{created_case}", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert "nodes" in data and "edges" in data

@pytest.mark.integration
class TestChat:
    def test_chat_query(self, auth_headers, created_case):
        res = client.post("/api/chat", json={
            "case_id": created_case, "question": "What files are suspicious?",
        }, headers=auth_headers)
        assert res.status_code == 200
        assert "answer" in res.json()

@pytest.mark.integration
class TestReports:
    def test_generate_pdf(self, auth_headers, created_case):
        res = client.post("/api/report", json={"case_id": created_case, "format": "pdf"}, headers=auth_headers)
        assert res.status_code == 201
        assert "filename" in res.json()
    def test_list_reports(self, auth_headers, created_case):
        res = client.get(f"/api/report?case_id={created_case}", headers=auth_headers)
        assert res.status_code == 200
        assert len(res.json()) >= 1

@pytest.mark.integration
class TestForensicRecords:
    def test_chain_of_custody(self, auth_headers, created_case):
        res = client.get(f"/api/forensic-records/cases/{created_case}/chain-of-custody", headers=auth_headers)
        assert res.status_code == 200
        assert any(r["action"] == "evidence_ingested" for r in res.json())
    def test_audit_log(self, auth_headers, created_case):
        res = client.get(f"/api/forensic-records/cases/{created_case}/audit-log", headers=auth_headers)
        assert res.status_code == 200
        assert "case_created" in {r["action"] for r in res.json()}

@pytest.mark.integration
class TestSettings:
    def test_get_settings(self, auth_headers):
        res = client.get("/api/settings", headers=auth_headers)
        assert res.status_code == 200
        assert "anomaly_threshold" in res.json()
    def test_update_threshold(self, auth_headers):
        res = client.put("/api/settings", json={"anomaly_threshold": 0.85}, headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["anomaly_threshold"] == 0.85
        client.put("/api/settings", json={"anomaly_threshold": 0.80}, headers=auth_headers)
    def test_invalid_threshold_rejected(self, auth_headers):
        res = client.put("/api/settings", json={"anomaly_threshold": 1.5}, headers=auth_headers)
        assert res.status_code in (400, 422)

@pytest.mark.integration
class TestHealth:
    def test_health_endpoint(self):
        res = client.get("/api/health")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] in ("healthy", "warning", "error")
        assert body["backend_status"] == "online"
    def test_model_status(self, auth_headers):
        res = client.get("/model/status", headers=auth_headers)
        assert res.status_code == 200
        assert "loaded" in res.json()


@pytest.mark.integration
class TestReports:
    def test_generate_and_download_report(self, auth_headers, auth_token, created_case):
        gen_res = client.post("/api/report", json={"case_id": created_case, "format": "pdf"}, headers=auth_headers)
        assert gen_res.status_code == 201
        report_data = gen_res.json()
        report_id = report_data["id"]
        assert report_data["filename"].endswith(".pdf")

        list_res = client.get(f"/api/report?case_id={created_case}", headers=auth_headers)
        assert list_res.status_code == 200
        items = list_res.json().get("items", [])
        assert any(r["id"] == report_id for r in items)

        dl_res = client.get(f"/api/report/download/{report_id}", headers=auth_headers)
        assert dl_res.status_code == 200
        assert dl_res.headers["content-type"] == "application/pdf"
        assert "attachment" in dl_res.headers.get("content-disposition", "")

        prev_res = client.get(f"/api/report/download/{report_id}?inline=true", headers=auth_headers)
        assert prev_res.status_code == 200
        assert prev_res.headers["content-type"] == "application/pdf"
        assert "inline" in prev_res.headers.get("content-disposition", "")

        token_res = client.get(f"/api/report/download/{report_id}?token={auth_token}&inline=true")
        assert token_res.status_code == 200
        assert token_res.headers["content-type"] == "application/pdf"

        unauth_res = client.get(f"/api/report/download/{report_id}")
        assert unauth_res.status_code == 401
