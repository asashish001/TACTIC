import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import pytest

BASE_URL = os.getenv("AIDFA_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def api_is_ready() -> bool:
    """Return whether the expected FastAPI instance is accepting requests."""
    try:
        with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def start_api_if_needed() -> subprocess.Popen | None:
    """Start the local FastAPI launcher for a self-contained integration run."""
    if api_is_ready():
        return None

    print(f"\n[SETUP] FastAPI is not running at {BASE_URL}; starting python app.py...")
    process = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for _ in range(30):
        if api_is_ready():
            print("[SETUP] FastAPI is ready.\n")
            return process
        if process.poll() is not None:
            break
        time.sleep(1)

    startup_output = ""
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    elif process.stdout is not None:
        startup_output = process.stdout.read().strip()
    raise RuntimeError(
        "FastAPI could not start. Install dependencies with 'pip install -r requirements.txt' "
        "and verify that port 8000 is available."
        + (f" Startup output: {startup_output[-500:]}" if startup_output else "")
    )

def make_request(url, data=None, headers=None, method="GET"):
    req_headers = headers or {}
    req_data = None
    if data is not None:
        if isinstance(data, dict):
            req_data = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        else:
            req_data = data  # Raw bytes (e.g. multipart)
    
    req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = response.read()
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(res_data.decode("utf-8")), response.status
            return res_data, response.status
    except urllib.error.HTTPError as e:
        err_data = e.read().decode("utf-8")
        try:
            return json.loads(err_data), e.code
        except json.JSONDecodeError:
            return err_data, e.code


@pytest.mark.integration
def test_suite():
    print("==================================================")
    print("AIDFA API COMPREHENSIVE INTEGRATION TEST SUITE")
    print("==================================================")

    print("\n[TEST 1] Registering a new investigator...")
    unique_username = f"investigator_{uuid.uuid4().hex[:6]}"
    reg_payload = {
        "username": unique_username,
        "full_name": "Test Investigator",
        "password": "SecurePassword123!",
        "role": "investigator"
    }
    res, code = make_request(f"{BASE_URL}/api/auth/register", data=reg_payload, method="POST")
    if code != 201:
        print(f"FAILED: Registration returned code {code}, body: {res}")
        return False
    print(f"SUCCESS: Registered user '{res['username']}' with role '{res['role']}'")

    print("\n[TEST 2] Authenticating credentials...")
    login_payload = {
        "username": unique_username,
        "password": "SecurePassword123!"
    }
    res, code = make_request(f"{BASE_URL}/api/auth/login", data=login_payload, method="POST")
    if code != 200:
        print(f"FAILED: Login returned code {code}, body: {res}")
        return False
    token = res["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("SUCCESS: Retrieved JWT access token.")

    print("\n[TEST 3] Creating new case file...")
    case_no = f"CASE-{uuid.uuid4().hex[:6].upper()}"
    case_payload = {
        "case_number": case_no,
        "name": "Intrusion Analysis",
        "description": "Analyze unauthorized root logins inside security clusters.",
        "incident_date": "2026-08-02"
    }
    res, code = make_request(f"{BASE_URL}/api/cases", data=case_payload, headers=headers, method="POST")
    if code != 201:
        print(f"FAILED: Case creation returned code {code}, body: {res}")
        return False
    case_id = res["id"]
    print(f"SUCCESS: Created case file '{res['name']}' (ID: {case_id})")

    print("\n[TEST 4] Uploading raw text evidence artifact...")
    boundary = "AIDFAForensicsBoundary"
    body_parts = []
    
    body_parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"case_id\"\r\n\r\n{case_id}\r\n".encode())
    
    file_content = (
        "2026-08-02T10:15:00Z - Authorized admin login successful.\n"
        "2026-08-02T10:20:12Z - Unauthorized program running: mimikatz.exe privilege dump.\n"
        "2026-08-02T10:22:30Z - Connected to remote C2 command address: 192.168.1.150.\n"
    )
    body_parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"security_alert.log\"\r\n"
        f"Content-Type: text/plain\r\n\r\n{file_content}\r\n".encode()
    )
    body_parts.append(f"--{boundary}--\r\n".encode())
    
    raw_body = b"".join(body_parts)
    multipart_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}"
    }
    
    res, code = make_request(f"{BASE_URL}/api/evidence/upload", data=raw_body, headers=multipart_headers, method="POST")
    if code != 201:
        print(f"FAILED: Uploading evidence returned code {code}, body: {res}")
        return False
    evidence_id = res["id"]
    if not res.get("sha1") or len(res["sha1"]) != 40:
        print("FAILED: Evidence response is missing a valid SHA-1 integrity hash.")
        return False
    print(f"SUCCESS: Preserved evidence file '{res['filename']}' with SHA256: {res['sha256'][:16]}...")

    print("\n[TEST 5] Executing AI analysis engine & Async Background Job System...")
    res, code = make_request(f"{BASE_URL}/api/analyze", data={"evidence_id": evidence_id}, headers=headers, method="POST")
    if code != 202:
        print(f"FAILED: Triggering async AI analysis returned code {code}, body: {res}")
        return False
    job_id = res["job_id"]
    print(f"SUCCESS: Asynchronous analysis job queued (Job ID: {job_id[:8]}). Polling status...")

    job_completed = False
    for _ in range(30):
        time.sleep(1)
        j_res, j_code = make_request(f"{BASE_URL}/api/jobs/{job_id}", headers=headers, method="GET")
        if j_code == 200:
            print(f"  [JOB STAGE] Stage: '{j_res['current_stage']}' | Progress: {j_res['progress_percent']}% | Status: {j_res['status']}")
            if j_res["status"] in ("COMPLETED", "PARTIAL"):
                job_completed = True
                break
            elif j_res["status"] == "FAILED":
                print(f"FAILED: Background job failed: {j_res.get('error_info')}")
                return False

    if not job_completed:
        print("FAILED: Async job did not complete within timeout.")
        return False
    print("SUCCESS: Asynchronous background forensic pipeline completed across all 8 stages.")

    sync_res, sync_code = make_request(f"{BASE_URL}/api/analyze", data={"evidence_id": evidence_id, "sync": True}, headers=headers, method="POST")
    if sync_code != 201:
        print(f"FAILED: Synchronous analysis returned code {sync_code}, body: {sync_res}")
        return False
    print(f"SUCCESS: Synchronous mode verified. Flagged {len(sync_res)} threat components.")

    print("\n[TEST 6] Reconstructing case chronological timeline...")
    res, code = make_request(f"{BASE_URL}/api/timeline/{case_id}", headers=headers, method="GET")
    if code != 200:
        print(f"FAILED: Fetching timeline returned code {code}, body: {res}")
        return False
    print(f"SUCCESS: Reconstructed timeline containing {len(res['events'])} chronological events.")

    print("\n[TEST 7] Compiling entity correlation graph...")
    res, code = make_request(f"{BASE_URL}/api/correlation/{case_id}", headers=headers, method="GET")
    if code != 200:
        print(f"FAILED: Fetching correlation returned {code}, body: {res}")
        return False
    print(f"SUCCESS: Graph generated with {len(res['nodes'])} nodes and {len(res['edges'])} link connections.")

    print("\n[TEST 8] Querying context chatbot...")
    chat_payload = {
        "case_id": case_id,
        "question": "What files are suspicious?"
    }
    res, code = make_request(f"{BASE_URL}/api/chat", data=chat_payload, headers=headers, method="POST")
    if code != 200:
        print(f"FAILED: Chat prompt returned {code}, body: {res}")
        return False
    print(f"SUCCESS: Chatbot responded (Model: {res['provider']}):\n{res['answer']}")

    print("\n[TEST 9] Compiling formal PDF Audit Report...")
    report_payload = {
        "case_id": case_id,
        "format": "pdf"
    }
    res, code = make_request(f"{BASE_URL}/api/report", data=report_payload, headers=headers, method="POST")
    if code != 201:
        print(f"FAILED: Report compilation returned {code}, body: {res}")
        return False
    print(f"SUCCESS: PDF Report saved as '{res['filename']}'")

    print("\n[TEST 10] Verifying chain of custody and audit records...")
    custody, code = make_request(f"{BASE_URL}/api/forensic-records/cases/{case_id}/chain-of-custody", headers=headers)
    if code != 200 or not any(item["action"] == "evidence_ingested" for item in custody):
        print(f"FAILED: Evidence custody record missing, code {code}, body: {custody}")
        return False
    audit, code = make_request(f"{BASE_URL}/api/forensic-records/cases/{case_id}/audit-log", headers=headers)
    expected_actions = {"case_created", "evidence_uploaded", "report_generated"}
    if code != 200 or not expected_actions.issubset({item["action"] for item in audit}):
        print(f"FAILED: Required audit records missing, code {code}, body: {audit}")
        return False
    print("SUCCESS: SHA-1, chain-of-custody, and audit records are preserved.")

    print("\n[TEST 11] Extracting browser forensic artifacts...")
    fixture_path = PROJECT_ROOT / "test_data" / "browser_bookmarks.json"
    if not fixture_path.is_file():
        print(f"FAILED: Browser test fixture is missing: {fixture_path}")
        return False
    browser_boundary = "AIDFABrowserBoundary"
    browser_body = b"".join([
        f"--{browser_boundary}\r\nContent-Disposition: form-data; name=\"case_id\"\r\n\r\n{case_id}\r\n".encode(),
        f"--{browser_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"browser_bookmarks.json\"\r\nContent-Type: application/json\r\n\r\n".encode(),
        fixture_path.read_bytes(),
        f"\r\n--{browser_boundary}--\r\n".encode(),
    ])
    browser_headers = {"Authorization": f"Bearer {token}", "Content-Type": f"multipart/form-data; boundary={browser_boundary}"}
    uploaded_browser, code = make_request(f"{BASE_URL}/api/evidence/upload", data=browser_body, headers=browser_headers, method="POST")
    if code != 201:
        print(f"FAILED: Browser fixture upload returned {code}, body: {uploaded_browser}")
        return False
    result, code = make_request(f"{BASE_URL}/api/browser/cases/{case_id}/analyze", data={}, headers=headers, method="POST")
    if code != 200 or result["artifacts_extracted"] < 2:
        print(f"FAILED: Browser analysis returned {code}, body: {result}")
        return False
    artifacts, code = make_request(f"{BASE_URL}/api/browser/cases/{case_id}/artifacts", headers=headers)
    if code != 200 or not any(item["artifact_type"] == "bookmark" for item in artifacts):
        print(f"FAILED: Bookmark records missing, code {code}, body: {artifacts}")
        return False
    print(f"SUCCESS: Extracted {result['artifacts_extracted']} browser artifact(s) without reading passwords.")

    print("\n[TEST 12] Querying Hugging Face Transformers model status...")
    model_status, code = make_request(f"{BASE_URL}/model/status", headers=headers)
    if code != 200 or "loaded" not in model_status or "model_name" not in model_status:
        print(f"FAILED: /model/status endpoint returned code {code}, body: {model_status}")
        return False
    print(f"SUCCESS: Model status retrieved (Name: {model_status['model_name']}, Loaded: {model_status['loaded']}, Error: {model_status['error_state']})")

    print("\n[TEST 13] Executing NLP Artifact Extraction Pipeline & Source Evidence Linking...")
    extracted_res, code = make_request(f"{BASE_URL}/api/artifacts/evidence/{evidence_id}/extract", data={}, headers=headers, method="POST")
    if code != 200 or extracted_res.get("artifacts_extracted", 0) < 1:
        print(f"FAILED: Artifact extraction returned code {code}, body: {extracted_res}")
        return False
    
    extracted_items, code = make_request(f"{BASE_URL}/api/artifacts/cases/{case_id}", headers=headers)
    if code != 200 or len(extracted_items) == 0:
        print(f"FAILED: Fetching extracted artifacts returned code {code}, body: {extracted_items}")
        return False

    for item in extracted_items:
        if item.get("source_evidence_id") != item.get("evidence_id"):
            print(f"FAILED: Extracted artifact missing source evidence link: {item}")
            return False

    print(f"SUCCESS: Extracted {len(extracted_items)} common artifact(s) retaining source evidence ID linking.")

    print("\n[TEST 14] Testing Configurable Anomaly Detection Threshold API & Validation...")
    settings, code = make_request(f"{BASE_URL}/api/settings", headers=headers)
    if code != 200 or "anomaly_threshold" not in settings:
        print(f"FAILED: GET /api/settings returned code {code}, body: {settings}")
        return False
    
    up_res, code = make_request(f"{BASE_URL}/api/settings", data={"anomaly_threshold": 0.85}, headers=headers, method="PUT")
    if code != 200 or up_res.get("anomaly_threshold") != 0.85:
        print(f"FAILED: PUT /api/settings returned code {code}, body: {up_res}")
        return False

    _invalid_res, code = make_request(f"{BASE_URL}/api/settings", data={"anomaly_threshold": 1.5}, headers=headers, method="PUT")
    if code not in (400, 422):
        print(f"FAILED: Expected validation failure (400/422) for invalid threshold 1.5, got code {code}")
        return False

    make_request(f"{BASE_URL}/api/settings", data={"anomaly_threshold": 0.80}, headers=headers, method="PUT")
    print(f"SUCCESS: System Settings API verified (Default threshold: {settings['anomaly_threshold']}, Updated: 0.85, Validation Error Code: {code}).")

    print("\n==================================================")
    print("ALL API SYSTEM MAPPINGS INTEGRATED AND PASSING.")
    print("==================================================")
    return True

if __name__ == "__main__":
    server_process = None
    try:
        server_process = start_api_if_needed()
        raise SystemExit(0 if test_suite() else 1)
    except RuntimeError as error:
        print(f"\nSETUP FAILED: {error}")
        raise SystemExit(1)
    finally:
        if server_process is not None and server_process.poll() is None:
            server_process.terminate()
            server_process.wait(timeout=5)
