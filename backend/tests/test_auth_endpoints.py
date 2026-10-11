import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_login_success_and_logout():
    # 1. Register a test user
    uid = uuid.uuid4().hex[:6]
    username = f"auth_user_{uid}"
    password = "Secur3Password!"
    reg_res = client.post("/api/auth/register", json={
        "username": username,
        "full_name": "Test Investigator",
        "password": password,
        "role": "investigator",
    })
    assert reg_res.status_code == 201

    # 2. Login with bad credentials
    bad_login = client.post("/api/auth/login", json={
        "username": username,
        "password": "WrongPassword123!"
    })
    assert bad_login.status_code == 401

    # 3. Login with correct credentials
    login_res = client.post("/api/auth/login", json={
        "username": username,
        "password": password
    })
    assert login_res.status_code == 200
    tokens = login_res.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    # 4. Access /api/users/me using access token
    me_res = client.get("/api/users/me", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    assert me_res.status_code == 200
    user_info = me_res.json()
    assert user_info["username"] == username
    assert user_info["role"] == "investigator"

    # 5. Logout with refresh token
    logout_res = client.post("/api/auth/logout", json={
        "refresh_token": tokens["refresh_token"]
    })
    assert logout_res.status_code == 200

    # 6. Attempting to refresh after logout should fail (401)
    revoked_refresh = client.post("/api/auth/refresh", json={
        "refresh_token": tokens["refresh_token"]
    })
    assert revoked_refresh.status_code == 401
