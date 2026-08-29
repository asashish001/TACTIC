"""Tests for refresh token rotation security.

Verifies:
  1. Successful rotation issues new tokens and invalidates the old refresh token
  2. Reusing an old refresh token is rejected (401)
  3. Reuse detection clears ALL refresh tokens (theft mitigation)
  4. Increasing token_version on the user invalidates all existing tokens
"""
import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import SessionLocal
from app.models.user import User

client = TestClient(app)


@pytest.fixture()
def registered_user():
    """Register a fresh user and return (username, password)."""
    username = f"rottest_{uuid.uuid4().hex[:6]}"
    password = "StrongPass123!"
    res = client.post("/api/auth/register", json={
        "username": username,
        "full_name": "Rotation Test User",
        "password": password,
        "role": "investigator",
    })
    assert res.status_code == 201
    return username, password


@pytest.fixture()
def login_pair(registered_user):
    """Login and return (access_token, refresh_token)."""
    username, password = registered_user
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    data = res.json()
    return data["access_token"], data["refresh_token"]


class TestRefreshTokenRotation:
    """Verify that refresh token rotation works end-to-end."""

    def test_first_refresh_succeeds(self, login_pair):
        """A valid refresh token can be used once to get new tokens."""
        _, refresh = login_pair
        res = client.post("/api/auth/refresh", json={"refresh_token": refresh})
        assert res.status_code == 200
        body = res.json()
        assert "access_token" in body
        assert "refresh_token" in body
        # The new refresh token should be different from the old one
        assert body["refresh_token"] != refresh

    def test_old_token_rejected_after_rotation(self, login_pair):
        """After a successful refresh, the old token must not work again."""
        _, refresh_old = login_pair
        # Rotate once
        res1 = client.post("/api/auth/refresh", json={"refresh_token": refresh_old})
        assert res1.status_code == 200

        # Try reusing the old token
        res2 = client.post("/api/auth/refresh", json={"refresh_token": refresh_old})
        assert res2.status_code == 401
        assert "already been used" in res2.json()["detail"].lower()

    def test_chained_rotations(self, login_pair):
        """Multiple consecutive rotations should work if each uses the latest token."""
        _, refresh = login_pair
        for i in range(3):
            res = client.post("/api/auth/refresh", json={"refresh_token": refresh})
            assert res.status_code == 200, f"Rotation {i+1} failed"
            refresh = res.json()["refresh_token"]

    def test_theft_detection_clears_all_tokens(self, login_pair):
        """If an old token is reused (theft), ALL refresh tokens for that user are invalidated."""
        _, refresh_a = login_pair

        # Rotate once → get refresh_b
        res1 = client.post("/api/auth/refresh", json={"refresh_token": refresh_a})
        assert res1.status_code == 200
        refresh_b = res1.json()["refresh_token"]

        # Reuse refresh_a → triggers theft detection
        res2 = client.post("/api/auth/refresh", json={"refresh_token": refresh_a})
        assert res2.status_code == 401

        # refresh_b should now also be invalid (all tokens cleared)
        res3 = client.post("/api/auth/refresh", json={"refresh_token": refresh_b})
        assert res3.status_code == 401

    def test_re_login_after_theft_clear(self, registered_user):
        """After theft detection clears tokens, the user can re-login successfully."""
        username, password = registered_user

        # Login → get token_a
        res = client.post("/api/auth/login", json={"username": username, "password": password})
        refresh_a = res.json()["refresh_token"]

        # Rotate → get token_b
        res = client.post("/api/auth/refresh", json={"refresh_token": refresh_a})
        refresh_b = res.json()["refresh_token"]

        # Reuse token_a → triggers theft detection (clears all)
        client.post("/api/auth/refresh", json={"refresh_token": refresh_a})

        # Re-login should work
        res = client.post("/api/auth/login", json={"username": username, "password": password})
        assert res.status_code == 200
        assert "refresh_token" in res.json()


class TestTokenVersionRevocation:
    """Verify that changing token_version invalidates all existing tokens."""

    def test_access_token_rejected_after_version_bump(self):
        """If token_version is bumped, all existing access tokens are rejected."""
        from app.auth.security import create_access_token, get_password_hash

        # Create user directly in DB to avoid rate limits
        username = f"vtest_{uuid.uuid4().hex[:6]}"
        db = SessionLocal()
        try:
            user = User(
                username=username,
                full_name="Version Test",
                password_hash=get_password_hash("Pass123!"),
                role="investigator",
                token_version=0,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            user_id = user.id
        finally:
            db.close()

        # Issue an access token at version 0
        access = create_access_token({
            "sub": username, "user_id": user_id,
            "role": "investigator", "token_version": 0,
        })

        # Verify it works
        res = client.get("/api/users/me", headers={"Authorization": f"Bearer {access}"})
        assert res.status_code == 200

        # Bump token_version in the database (simulates password change)
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            user.token_version = 1
            db.commit()
        finally:
            db.close()

        # The old access token should now be rejected
        res = client.get("/api/users/me", headers={"Authorization": f"Bearer {access}"})
        assert res.status_code == 401

    def test_refresh_token_rejected_after_version_bump(self):
        """If token_version is bumped, all refresh tokens are also rejected."""
        from app.auth.security import create_refresh_token, get_password_hash

        # Create user directly in DB to avoid rate limits
        username = f"vtest_{uuid.uuid4().hex[:6]}"
        db = SessionLocal()
        try:
            user = User(
                username=username,
                full_name="Version Test 2",
                password_hash=get_password_hash("Pass123!"),
                role="investigator",
                token_version=0,
                refresh_token_jtis="[]",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            user_id = user.id
        finally:
            db.close()

        # Issue a refresh token at version 0
        refresh = create_refresh_token({
            "sub": username, "user_id": user_id,
            "role": "investigator", "token_version": 0,
        })

        # Bump token_version
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            user.token_version = 1
            db.commit()
        finally:
            db.close()

        # The old refresh token should be rejected
        res = client.post("/api/auth/refresh", json={"refresh_token": refresh})
        assert res.status_code == 401
        assert "revoked" in res.json()["detail"].lower()
