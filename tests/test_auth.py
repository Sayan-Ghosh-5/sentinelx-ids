"""Tests for authentication, JWT handling, and RBAC."""

import pytest
from httpx import AsyncClient
import jwt

from backend.auth import (
    create_access_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from backend.config import settings


def test_password_hashing():
    """Verify password hashing generates verifiable bcrypt hashes."""
    pwd = "SecretPassword123!"
    hashed = get_password_hash(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_creation_and_verification():
    """Verify JWT access token contains expected claims and decodes."""
    payload = {"sub": "analyst_bob", "role": "analyst"}
    token = create_access_token(payload)

    decoded = verify_token(token)
    assert decoded["sub"] == "analyst_bob"
    assert "exp" in decoded


@pytest.mark.asyncio
async def test_auth_me_endpoint(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/auth/me returns current user profile for authenticated requests."""
    resp = await client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "admin"
    assert "email" in data
    assert "role" in data


@pytest.mark.asyncio
async def test_auth_me_unauthorized(client: AsyncClient):
    """GET /api/auth/me returns 401 with invalid credentials when demo mode is bypassed."""
    resp = await client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_auth_login_invalid(client: AsyncClient):
    """POST /api/auth/login returns 401 for incorrect credentials."""
    resp = await client.post(
        "/api/auth/login",
        json={"username": "non_existent_user_999", "password": "WrongPassword!"},
    )
    assert resp.status_code == 401
    assert "Invalid username or password" in resp.json()["detail"]

