"""Tests for RBAC permission matrix, demo auth bypass removal, and login throttling."""

import pytest
from httpx import AsyncClient

from backend.rate_limiter import login_rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the login rate limiter before each test."""
    login_rate_limiter.reset()
    yield
    login_rate_limiter.reset()


@pytest.mark.asyncio
async def test_dashboard_requires_authentication(client: AsyncClient):
    """GET /api/dashboard MUST return 401 when unauthenticated (no demo bypass)."""
    resp = await client.get("/api/dashboard")
    assert resp.status_code == 401
    assert "Not authenticated" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_dashboard_accessible_with_token(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/dashboard returns 200 with valid token."""
    resp = await client.get("/api/dashboard", headers=auth_headers)
    assert resp.status_code == 200
    assert "metrics" in resp.json()


@pytest.mark.asyncio
async def test_unauthenticated_registration_rejected(client: AsyncClient):
    """POST /api/auth/register MUST return 401 when unauthenticated."""
    resp = await client.post(
        "/api/auth/register",
        json={
            "username": "audit_admin",
            "email": "audit@example.invalid",
            "password": "temporary-test-pass-123",
            "role": "admin",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_non_admin_cannot_create_admin(client: AsyncClient, viewer_headers: dict[str, str]):
    """Authenticated non-admin (viewer) cannot create an admin account (403 Forbidden)."""
    resp = await client.post(
        "/api/auth/register",
        headers=viewer_headers,
        json={
            "username": "rogue_admin",
            "email": "rogue@example.invalid",
            "password": "temporary-test-pass-123",
            "role": "admin",
        },
    )
    assert resp.status_code == 403
    assert "Only administrators can assign elevated roles" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_admin_can_create_user(client: AsyncClient, auth_headers: dict[str, str]):
    """Authenticated admin can register users with roles."""
    import uuid
    uid = uuid.uuid4().hex[:8]
    resp = await client.post(
        "/api/auth/register",
        headers=auth_headers,
        json={
            "username": f"analyst_{uid}",
            "email": f"analyst_{uid}@example.invalid",
            "password": "StrongPassword123!",
            "role": "analyst",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == f"analyst_{uid}"
    assert data["role"] == "analyst"


@pytest.mark.asyncio
async def test_role_matrix_viewer_forbidden_on_analyst_routes(
    client: AsyncClient, viewer_headers: dict[str, str]
):
    """Viewer role is forbidden on analyst/admin write routes."""
    # POST /api/rules requires admin or analyst
    resp = await client.post(
        "/api/rules",
        headers=viewer_headers,
        json={"name": "Test Rule", "severity": "medium", "pattern": "test.*pattern"},
    )
    assert resp.status_code == 403

    # POST /api/intel/iocs requires admin or analyst
    resp = await client.post(
        "/api/intel/iocs",
        headers=viewer_headers,
        json={"indicator_type": "ip", "indicator_value": "1.2.3.4", "threat_score": 80.0},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_role_matrix_analyst_forbidden_on_admin_routes(
    client: AsyncClient, analyst_headers: dict[str, str]
):
    """Analyst role is forbidden on admin-only routes."""
    # DELETE /api/rules/{id} requires admin
    resp = await client.delete("/api/rules/9999", headers=analyst_headers)
    assert resp.status_code == 403

    # DELETE /api/intel/iocs/{id} requires admin
    resp = await client.delete("/api/intel/iocs/9999", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_login_throttling_triggers_429(client: AsyncClient):
    """Submitting 5 consecutive failed logins triggers 429 Too Many Requests."""
    login_rate_limiter.reset()

    for i in range(5):
        resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": f"wrong-pass-{i}"},
        )
        assert resp.status_code == 401

    # 6th attempt should be blocked with 429
    blocked_resp = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-pass-6"},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert "Too many failed login attempts" in blocked_resp.json()["detail"]


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    """Responses include standard security headers."""
    resp = await client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin" in resp.headers.get("Referrer-Policy", "")
