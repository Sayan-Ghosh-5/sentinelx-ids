"""Integration tests for REST API endpoints (Rules, Alerts, Logs, Dashboard)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_dashboard_summary(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/dashboard returns aggregate metrics."""
    resp = await client.get("/api/dashboard", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_logs" in data
    assert "total_alerts" in data
    assert "active_rules" in data


@pytest.mark.asyncio
async def test_get_rules_list(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/rules returns list of seeded detection rules."""
    resp = await client.get("/api/rules", headers=auth_headers)
    assert resp.status_code == 200
    rules = resp.json()
    assert isinstance(rules, list)
    assert len(rules) > 0
    rule = rules[0]
    assert "name" in rule
    assert "severity" in rule
    assert "pattern" in rule


@pytest.mark.asyncio
async def test_create_and_toggle_rule(client: AsyncClient, auth_headers: dict[str, str]):
    """POST /api/rules creates a rule and PATCH toggles its status."""
    new_rule = {
        "name": "Test Port 1337 Backdoor",
        "description": "Detects backdoor traffic on port 1337",
        "category": "Command and Control",
        "severity": "critical",
        "pattern": r"port 1337",
        "enabled": True,
    }
    create_resp = await client.post("/api/rules", json=new_rule, headers=auth_headers)
    assert create_resp.status_code in (201, 409)

    if create_resp.status_code == 201:
        rule_data = create_resp.json()
        rule_id = rule_data["id"]
        assert rule_data["name"] == new_rule["name"]

        # Toggle rule to disabled
        patch_resp = await client.patch(
            f"/api/rules/{rule_id}",
            json={"enabled": False},
            headers=auth_headers,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_get_logs_pagination(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/logs returns paginated log entries with total count."""
    resp = await client.get("/api/logs?page=1&page_size=10", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.asyncio
async def test_get_alerts_pagination(client: AsyncClient, auth_headers: dict[str, str]):
    """GET /api/alerts returns paginated alerts."""
    resp = await client.get("/api/alerts?page=1&page_size=10", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data

