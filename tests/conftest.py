"""Pytest configuration and shared fixtures for SentinelX IDS tests."""

import sys
from pathlib import Path
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.auth import create_access_token
from backend.main import app


@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client bound to FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def admin_token() -> str:
    """Generate a valid JWT token for the admin user."""
    return create_access_token({"sub": "admin", "role": "admin"})


@pytest.fixture
def auth_headers(admin_token: str) -> dict[str, str]:
    """Authorization header dictionary for authenticated requests."""
    return {"Authorization": f"Bearer {admin_token}"}
