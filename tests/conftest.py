"""Pytest configuration and shared fixtures for SentinelX IDS tests."""

import sys
from pathlib import Path
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.auth import create_access_token, get_password_hash
from backend.database import async_session
from backend.main import app
from backend.models import User, UserRole


@pytest.fixture(autouse=True)
async def seed_test_users():
    """Seed test accounts (admin, analyst, viewer) into test database."""
    async with async_session() as session:
        # Admin
        res = await session.execute(select(User).where(User.username == "admin"))
        if not res.scalar_one_or_none():
            admin = User(
                username="admin",
                email="admin@sentinelx.local",
                hashed_password=get_password_hash("test-admin-pass-123"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            session.add(admin)

        # Analyst
        res = await session.execute(select(User).where(User.username == "analyst_user"))
        if not res.scalar_one_or_none():
            analyst = User(
                username="analyst_user",
                email="analyst@sentinelx.local",
                hashed_password=get_password_hash("test-analyst-pass-123"),
                role=UserRole.ANALYST,
                is_active=True,
            )
            session.add(analyst)

        # Viewer
        res = await session.execute(select(User).where(User.username == "viewer_user"))
        if not res.scalar_one_or_none():
            viewer = User(
                username="viewer_user",
                email="viewer@sentinelx.local",
                hashed_password=get_password_hash("test-viewer-pass-123"),
                role=UserRole.VIEWER,
                is_active=True,
            )
            session.add(viewer)

        await session.commit()


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
def analyst_token() -> str:
    """Generate a valid JWT token for an analyst user."""
    return create_access_token({"sub": "analyst_user", "role": "analyst"})


@pytest.fixture
def viewer_token() -> str:
    """Generate a valid JWT token for a viewer user."""
    return create_access_token({"sub": "viewer_user", "role": "viewer"})


@pytest.fixture
def auth_headers(admin_token: str) -> dict[str, str]:
    """Authorization header dictionary for admin requests."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token: str) -> dict[str, str]:
    """Authorization header dictionary for analyst requests."""
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token: str) -> dict[str, str]:
    """Authorization header dictionary for viewer requests."""
    return {"Authorization": f"Bearer {viewer_token}"}
