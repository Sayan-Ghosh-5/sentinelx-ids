"""
SentinelX IDS - JWT Authentication Module

Provides password hashing, JWT token creation / verification using PyJWT,
FastAPI dependencies for extracting the current user and enforcing
role-based access control, and opt-in demo administrator seeding.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import bcrypt
import jwt
from jwt.exceptions import PyJWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import async_session, get_db
from backend.models import User, UserRole

logger = logging.getLogger("sentinelx.auth")

# ── OAuth2 Scheme ────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


# ═══════════════════════════════════════════════════════════════════════════
# Password helpers
# ═══════════════════════════════════════════════════════════════════════════

def get_password_hash(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return ``True`` if *plain_password* matches the *hashed_password*."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ═══════════════════════════════════════════════════════════════════════════
# JWT helpers
# ═══════════════════════════════════════════════════════════════════════════

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT access token.

    Parameters
    ----------
    data:
        Payload claims – must include at least ``{"sub": "<username>"}``.
    expires_delta:
        Custom TTL. Falls back to ``ACCESS_TOKEN_EXPIRE_MINUTES`` from settings.

    Returns
    -------
    str
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str) -> dict:
    """Decode and validate a JWT token.

    Raises
    ------
    HTTPException(401)
        If the token is missing, expired, or otherwise invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except PyJWTError:
        raise credentials_exception


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI dependencies
# ═══════════════════════════════════════════════════════════════════════════

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract the current authenticated user from the Bearer token.

    Authentication is strictly required for all protected routes, including
    in demo mode.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token)
    username: str = payload["sub"]

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )
    return user


def require_role(allowed_roles: List[str]):
    """Dependency factory: restrict access to users whose role is in *allowed_roles*.

    Usage::

        @router.post("/admin-only", dependencies=[Depends(require_role(["admin"]))])
        async def admin_endpoint(): ...

    Or inject the user directly::

        @router.get("/data")
        async def get_data(user: User = Depends(require_role(["admin", "analyst"]))):
            ...
    """

    async def _role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role.value not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role(s): {', '.join(allowed_roles)}",
            )
        return current_user

    return _role_checker


# ═══════════════════════════════════════════════════════════════════════════
# Demo seed (Opt-in only with unique password)
# ═══════════════════════════════════════════════════════════════════════════

async def seed_demo_user() -> None:
    """Create a demo admin user ONLY if explicitly opted in via ENABLE_DEMO_ADMIN."""
    if not settings.ENABLE_DEMO_ADMIN:
        logger.info("Demo administrator seeding disabled (ENABLE_DEMO_ADMIN=false)")
        return

    password = settings.DEMO_ADMIN_PASSWORD
    if not password or password == "sentinelx" or len(password) < 8:
        logger.warning(
            "ENABLE_DEMO_ADMIN is true but DEMO_ADMIN_PASSWORD is empty, insecure ('sentinelx'), or too short (< 8 chars). Skipping demo admin seed."
        )
        return

    async with async_session() as session:
        result = await session.execute(
            select(User).where(User.username == settings.DEMO_ADMIN_USERNAME)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return

        admin = User(
            username=settings.DEMO_ADMIN_USERNAME,
            email=f"{settings.DEMO_ADMIN_USERNAME}@sentinelx.local",
            hashed_password=get_password_hash(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        logger.info("Created opt-in demo administrator '%s'", settings.DEMO_ADMIN_USERNAME)
