"""
SentinelX IDS - Authentication Routes

POST /auth/login    – Authenticate and receive JWT token (rate-limited)
POST /auth/register – Create a new user (admin required for elevated roles; forces viewer for non-admins)
GET  /auth/me       – Return the current user's profile
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.audit import audit
from backend.auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
)
from backend.database import get_db
from backend.models import AuditAction, User, UserRole
from backend.rate_limiter import login_rate_limiter
from backend.schemas import Token, UserCreate, UserLogin, UserResponse, UserRoleEnum

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=Token,
    summary="Login and get JWT token",
)
async def login(
    credentials: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Token:
    """Authenticate with username + password and receive a JWT token.

    Protected by sliding-window rate limiting to prevent brute-force attacks.
    """
    # Check rate limit before evaluating password
    login_rate_limiter.check(request, credentials.username)

    result = await db.execute(
        select(User).where(User.username == credentials.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(credentials.password, user.hashed_password):
        login_rate_limiter.record_failure(request, credentials.username)
        # Audit failed login attempt
        await audit(
            db,
            None,
            AuditAction.LOGIN_FAILED,
            resource_type="auth",
            resource_id=credentials.username,
            description=f"Failed login attempt for '{credentials.username}'",
            request=request,
            status="failure",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    # Successful login: reset throttle records
    login_rate_limiter.record_success(request, credentials.username)

    token = create_access_token(data={"sub": user.username, "role": user.role.value})
    await audit(
        db,
        user,
        AuditAction.LOGIN,
        resource_type="auth",
        description=f"User '{user.username}' logged in",
        request=request,
    )
    return Token(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Create a new user account.

    Only an authenticated administrator can create elevated accounts (admin, analyst).
    Ordinary registration forces the viewer role. Unauthenticated registration is rejected.
    """
    if current_user.role == UserRole.ADMIN:
        assigned_role = UserRole(user_in.role.value)
    else:
        if user_in.role != UserRoleEnum.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can assign elevated roles; ordinary registration forces the viewer role.",
            )
        assigned_role = UserRole.VIEWER

    # Check for duplicate username or email
    existing = await db.execute(
        select(User).where(
            (User.username == user_in.username) | (User.email == user_in.email)
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()
    await db.refresh(new_user)
    await audit(
        db,
        current_user,
        AuditAction.SYSTEM,
        resource_type="user",
        resource_id=new_user.username,
        description=f"Created new user '{new_user.username}' with role '{new_user.role.value}'",
        extra={"new_user_id": new_user.id, "role": new_user.role.value},
    )
    return UserResponse.model_validate(new_user)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    return UserResponse.model_validate(current_user)
