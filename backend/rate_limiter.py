"""
SentinelX IDS - Authentication Rate Limiter

Provides in-memory sliding-window throttling for login attempts to protect
against brute-force and credential-stuffing attacks.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request, status


class LoginRateLimiter:
    """Sliding-window rate limiter for login requests."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 60,
        lockout_seconds: int = 300,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}
        self._lock = Lock()

    def _get_keys(self, request: Request, username: Optional[str] = None) -> list[str]:
        client_ip = request.client.host if request.client else "127.0.0.1"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        keys = [f"ip:{client_ip}"]
        if username:
            keys.append(f"user:{username.lower().strip()}")
        return keys

    def check(self, request: Request, username: Optional[str] = None) -> None:
        """Check if the client IP or username is locked out or exceeded rate limits."""
        now = time.time()
        keys = self._get_keys(request, username)
        with self._lock:
            for key in keys:
                lockout_until = self._lockouts.get(key, 0)
                if now < lockout_until:
                    retry_after = int(lockout_until - now) + 1
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many failed login attempts. Temporarily locked out.",
                        headers={"Retry-After": str(retry_after)},
                    )

                # Clean expired attempts
                self._attempts[key] = [
                    t for t in self._attempts[key] if now - t < self.window_seconds
                ]
                if len(self._attempts[key]) >= self.max_attempts:
                    self._lockouts[key] = now + self.lockout_seconds
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many failed login attempts. Please try again later.",
                        headers={"Retry-After": str(self.lockout_seconds)},
                    )

    def record_failure(self, request: Request, username: Optional[str] = None) -> None:
        """Record a failed login attempt."""
        now = time.time()
        keys = self._get_keys(request, username)
        with self._lock:
            for key in keys:
                self._attempts[key].append(now)
                if len(self._attempts[key]) >= self.max_attempts:
                    self._lockouts[key] = now + self.lockout_seconds

    def record_success(self, request: Request, username: Optional[str] = None) -> None:
        """Clear recorded failures upon successful authentication."""
        keys = self._get_keys(request, username)
        with self._lock:
            for key in keys:
                self._attempts.pop(key, None)
                self._lockouts.pop(key, None)

    def reset(self) -> None:
        """Reset all rate limiter records (useful for test suites)."""
        with self._lock:
            self._attempts.clear()
            self._lockouts.clear()


login_rate_limiter = LoginRateLimiter(
    max_attempts=5, window_seconds=60, lockout_seconds=300
)

