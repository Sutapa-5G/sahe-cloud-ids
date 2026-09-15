"""
backend/app/api/auth.py

Authentication dependency for protected endpoints (crypto operations,
firewall actions), per the Phase 0 review requirement: "Add a future
authentication layer for protected FastAPI endpoints, especially
encryption/decryption and firewall operations."

This is a STUB implementation: a single shared bearer token, read from
config. It is NOT a production-grade auth system (no per-user identity,
no token expiry, no OAuth/JWT). It exists so that:

  1. Protected routes are never left open by omission during
     development — every sensitive route has a real dependency
     enforcing SOMETHING from the start.
  2. The interface (a FastAPI dependency raising HTTPException on
     failure) is established now, so swapping in a real auth system
     later (JWT, OAuth2, per-user API keys) is a localized change to
     this one file plus route dependencies, not a redesign.

FAILS CLOSED: if `api_auth_token` is not configured (None, the default),
every request to a protected route is rejected with 503, not silently
allowed through. An unconfigured deployment must not be an open
deployment.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, status, Depends

from backend.app.config import Settings, get_settings


async def require_auth(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    """
    FastAPI dependency. Usage: `@router.post(..., dependencies=[Depends(require_auth)])`
    or as a parameter: `async def route(_: None = Depends(require_auth))`.

    Expects `Authorization: Bearer <token>` matching `settings.api_auth_token`.
    """
    if settings.api_auth_token is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication is not configured for this deployment "
                "(api_auth_token is unset). Protected endpoints are "
                "disabled until this is configured, rather than being "
                "left open."
            ),
        )

    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: Bearer <token>",
        )

    token = authorization.removeprefix("Bearer ").strip()
    if token != settings.api_auth_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
