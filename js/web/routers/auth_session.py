"""Auth session cookie exchange — extracted from ``js.web.server``."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from js.exceptions import AuthRequiredError
from js.web.auth import (
    _SESSION_COOKIE,
    _SESSION_TTL_SECONDS,
    AuthManager,
    check_origin,
    resolve_session_cookie,
    session_cookie_name,
)

router = APIRouter(tags=["auth"])


def _request_settings(request: Request) -> Any:
    runtime = getattr(request.app.state, "runtime_settings", None)
    if runtime is not None:
        return runtime
    from js.web.server import _settings

    return _settings


@router.post("/api/auth/session")
async def create_auth_session(request: Request) -> JSONResponse:
    """Exchange a valid API key for an HttpOnly session cookie.

    The key may arrive via the X-API-Key header or a JSON body
    (``{"api_key": ...}``).  The returned cookie carries a random token;
    only its hash is stored server-side, with an expiry, and it can be
    revoked via /api/auth/logout (or by revoking the underlying key).
    """
    check_origin(request)
    settings = _request_settings(request)
    if settings is None:
        raise HTTPException(
            503, "Server is still starting up. Please wait a moment and try again."
        )
    api_key = request.headers.get("x-api-key")
    if not api_key:
        try:
            body = await request.json()
        except Exception:
            body = None
        if isinstance(body, dict):
            body_key = body.get("api_key")
            if isinstance(body_key, str):
                api_key = body_key
    try:
        token, expires_at = AuthManager(settings.state_dir).create_session(api_key)
    except AuthRequiredError as exc:
        raise HTTPException(401, str(exc), headers={"WWW-Authenticate": "Bearer"}) from exc
    cookie_name = session_cookie_name(
        str(getattr(settings, "product_id", "js-agent") or "js-agent")
    )
    response = JSONResponse({"success": True, "expires_at": expires_at})
    response.set_cookie(
        cookie_name,
        token,
        max_age=_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    # Drop the pre-AppShell host-wide cookie so a stale Personal/Work token
    # cannot keep failing closed as "Invalid session" / HTTP 401.
    if cookie_name != _SESSION_COOKIE:
        response.delete_cookie(_SESSION_COOKIE, path="/")
    return response


@router.post("/api/auth/logout")
async def revoke_auth_session(request: Request) -> JSONResponse:
    """Revoke the current session server-side and clear the cookie."""
    check_origin(request)
    settings = _request_settings(request)
    product_id = (
        str(getattr(settings, "product_id", "js-agent") or "js-agent")
        if settings is not None
        else "js-agent"
    )
    cookie_name = session_cookie_name(product_id)
    token = resolve_session_cookie(request.cookies, product_id)
    if settings is not None and token:
        AuthManager(settings.state_dir).revoke_session(token)
    response = JSONResponse({"success": True})
    response.delete_cookie(cookie_name, path="/")
    # Also clear the legacy unscoped cookie so Personal migrations don't
    # leave a stale host-wide token that Work would ignore but confuse UX.
    if cookie_name != _SESSION_COOKIE:
        response.delete_cookie(_SESSION_COOKIE, path="/")
    return response
