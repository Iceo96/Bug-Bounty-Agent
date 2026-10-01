"""Safe, non-secret authentication signals.

Two independent, secret-free ways to reason about whether a browser session is
authenticated:

1. ``request_is_authenticated`` — inspects only request header *names* (never
   values). An auth header being present (Cookie/Authorization/VerifyAuthToken/...)
   means the request carried credentials; the value is irrelevant and never read.

2. ``page_login_signal`` — a heuristic over visible page/UI text only (a login
   form / "sign in" control vs an "account"/"sign out" control). It reads rendered
   HTML markup, never cookies, tokens, localStorage, or sessionStorage.

Neither function stores or returns any secret material.
"""

from __future__ import annotations

# Auth header NAMES (lower-cased). Presence of any of these names — regardless of
# value — marks a request as credentialed.
AUTH_HEADER_NAMES = {
    "authorization", "cookie", "verifyauthtoken", "x-verify-auth-token",
    "x-api-key", "x-auth-token", "proxy-authorization",
}

_LOGGED_OUT_MARKERS = (
    "sign in", "sign-in", "signin", "log in", "log-in", "login",
    "create account", "create an account", "register", "join now",
)
_LOGGED_IN_MARKERS = (
    "sign out", "sign-out", "log out", "log-out", "logout",
    "my account", "your account", "account settings", "my orders", "your orders",
)


def request_is_authenticated(header_names) -> bool:
    """True if any auth header NAME is present. Values are never inspected."""
    lowered = {str(h).lower() for h in header_names}
    return bool(lowered & AUTH_HEADER_NAMES)


def page_login_signal(html: str | None) -> str:
    """Classify visible login state from page markup only.

    Returns "logged_in", "logged_out", or "unknown". Reads no storage and no
    cookies — purely the rendered HTML text/controls.
    """
    t = (html or "").lower()
    has_password_field = ('type="password"' in t) or ("type='password'" in t)
    looks_out = has_password_field or any(m in t for m in _LOGGED_OUT_MARKERS)
    looks_in = any(m in t for m in _LOGGED_IN_MARKERS)
    if looks_in and not looks_out:
        return "logged_in"
    if looks_out and not looks_in:
        return "logged_out"
    return "unknown"
