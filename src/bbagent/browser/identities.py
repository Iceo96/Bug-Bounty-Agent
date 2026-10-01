"""Per-identity browser profiles.

Each authorized test identity maps to its OWN persistent Chromium profile (its
manually-authenticated session). This module builds one browser backend per
identity from the program's configured profile-dir env refs, and enforces that no
two identities ever share a profile directory. It reads only directory PATHS (via
``ProgramManager.resolve_profile_dir``) — never cookies, tokens, or storage state.
"""

from __future__ import annotations

import os

from bbagent.browser.playwright_backend import PlaywrightBackend
from bbagent.program.manager import ProgramManager


class ProfileConflict(Exception):
    """Raised when two identities resolve to the same browser profile directory."""


class ResearchHeaderUnavailable(Exception):
    """Raised when a required non-secret research header's env value is missing."""


# Session/secret header names that must NEVER be injected into the browser context —
# the authenticated session comes exclusively from the persistent profile.
_SECRET_HEADER_NAMES = {
    "cookie", "set-cookie", "verifyauthtoken", "x-verify-auth-token",
    "authorization", "accesstoken", "access-token", "x-access-token",
    "x-api-key", "x-auth-token", "proxy-authorization",
}


def research_headers(program: ProgramManager) -> dict[str, str]:
    """Resolve ONLY the non-secret identifier required-headers (e.g.
    ``X-HackerOne-Research``) from the environment, for context-level injection.

    Session/secret headers (Cookie/VerifyAuthToken/Authorization/…) are skipped on
    purpose — they live in the profile, never injected. Fails closed if a required
    non-secret header's env var is unset. Never logs the resolved value.
    """
    out: dict[str, str] = {}
    for name, env_var in getattr(program.config, "required_header_refs", {}).items():
        if name.lower() in _SECRET_HEADER_NAMES:
            continue  # session/secret -> supplied by the persistent profile only
        value = os.getenv(env_var)
        if value is None:
            raise ResearchHeaderUnavailable(
                f"required research header {name!r} unavailable (env {env_var} unset)")
        out[name] = value
    return out


def identity_profiles(program: ProgramManager) -> dict[str, str]:
    """Map identity label -> resolved profile directory (only those configured)."""
    out: dict[str, str] = {}
    for acct in program.config.test_accounts:
        d = program.resolve_profile_dir(acct.label)
        if d:
            out[acct.label] = d
    return out


def build_identity_backends(
    program: ProgramManager, *, headless: bool = True,
) -> dict[str, PlaywrightBackend]:
    """Build one PlaywrightBackend per configured identity, each bound to its OWN
    persistent profile and labelled with that identity. Fails closed if two
    identities resolve to the same directory (profiles must never be shared)."""
    # Non-secret research identifier header(s), injected into EVERY identity's context
    # (same value for A and B). Fails closed if the research env var is unset. Session
    # secrets are never here — they stay in each profile.
    headers = research_headers(program)

    backends: dict[str, PlaywrightBackend] = {}
    used: dict[str, str] = {}
    for label, directory in identity_profiles(program).items():
        if directory in used:
            raise ProfileConflict(
                f"identities {used[directory]!r} and {label!r} resolve to the same "
                f"browser profile directory; profiles must not be shared between identities")
        used[directory] = label
        backends[label] = PlaywrightBackend(
            headless=headless, user_data_dir=directory, identity_label=label,
            extra_http_headers=headers)
    return backends
