"""Deterministic, synthetic accounts and objects for the lab.

NOTE: The bearer tokens below are NOT secrets. They are fixed test fixtures for a
throwaway local application that only ever binds to localhost. They are safe to
commit. Real engagements must never store credentials in source.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    user_id: str
    label: str
    token: str  # synthetic, non-secret test token


# Two authorized test identities.
USERS: dict[str, User] = {
    "user_a": User(user_id="1001", label="user_a", token="tok_test_a_11111111"),
    "user_b": User(user_id="1002", label="user_b", token="tok_test_b_22222222"),
}

# token -> label, for auth lookups.
TOKENS: dict[str, str] = {u.token: u.label for u in USERS.values()}

# Notes: per-user objects. The notes endpoint is the VULNERABLE one (no per-object
# authorization). Contents are harmless synthetic data.
NOTES: dict[str, dict] = {
    "note-a1": {"id": "note-a1", "owner": "user_a", "title": "Groceries", "body": "apples, bread, milk"},
    "note-a2": {"id": "note-a2", "owner": "user_a", "title": "Todo", "body": "water the plants"},
    "note-b1": {"id": "note-b1", "owner": "user_b", "title": "Books", "body": "return library book"},
}

# Profiles: per-user objects. The profile endpoint is the CORRECTLY protected one.
PROFILES: dict[str, dict] = {
    "1001": {"user_id": "1001", "owner": "user_a", "display_name": "Alice Example", "email": "alice@example.test"},
    "1002": {"user_id": "1002", "owner": "user_b", "display_name": "Bob Example", "email": "bob@example.test"},
}


def label_for_token(token: str) -> str | None:
    return TOKENS.get(token)
