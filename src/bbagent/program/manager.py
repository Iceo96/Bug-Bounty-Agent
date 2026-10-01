"""Program Manager: loads a program and exposes its rules to the rest of the agent."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from bbagent.config import ProgramConfig, load_program
from bbagent.config.models import TestAccount
from bbagent.logging_config import get_logger

log = get_logger(__name__)


class ProgramManager:
    """Holds the active :class:`ProgramConfig` and answers questions about it.

    This object is the authoritative accessor for scope, restrictions, headers,
    rate limits, and test accounts. Other components should read from here
    rather than parsing config themselves.
    """

    def __init__(self, config: ProgramConfig):
        self.config = config
        log.info(
            "program.loaded",
            name=config.name,
            in_scope=len(config.scope.in_scope),
            excluded=len(config.scope.excluded),
            active_testing=config.restrictions.allow_active_testing,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "ProgramManager":
        return cls(load_program(path))

    # --- convenience accessors -------------------------------------------------

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def required_headers(self) -> dict[str, str]:
        return dict(self.config.required_headers)

    def test_account(self, label: str) -> Optional[TestAccount]:
        for acct in self.config.test_accounts:
            if acct.label == label:
                return acct
        return None

    def resolve_account_secret(self, label: str) -> Optional[str]:
        """Resolve a test account's secret from its referenced environment variable.

        Secrets never live in the config file; only the env-var name does.
        Returns ``None`` if the account or the env var is absent.
        """
        acct = self.test_account(label)
        if acct is None or not acct.secret_env:
            return None
        return os.getenv(acct.secret_env)

    def resolve_profile_dir(self, label: str) -> Optional[str]:
        """Resolve a test identity's OWN persistent browser-profile directory.

        Only the env-var name lives in the config; the resolved path is used to
        point the browser at that identity's profile. Returns ``None`` if the
        account or the env var is absent. The value is never printed or stored.
        """
        acct = self.test_account(label)
        if acct is None or not acct.profile_dir_env:
            return None
        return os.getenv(acct.profile_dir_env)

    def is_method_allowed(self, method: str) -> bool:
        return method.upper() in self.config.restrictions.allowed_methods

    def is_path_forbidden(self, path: str) -> bool:
        return any(frag and frag in path for frag in self.config.restrictions.forbidden_paths)
