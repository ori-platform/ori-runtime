# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Environment variable names and ``${VAR}`` expansion."""

import os
import re

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")


def expand_env_vars(text: str) -> str:
    """Replace ${VAR_NAME} with the environment variable value, or leave as-is."""

    def _replace(match: re.Match[str]) -> str:
        var = match.group(1)
        return os.environ.get(var, match.group(0))

    return _ENV_VAR_RE.sub(_replace, text)
