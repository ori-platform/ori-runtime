# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import sys
import types
from pathlib import Path
from typing import Optional

_ALLOWED_IMPORTS: frozenset = frozenset(
    {
        "math",
        "statistics",
        "datetime",
        "time",
        "collections",
        "itertools",
        "functools",
        "json",
        "re",
        "string",
        "ori.network.events",
    }
)

_BLOCKED_BUILTINS: frozenset = frozenset(
    {
        "open",
        "exec",
        "eval",
        "__import__",
        "compile",
        "breakpoint",
    }
)


class SkillSecurityError(Exception):
    """Raised when a hooks file violates security constraints."""


class RestrictedImportFinder:
    """sys.meta_path finder that blocks any module not in _ALLOWED_IMPORTS."""

    def find_module(self, fullname: str, path=None):
        # Support submodule checks: 'ori.network.events' is allowed,
        # but 'ori' alone or 'ori.network' alone are intermediate packages
        # that must be permitted to resolve the full dotted name.
        if fullname in _ALLOWED_IMPORTS:
            return None  # allow normal import machinery to handle it

        # Allow intermediate packages of explicitly allowed dotted modules
        for allowed in _ALLOWED_IMPORTS:
            if allowed.startswith(fullname + "."):
                return None  # intermediate package, allow

        # Block everything else
        raise ImportError(
            f"Import of '{fullname}' is not allowed in skill hooks. "
            f"Allowed modules: {sorted(_ALLOWED_IMPORTS)}"
        )


def load_hooks_restricted(hooks_path: str) -> Optional[types.ModuleType]:
    """Load a skill hooks.py file inside a restricted import sandbox.

    Returns None if the file does not exist.
    Raises SkillSecurityError if the hooks file attempts a disallowed import.
    """
    path = Path(hooks_path)
    if not path.exists():
        return None

    finder = RestrictedImportFinder()
    sys.meta_path.insert(0, finder)
    try:
        source = path.read_text(encoding="utf-8")

        module = types.ModuleType(path.stem)
        module.__file__ = str(path)

        # Build a restricted builtins dict.
        # Most _BLOCKED_BUILTINS are stripped outright.
        # __import__ is special: removing it entirely also breaks normal
        # `import` statements (the import statement calls __import__
        # internally).  Instead we replace it with a wrapper that enforces
        # the same allowlist as RestrictedImportFinder so that direct
        # __import__('os') calls are also rejected.
        import builtins as _builtins_module

        _original_import = _builtins_module.__import__

        def _restricted_import(name, *args, **kwargs):
            # Allow if the exact name or any prefix of an allowed dotted name
            allowed = name in _ALLOWED_IMPORTS or any(
                a.startswith(name + ".") for a in _ALLOWED_IMPORTS
            )
            if not allowed:
                raise ImportError(f"Import of '{name}' is not allowed in skill hooks.")
            return _original_import(name, *args, **kwargs)

        safe_builtins = vars(_builtins_module).copy()
        for blocked in _BLOCKED_BUILTINS:
            safe_builtins.pop(blocked, None)
        # Restore a restricted __import__ so that `import X` statements work
        # for allowed modules while direct __import__('bad') calls are blocked.
        safe_builtins["__import__"] = _restricted_import

        module.__builtins__ = safe_builtins

        try:
            exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102
        except ImportError as exc:
            raise SkillSecurityError(str(exc)) from exc

        return module
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
