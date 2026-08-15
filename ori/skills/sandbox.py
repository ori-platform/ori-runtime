# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Skill security errors, and the retired in-process hook loader.

This module used to offer ``load_hooks_restricted()``, which executed community
``hooks.py`` inside the runtime interpreter with a filtered ``builtins`` mapping
and a ``sys.meta_path`` import finder. It was described as a sandbox. It was not
one, for two independent reasons:

1. **The namespace was never closed.** The restricted mapping was built by
   copying ``builtins`` and removing a short denylist, so ``object``, ``type``,
   ``getattr`` and ``__build_class__`` remained. Ordinary attribute traversal
   from any surviving object reached the full interpreter, and the modules the
   allowlist permitted kept references to their own globals.

2. **Half of it was inert on modern Python.** The import finder implemented only
   ``find_module``, a protocol removed in Python 3.12. On Python 3.12 — which is
   what Ubuntu 24.04 ships, one of Ori's supported deployment targets — the
   finder was silently ignored by the import system. It failed open, with no
   error, for the entire time it was installed.

A boundary that can be walked around is worse than no boundary, because the
configuration around it is written as though the protection exists. The function
therefore refuses rather than executing anything, and community hooks are
blocked at the loader as well: refusing in one place would make that place
load-bearing.

Executing community hooks outside the runtime interpreter is being specified
before it is implemented. Until that contract lands, there is no supported path
for running third-party hook code in this process.
"""

from typing import NoReturn


class SkillSecurityError(Exception):
    """Raised when a hooks file violates security constraints."""


def load_hooks_restricted(hooks_path: str) -> NoReturn:
    """Refuse to execute *hooks_path* in the runtime interpreter.

    Raises:
        SkillSecurityError: Always. There is no in-process execution path for
            community hook code.
    """
    raise SkillSecurityError(
        f"in-process execution of community hooks is disabled: {hooks_path}. "
        "The restricted-import loader was not a security boundary and has been "
        "removed rather than repaired. Community hook execution is blocked "
        "pending the isolated-worker contract."
    )
