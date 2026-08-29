# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Policy shared by every evidence path.

Kept separate from the producer so a caller can ask which tiers are attested,
or reduce a failure to a safe category, without importing the machinery that
opens a chain.
"""

from __future__ import annotations

#: Tiers whose actions are signed into the evidence chain. Tier A and B are
#: excluded because evidence exists for actions with physical consequence a
#: third party may later need to reason about.
_ATTESTED_TIERS = ("C", "D")


def tier_requires_attestation(tier: str) -> bool:
    """True when *tier* is on the evidence-signing path (Tier C/D)."""
    return str(tier or "").upper() in _ATTESTED_TIERS


#: Ordered most specific first: `isinstance` against a subclass must not be
#: claimed by a broader base that appears earlier.
_PUBLIC_FAILURE_CATEGORIES: tuple[tuple[type[BaseException], str], ...] = (
    (ModuleNotFoundError, "module_unavailable"),
    (ImportError, "module_unavailable"),
    (PermissionError, "permission_denied"),
    (FileNotFoundError, "not_found"),
    (TimeoutError, "timeout"),
    (MemoryError, "resource_exhausted"),
    (OSError, "io_error"),
    (ValueError, "invalid_value"),
    (TypeError, "invalid_type"),
    (AttributeError, "interface_mismatch"),
)
_UNCATEGORISED_FAILURE = "internal_error"


def safe_failure_reason(exc: BaseException) -> str:
    """A category from a closed set. No text derived from *exc*, ever.

    Every failure on this path carries an exception raised by, or naming, the
    private component. Neither its message nor its traceback can be shown to an
    operator, and relocating them to DEBUG does not help — `logging.level:
    DEBUG` is a documented operator choice, so a level an operator can select
    is not a private channel.

    The exception's *class name* is not safe either, which is the subtler
    version of the same mistake: a private component is free to raise
    `AcmeChainConnectionError`, or a class whose name carries a deployment
    identity, and `type(exc).__name__` would print it. So nothing here reads
    text off the exception. The category comes from an `isinstance` test
    against builtin types, and anything unrecognised is `internal_error`.

    What survives is the distinction worth having: a missing module reads
    differently from a permission failure or a refused call.
    """
    for exception_type, category in _PUBLIC_FAILURE_CATEGORIES:
        if isinstance(exc, exception_type):
            return category
    return _UNCATEGORISED_FAILURE
