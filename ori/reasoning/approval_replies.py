# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An operator's reply to a Tier C approval request, as text and as a decision."""

from ori.utils.ascii_text import ASCII_WHITESPACE

_YES_TOKENS = frozenset({"yes", "y", "approve", "go", "ok", "confirm"})
_NO_TOKENS = frozenset({"no", "n", "cancel", "stop", "reject", "deny"})


#: What an unencodable reply is classified as: text that is no decision.
_UNENCODABLE_REPLY = "\ufffd"


def _normalize_proposal_id(value: str | None) -> str:
    # ASCII letters and digits only, selected before folding: `ﬀ` upper-cases to FF.
    return "".join(c for c in str(value or "") if c.isascii() and c.isalnum()).upper()


def storable_reply(reply: object) -> str | None:
    """A heard reply as text the store can hold, or None when it is not text.

    A lone surrogate, which a provider's JSON can carry and UTF-8 cannot, is
    escaped for storage and reporting only; it is never classified.
    """
    if not isinstance(reply, str):
        return None
    return reply.encode("utf-8", "backslashreplace").decode("utf-8")


def classifiable_reply(reply: object) -> str | None:
    """A heard reply as the classifier sees it: None when it is not text, and
    no decision at all when UTF-8 cannot carry it."""
    if not isinstance(reply, str):
        return None
    try:
        reply.encode("utf-8")
    except UnicodeEncodeError:
        return _UNENCODABLE_REPLY
    return reply


def classify_approval_response(
    response: str | None,
    *,
    proposal_id: str | None = None,
    allow_offline_token: bool = False,
    require_scoped: bool = False,
) -> str:
    """Classify a Tier C response; only ASCII is folded, so no look-alike reads as one."""
    if response is None:
        return "invalid"

    raw = response.strip(ASCII_WHITESPACE)
    if not raw:
        return "invalid"
    if allow_offline_token and raw[:6].isascii() and raw[:6].upper() == "TOKEN:":
        return "token"

    token = raw.lower() if raw.isascii() else ""
    if require_scoped:
        if "-" not in raw:
            return "invalid"
    else:
        if token in _YES_TOKENS:
            return "approve"
        if token in _NO_TOKENS:
            return "reject"
        if "-" not in raw:
            return "invalid"

    head, suffix = raw.split("-", 1)
    expected = _normalize_proposal_id(proposal_id)
    if not expected or _normalize_proposal_id(suffix) != expected:
        return "invalid"

    head_token = head.strip(ASCII_WHITESPACE).lower() if head.isascii() else ""
    if head_token in _YES_TOKENS:
        return "approve"
    if head_token in _NO_TOKENS:
        return "reject"
    return "invalid"
