# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""An operator's reply to a Tier C approval request, as text and as a decision."""

from ori.utils.ascii_text import ASCII_WHITESPACE

_DECISIONS = {"YES": "approve", "NO": "reject"}
_TRAILING = ASCII_WHITESPACE + "."


#: What an unencodable reply is classified as: text that is no decision.
_UNENCODABLE_REPLY = "\ufffd"


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
    """Classify a Tier C reply as `approve`, `reject`, `token` or `invalid`.

    The decision is `YES` or `NO`, scoped as `YES-<proposal_id>` / `NO-<proposal_id>`
    and bare only when scoped replies are not required. Only ASCII case,
    surrounding ASCII whitespace and trailing periods, which phone keyboards add,
    are tolerated; every other reply is `invalid`. Trimming a period is safe only
    because no proposal id contains one.
    """
    if response is None:
        return "invalid"

    raw = response.strip(ASCII_WHITESPACE)
    if allow_offline_token and raw[:6].isascii() and raw[:6].upper() == "TOKEN:":
        return "token"
    raw = raw.rstrip(_TRAILING)
    # Upper-casing only ASCII text keeps a look-alike (`ſ`, `ﬀ`) from folding in.
    if not raw.isascii():
        return "invalid"

    word, scoped, given_id = raw.upper().partition("-")
    decision = _DECISIONS.get(word)
    if decision is None:
        return "invalid"
    if not scoped:
        return "invalid" if require_scoped else decision

    expected = proposal_id if isinstance(proposal_id, str) else ""
    if not expected or not expected.isascii() or given_id != expected.upper():
        return "invalid"
    return decision
