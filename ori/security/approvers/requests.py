# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""operator-socket/v3 requests: the bound, the parse, and each operation's members.

Everything here is decided from the request bytes alone, before the caller is
established and before any registry state is read.
"""

from __future__ import annotations

import json
from typing import Any, Final

from ori.security.approvers.forms import (
    OPERATIONS,
    PHONE_CHANNELS,
    canonical_b64,
    is_candidate,
    is_id,
    is_signed_object,
    is_value,
)

MAX_REQUEST_BYTES: Final = 16_384
MAX_DEPTH: Final = 32

REGISTRY_OPERATIONS: Final = frozenset(
    {
        "approver_registry_challenge",
        "approver_registry_recover",
        "approver_registry_local_seed",
        "approver_registry_enrol",
        "approver_registry_revoke",
        "approver_registry_binding",
    }
)
SOCKET_OPERATIONS: Final = REGISTRY_OPERATIONS | {
    "reconcile_tier_c",
    "evidence_commission",
}


class SocketRequestError(Exception):
    """A request refused before the caller is established."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _invalid(detail: str) -> SocketRequestError:
    return SocketRequestError("invalid_arguments", detail)


class _Members(dict[str, Any]):
    """A parsed object, remembering every value a repeated member shadowed."""

    def __init__(self) -> None:
        super().__init__()
        self.shadowed: list[Any] = []

    @property
    def duplicated(self) -> bool:
        return bool(self.shadowed)


class _Oversized:
    """An integer literal past every bound: no form accepts it."""


def _integer(text: str) -> int | _Oversized:
    # Longer than 2^53 - 1 is out of every form, and Python refuses to convert
    # an integer past 4,300 digits, which would refuse the request as a parse
    # failure rather than judging it on its form.
    return int(text) if len(text.lstrip("-")) <= 16 else _Oversized()


def _not_json(name: str) -> Any:
    # NaN, Infinity and -Infinity are not JSON.
    raise ValueError(f"{name} is not JSON")


def _members(pairs: list[tuple[str, Any]]) -> _Members:
    members = _Members()
    for name, value in pairs:
        if name in members:
            members.shadowed.append(members[name])
        members[name] = value
    return members


def frame(received: bytes) -> bytes:
    """The request: the bytes before the first LF, held to the bound.

    Over the bound is ``payload_too_large`` before anything is parsed. A
    connection that ended, or ran out of time, before any LF is
    ``invalid_arguments`` within the bound.
    """
    head, lf, _ = received.partition(b"\n")
    if len(head) > MAX_REQUEST_BYTES:
        raise SocketRequestError("payload_too_large", "the request exceeds its bound")
    if not lf:
        raise _invalid("the request ended before its LF")
    return head


def _check_tree(value: Any, *, document_allowed: bool) -> None:
    """The registry operations' parse rules over the whole request.

    Nesting past 32 levels (the request object is level 1) and a string with
    no UTF-8 form are parse failures wherever they occur, a shadowed value or
    a revocation document included. A member named twice is the request's
    fault, except inside a revocation document, where it is the document's.
    """
    stack: list[tuple[Any, int, bool]] = [(value, 1, False)]
    while stack:
        node, level, inside = stack.pop()
        if isinstance(node, str):
            _require_utf8(node)
        elif isinstance(node, dict):
            if level > MAX_DEPTH:
                raise _invalid("the request nests too deeply")
            if getattr(node, "duplicated", False) and not inside:
                raise _invalid("a request member is named twice")
            for name, member in node.items():
                _require_utf8(name)
                into = inside or (
                    level == 1 and name == "document" and document_allowed
                )
                stack.append((member, level + 1, into))
            if isinstance(node, _Members):
                stack.extend((member, level + 1, True) for member in node.shadowed)
        elif isinstance(node, list):
            if level > MAX_DEPTH:
                raise _invalid("the request nests too deeply")
            stack.extend((member, level + 1, inside) for member in node)


def _require_utf8(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _invalid("a string has no UTF-8 form") from exc


def parse(head: bytes) -> dict[str, Any]:
    """One JSON object whose `operation` is one of the socket's eight.

    The parse rules of Approver Registry Operations apply to the registry
    operations; `reconcile_tier_c` and `evidence_commission` keep v2's, under
    which a repeated member is refused and their own members judge the rest.
    """
    try:
        value = json.loads(
            head.decode("utf-8"),
            object_pairs_hook=_members,
            parse_int=_integer,
            parse_constant=_not_json,
        )
    except (ValueError, RecursionError) as exc:
        raise _invalid("the request must be one JSON object") from exc
    if not isinstance(value, _Members):
        raise _invalid("the request must be one JSON object")
    if value.duplicated:
        raise _invalid("a request member is named twice")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in SOCKET_OPERATIONS:
        raise _invalid("the operation is not one this socket serves")
    if operation in REGISTRY_OPERATIONS:
        _check_tree(value, document_allowed=operation == "approver_registry_revoke")
    else:
        _no_repeats(value)
    return dict(value)


def _no_repeats(value: Any) -> None:
    """v2's rule: a member named twice at any depth refuses the request."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if getattr(node, "duplicated", False):
                raise _invalid("a request member is named twice")
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def _exactly(request: dict[str, Any], members: set[str]) -> None:
    if set(request) != members:
        raise _invalid("the request's members are not this operation's")


def _challenge_id(value: object) -> None:
    if canonical_b64(value, 16) is None:
        raise _invalid("challenge_id is not canonical Base64 of 16 bytes")


def validate_registry_request(request: dict[str, Any]) -> dict[str, Any]:
    """The operation's members and forms; the request itself when they hold."""
    operation = request["operation"]
    if operation == "approver_registry_challenge":
        _exactly(request, {"operation", "challenge_operation", "candidate"})
        kind = request["challenge_operation"]
        candidate = request["candidate"]
        if not isinstance(kind, str) or kind not in OPERATIONS:
            raise _invalid("challenge_operation is not recover, local_seed or enrol")
        if kind == "recover":
            if candidate is not None:
                raise _invalid("a recover challenge names no candidate")
        else:
            members = {"channel", "value"} | (
                {"approver_id"} if kind == "enrol" else set()
            )
            if not isinstance(candidate, dict) or set(candidate) != members:
                raise _invalid("the candidate's members are not this operation's")
            if not isinstance(candidate["channel"], str) or not is_value(
                candidate["channel"], candidate["value"]
            ):
                raise _invalid("the candidate's channel or value is not its form")
            if kind == "enrol" and not (
                candidate["approver_id"] is None or is_id(candidate["approver_id"])
            ):
                raise _invalid("approver_id is neither null nor an approver ID")
    elif operation == "approver_registry_recover":
        _exactly(request, {"operation", "challenge_id"})
        _challenge_id(request["challenge_id"])
    elif operation == "approver_registry_local_seed":
        _exactly(request, {"operation", "challenge_id", "candidate", "possession"})
        _challenge_id(request["challenge_id"])
        if not is_candidate(request["candidate"]):
            raise _invalid("the candidate is not a candidate")
        if not is_signed_object(request["possession"], "candidate_credential_id"):
            raise _invalid("the possession is not a possession object")
    elif operation == "approver_registry_enrol":
        _exactly(
            request,
            {"operation", "challenge_id", "candidate", "authorization", "possession"},
        )
        _challenge_id(request["challenge_id"])
        candidate = request["candidate"]
        if not is_candidate(candidate):
            raise _invalid("the candidate is not a candidate")
        authorization = request["authorization"]
        if authorization is not None and not is_signed_object(
            authorization, "authorizer_credential_id"
        ):
            raise _invalid("the authorization is not an authorization object")
        possession = request["possession"]
        if candidate["channel"] in PHONE_CHANNELS:
            if possession is not None:
                raise _invalid("a phone candidate carries no possession object")
        elif not is_signed_object(possession, "candidate_credential_id"):
            raise _invalid("a LAN candidate needs a possession object")
    elif operation == "approver_registry_revoke":
        _exactly(request, {"operation", "document"})
    elif operation == "approver_registry_binding":
        _exactly(request, {"operation"})
    else:
        raise _invalid("not a registry operation")
    return request
