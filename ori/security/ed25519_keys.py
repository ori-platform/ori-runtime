# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The one way an Ed25519 public key becomes a verifier in this runtime.

The library verifies under any 32 bytes that decode to a point. Under a point
of small order a signature that verifies can be made with no private key, so
such a key binds a signature to no key holder. Under a point of mixed order,
a prime-order key shifted by a small-order point, the shifted key's holder is
the unshifted key's, so a check that recognises a key by its bytes is passed
by shifting a key it refuses. The refusal clauses are those of
`ed25519-key-admission/v1`, whose corpus is vendored under
`tests/vectors/ed25519_key_admission`: RFC 8032 section 5.1.3 decoding, with
small-order and mixed-order points refused. Applied to a frozen contract ahead
of its successor, this is hardening, not conformance.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CLAUSE_NON_CANONICAL = "non_canonical"
CLAUSE_OFF_CURVE = "off_curve"
CLAUSE_INVALID_SIGN = "invalid_sign"
CLAUSE_SMALL_ORDER = "small_order"
CLAUSE_MIXED_ORDER = "mixed_order"

# RFC 8032, section 5.1.
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
# The prime order of the base point.
_L = 2**252 + 27742317777372353535851937790883648493

_Point = tuple[int, int, int, int]


class RefusedPublicKeyError(ValueError):
    """A public key that cannot bind a signature to a key holder."""

    def __init__(self, clause: str) -> None:
        super().__init__(f"Ed25519 public key refused: {clause}")
        self.clause = clause


def _point_add(p: _Point, q: _Point) -> _Point:
    """Extended-coordinate point addition, RFC 8032 section 5.1.4."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _is_identity(point: _Point) -> bool:
    return point[0] % _P == 0 and (point[1] - point[2]) % _P == 0


def _scalar_mul(k: int, point: _Point) -> _Point:
    result: _Point = (0, 1, 1, 0)
    while k:
        if k & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        k >>= 1
    return result


# A device or anchor key recurs on every message; the decode is pure.
@lru_cache(maxsize=1024)
def refused_public_key_clause(public_key: bytes) -> str | None:
    """The clause refusing a 32-byte Ed25519 public key, or None when it is accepted."""
    if len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    encoded = int.from_bytes(public_key, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _P:
        return CLAUSE_NON_CANONICAL
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if v * x * x % _P != u:
        if v * x * x % _P != (-u) % _P:
            return CLAUSE_OFF_CURVE
        x = x * _SQRT_M1 % _P
    if x == 0 and sign:
        return CLAUSE_INVALID_SIGN
    # The sign of x is not applied: a point and its negation have one order.
    point: _Point = (x, y, 1, x * y % _P)
    if _is_identity(_scalar_mul(8, point)):
        return CLAUSE_SMALL_ORDER
    if not _is_identity(_scalar_mul(_L, point)):
        return CLAUSE_MIXED_ORDER
    return None


def key_identity(public_key: bytes) -> bytes:
    """The bytes a key shares with its negation: y, with the sign of x cleared.

    The holder of a key's scalar a holds -a, which signs under the negated key,
    and admission refuses neither. A check that recognises a key (a published
    key, a collision, a key not to be reused) compares this, not the encoding.
    No other related key, [c]A for a c only its holder knows, can be recognised
    from public material.
    """
    if len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return public_key[:31] + bytes([public_key[31] & 0x7F])


def admit_public_key(public_key: bytes) -> Ed25519PublicKey:
    """A verifier for *public_key*, or RefusedPublicKeyError (a ValueError)."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    clause = refused_public_key_clause(public_key)
    if clause is not None:
        raise RefusedPublicKeyError(clause)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(public_key)
