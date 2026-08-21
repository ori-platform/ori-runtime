# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Network-address classification shared by config validation and the runtime.

There were two implementations of "is this host loopback" and they disagreed.
Configuration validation tested `value.startswith("127.")`, which is true of
`127.attacker.example` — a perfectly registrable DNS name that resolves
wherever its owner points it. Under production posture that string took the
loopback branch and skipped every non-loopback requirement at once: TLS, the
broker deployment check, `anonymous_access: disabled`, per-device ACLs,
`require_credentials`, and the username/password check. The runtime's own
diagnostics used `ip_address()` and classified the same host as public, so the
two halves of the system disagreed about whether a deployment was hardened.

One helper, used by both. A host is loopback only when it is the literal name
`localhost` or an address the standard library resolves as loopback. No
prefix matching: a name is not an address, and treating it as one is how the
bypass above existed.
"""

from __future__ import annotations

from ipaddress import ip_address

# The one hostname treated as loopback without being an address. Matched
# exactly, so `localhost.attacker.example` is not loopback.
_LOOPBACK_HOSTNAMES = frozenset({"localhost"})


def is_loopback_host(host: str | None) -> bool:
    """True when *host* is unambiguously loopback.

    Accepts the host component of a parsed URL, not a whole URL: callers must
    parse first, because userinfo (`user:pass@127.0.0.1`) precedes the host and
    defeats any comparison against the raw string.
    """
    value = str(host or "").strip().lower()
    if not value:
        return False
    if value in _LOOPBACK_HOSTNAMES:
        return True
    # Brackets survive some hand-built URLs even though urlparse strips them.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ip_address(value).is_loopback
    except ValueError:
        # Not an address. A hostname is never loopback on the strength of how
        # it is spelled, however much it resembles one.
        return False
