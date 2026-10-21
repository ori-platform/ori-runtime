# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Replay caches for tests that sign and verify on their own clocks.

A cache built without `start_ms` takes its start floor from the wall clock at
construction, which is correct for a runtime and refuses, as
`before_replay_floor`, any envelope a test signed a millisecond earlier: a
flake that depends on whether the two land in the same millisecond. Every
authenticator a test builds takes its cache from here
(`tests/test_gateway_auth_helpers_guard.py`).
"""

from __future__ import annotations

from ori.security.gateway_messages import GatewayMessageAuthConfig, GatewayReplayCache


def cache_for(config: GatewayMessageAuthConfig, **kwargs: object) -> GatewayReplayCache:
    """A cache matching *config*, started at clock 0 unless told otherwise."""
    kwargs.setdefault("start_ms", 0)
    return GatewayReplayCache(
        ttl_ms=config.replay_ttl_ms,
        max_skew_ms=config.max_skew_ms,
        **kwargs,  # type: ignore[arg-type]
    )
