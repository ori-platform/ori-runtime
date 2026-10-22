# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's gateway envelope state and authenticators, built from config.

One replay cache and one signing clock per runtime, shared by every gateway
route: see `build_gateway_envelope_state`.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ori.gateway.payload_bounds import replay_capacity
from ori.security.gateway_messages import (
    GatewayEnvelopeState,
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
    GatewayReplayCache,
    replay_retention_ms,
)
from ori.security.signing_clock import (
    SigningClock,
    durable_store,
    reservation_for_skew,
)
from ori.utils.bool_utils import is_truthy

if TYPE_CHECKING:
    from ori.config import Config

# The runtime's logger: these lines have always been the runtime's.
logger = logging.getLogger("ori.runtime")


def build_gateway_envelope_state(config: Config) -> GatewayEnvelopeState | None:
    """The one replay cache and signing clock every gateway route shares, or
    None without auth.

    One per runtime: the cache's size covers every family, and every key names
    its message type, so a cache per route would hold the same table six
    times; and gateway-api/v2 Senders wants one clock, never repeating a
    signing time, behind every signer.
    """
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        return None
    replay_ttl_ms = int(auth_cfg.get("replay_ttl_ms", 300_000))
    skew_ms = int(auth_cfg.get("max_clock_skew_ms", 300_000))
    retention_ms = replay_retention_ms(replay_ttl_ms, skew_ms)
    persistent = is_truthy(auth_cfg.get("persistent_replay_cache", True))
    database_path = str(getattr(config, "database_path", "") or "")
    replay_cache = GatewayReplayCache(
        ttl_ms=replay_ttl_ms,
        max_skew_ms=skew_ms,
        # Every message the families admit in one retention window, up to a
        # ceiling past which a full cache evicts with a floor raise.
        max_entries=replay_capacity(retention_ms),
        # A restart is attacker-influenceable on a physically accessible
        # device (pulling power is enough), so held keys and the replay floor
        # persist to the state database. With persistence off, a floor an
        # earlier run stored there is still read, never written.
        db_path=database_path,
        stores=persistent,
    )
    if not durable_store(database_path):
        # Refused at config load in a hardened posture; here, development only.
        logger.warning(
            "[runtime] the state database %r does not outlive the process: "
            "gateway signing times are nondurable and can repeat across a "
            "restart (development only).",
            database_path,
        )
    return GatewayEnvelopeState(
        replay_cache=replay_cache,
        signing_clock=SigningClock(
            database_path if durable_store(database_path) else None,
            reservation_ms=reservation_for_skew(skew_ms),
        ),
    )


def build_gateway_message_auth(
    config: Config, envelope_state: GatewayEnvelopeState | None = None
) -> GatewayMessageAuthenticator | None:
    """Build optional HMAC auth for runtime-gateway MQTT envelopes.

    *envelope_state* is the runtime's shared one; without it one is built.
    """
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    if not bool(auth_cfg.get("enabled", False)):
        return None
    env_name = str(auth_cfg.get("shared_secret_env", "") or "").strip()
    secret = os.environ.get(env_name, "") if env_name else ""
    if not secret:
        raise ValueError(
            "gateway auth is enabled but configured shared-secret environment "
            "variable is empty"
        )
    previous_env_name = str(
        auth_cfg.get("previous_shared_secret_env", "") or ""
    ).strip()
    previous_secret = os.environ.get(previous_env_name, "") if previous_env_name else ""
    if previous_env_name and not previous_secret:
        logger.warning(
            "[runtime] gateway auth previous shared-secret environment variable "
            "is configured but empty; previous-secret verification disabled."
        )
    replay_ttl_ms = int(auth_cfg.get("replay_ttl_ms", 300_000))
    if envelope_state is None:
        envelope_state = build_gateway_envelope_state(config)
    assert envelope_state is not None
    return GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(
            shared_secret=secret,
            previous_shared_secret=previous_secret,
            max_skew_ms=int(auth_cfg.get("max_clock_skew_ms", 300_000)),
            replay_ttl_ms=replay_ttl_ms,
        ),
        replay_cache=envelope_state.replay_cache,
        signing_clock=envelope_state.signing_clock,
    )
