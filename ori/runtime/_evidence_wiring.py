# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The evidence attestor, its posture, the authority keys the release ships,
custody keys, and the evidence MQTT routes."""

import logging
import os
from importlib import resources

from ori.config import Config
from ori.gateway.envelope_auth import (
    build_gateway_message_auth as _build_gateway_message_auth,
)
from ori.gateway.evidence_inbound import (
    EvidenceInboundRouter,
    MqttEvidenceInboundSubscriber,
)
from ori.gateway.evidence_outbound import (
    EvidenceOutboundAckRouter,
    MqttEvidenceOutboundPublisher,
)
from ori.security.evidence.authority_keys import (
    VERIFIED_PURPOSES,
    AuthorityKeyError,
    ReleaseAuthorityKeys,
    load_release_authority_key_registry,
)
from ori.security.evidence.custody_keys import (
    CustodyKeyRegistry,
    CustodyKeyRegistryError,
)
from ori.security.evidence.first_party import FirstPartyEvidenceAttestor
from ori.security.gateway_messages import GatewayEnvelopeState

logger = logging.getLogger("ori.runtime")


def build_evidence_attestor(config: Config) -> FirstPartyEvidenceAttestor | None:
    """Build the optional Tier C/D evidence attestor.

    Evidence signing is opt-in via ``evidence.enabled``. A configured but
    missing device secret fails startup loudly -- a silently unkeyed evidence
    chain would defeat the point of enabling it.

    The epoch and key selector are not read from configuration. They are derived
    from the device identity and the evidence key once that key exists, because
    they are sealed into immutable envelopes and recomputed by the evidence
    authority: a configured value would eventually be set wrongly on some device
    and could not be corrected afterwards.
    """
    evidence = getattr(config, "evidence", None)
    if evidence is None or not bool(evidence.enabled):
        return None
    secret = os.environ.get(evidence.device_secret_env, "")
    if not secret:
        raise ValueError(
            "evidence signing is enabled but the configured device-secret "
            f"environment variable ({evidence.device_secret_env}) is empty; "
            "provision a random install secret (not just the device serial)"
        )
    shipped = _load_authority_keys()
    return FirstPartyEvidenceAttestor(
        db_path=evidence.db_path,
        key_path=evidence.key_path,
        device_secret=secret,
        device_id=config.device.id,
        custody_keys=_custody_key_registry(config),
        authority_keys=shipped.keys,
        authority_keys_refused=shipped.refused,
    )


#: Closed vocabulary for `evidence.posture_problems` in runtime health.
EVIDENCE_POSTURE_SIGNING_UNAVAILABLE = "signing_unavailable"


EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING = "authority_keys_missing"


EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED = "authority_keys_refused"


EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE = "authority_keys_incomplete"


EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED = "custody_unconfigured"


def evidence_posture_problems(
    config: Config, attestor: FirstPartyEvidenceAttestor
) -> list[str]:
    """What stops evidence trust being established, from local, knowable facts.

    The ledger and device key opened, the signed release shipped an
    authority-key registry that was accepted and holds a verifying key for
    every purpose this release verifies, and custody can be verified when a
    gateway carries evidence. Each missing piece is reported, never used to
    refuse startup:
    evidence records what happened and must not decide whether the runtime may
    run. With any of these missing, ingest refuses what it cannot verify and
    health says why.
    """
    problems: list[str] = []
    if not attestor.available:
        problems.append(EVIDENCE_POSTURE_SIGNING_UNAVAILABLE)
    held = attestor.verifying_authority_purposes
    if attestor.authority_keys_refused:
        problems.append(EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED)
    elif not held:
        problems.append(EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING)
    elif not VERIFIED_PURPOSES <= held:
        problems.append(EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE)
    if bool(config.gateway.enabled) and not attestor.custody_configured:
        problems.append(EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED)
    return problems


def _load_authority_keys() -> ReleaseAuthorityKeys:
    """Resolve the authority key registry from the signed release.

    Packaged inside the wheel, so it is covered by the release signature and
    arrives only through an activated release -- the same path the installer
    already uses for release keys. It is deliberately not a configurable path:
    an operator who could point the runtime at a registry of their choosing
    could make arbitrary receipts and epoch confirmations trusted, which is the
    entire property this registry exists to provide.

    A release that ships none yields an empty registry, so inbound authority
    artifacts are refused as unknown-key rather than accepted unverified. A
    registry that is present but refused is never read in part: it yields no
    keys and is marked refused, which stops evidence verification and reports
    `authority_keys_refused`, and never stops the runtime, because Tier D is
    never gated on evidence.
    """
    resource = resources.files("ori.security").joinpath("evidence-authority-keys.json")
    try:
        with resources.as_file(resource) as path:
            if not path.exists():
                return ReleaseAuthorityKeys(keys={})
            return ReleaseAuthorityKeys(keys=load_release_authority_key_registry(path))
    except (FileNotFoundError, ModuleNotFoundError):
        return ReleaseAuthorityKeys(keys={})
    except AuthorityKeyError as exc:
        logger.error(
            "[evidence] the release's authority keys are refused (%s); "
            "no authority artifact will verify",
            exc.rule,
        )
        return ReleaseAuthorityKeys(keys={}, refused=True)


def _envelope_secrets(config: Config) -> tuple[str, ...]:
    """Every runtime-gateway envelope secret currently resolvable.

    Handed to the custody registry so reuse is refused on the bytes. Two
    environment variables can hold the same value, so comparing the names an
    operator wrote would report that configuration as correct.

    Each value is contributed both as provisioned and stripped of surrounding
    whitespace. A custody secret differing from an envelope secret only by a
    trailing newline is the same secret to any peer that trims one of them, and
    treating those as distinct key material would let a stray keystroke defeat
    the separation rather than report it.
    """
    raw_auth = getattr(config.gateway, "auth", {})
    auth_cfg = raw_auth if isinstance(raw_auth, dict) else {}
    names = (
        str(auth_cfg.get("shared_secret_env", "") or "").strip(),
        str(auth_cfg.get("previous_shared_secret_env", "") or "").strip(),
    )
    resolved: list[str] = []
    for name in names:
        if not name:
            continue
        value = os.environ.get(name, "")
        for candidate in (value, value.strip()):
            if candidate and candidate not in resolved:
                resolved.append(candidate)
    return tuple(resolved)


def _custody_key_registry(config: Config) -> CustodyKeyRegistry | None:
    """The custody generations acknowledgements are verified against.

    Built from `gateway.custody`, which is a **different secret** from
    `gateway.auth.shared_secret_env`. Custody previously read the envelope
    secret here, which every conformance test contradicted and no running
    system exercised, because nothing routes an acknowledgement inbound yet.

    None when no custody secret is configured. Custody is then refused at
    ingest rather than accepted unauthenticated, since an unauthenticated
    acknowledgement is forgeable by anything on the site network and the
    runtime uses custody state to manage its queue.
    """
    raw = getattr(config.gateway, "custody", {})
    custody_cfg = raw if isinstance(raw, dict) else {}
    env_name = str(custody_cfg.get("secret_env", "") or "").strip()

    # Not configured at all is a choice; configured and empty is a broken
    # credential. Collapsing the second into the first would report a
    # deployment whose custody secret never reached the process as one that
    # deliberately runs without custody, and the operator would see a healthy
    # runtime silently refusing every acknowledgement.
    if not env_name:
        return None
    # Read exactly as provisioned. The custody MAC keys from these bytes, so
    # trimming would key from bytes the operator did not set; the registry
    # refuses surrounding whitespace instead of silently deriving a different
    # identifier from the one the gateway holds.
    active = os.environ.get(env_name, "")
    if not active:
        raise ValueError(
            f"gateway.custody.secret_env names {env_name}, but that environment "
            "variable is empty or unset; provision the custody secret or remove "
            "the setting to run without custody verification"
        )

    previous_env = str(custody_cfg.get("previous_secret_env", "") or "").strip()
    previous = ""
    if previous_env:
        previous = os.environ.get(previous_env, "")
        if not previous:
            raise ValueError(
                f"gateway.custody.previous_secret_env names {previous_env}, but "
                "that environment variable is empty or unset; a rotation window "
                "needs the outgoing secret, so remove the setting to close it"
            )

    retired = tuple(str(v) for v in (custody_cfg.get("retired_key_ids") or ()))
    try:
        return CustodyKeyRegistry(
            active_secret=active,
            previous_secret=previous or None,
            retired_key_ids=retired,
            forbidden_secrets=_envelope_secrets(config),
        )
    except CustodyKeyRegistryError as exc:
        # Fail closed and loudly. A registry that cannot be built is a
        # misconfiguration an operator must fix, and silently continuing
        # without custody verification would look like a working deployment.
        raise ValueError(f"gateway.custody is misconfigured: {exc}") from exc


def build_evidence_inbound_subscriber(
    config: Config,
    attestor: FirstPartyEvidenceAttestor | None,
    envelope_state: GatewayEnvelopeState | None = None,
) -> MqttEvidenceInboundSubscriber | None:
    """Instantiate the inbound authority-artifact route when configured.

    Requires a gateway and a started attestor. Without the attestor there is no
    ledger to apply anything to, and subscribing anyway would leave a runtime
    acknowledging receipt of artifacts it cannot record -- which is worse than
    not listening, because the gateway would stop retrying.

    Envelope authentication is defense in depth rather than the proof. Every
    artifact carries its own authenticator, verified under key material this
    transport never sees: custody under the dedicated custody secret, receipts
    and epoch confirmations under authority keys from the signed release. An
    unauthenticated envelope therefore degrades the route rather than opening
    it, which is why development may run without one while staging and
    production reject an auth-disabled gateway broker at config load.
    """
    if not bool(config.gateway.enabled):
        return None
    if attestor is None or not attestor.available:
        return None
    ingest = attestor.ingest
    if ingest is None:
        return None

    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[evidence-inbound] gateway.auth.enabled is false — inbound "
            "authority artifacts are accepted without envelope verification. "
            "Each artifact is still verified under its own key material, so "
            "nothing is trusted on arrival, but anything on the site network "
            "can then spend this runtime's ingest path. Enable gateway.auth "
            "for all production deployments."
        )
    try:
        router = EvidenceInboundRouter(
            device_id=config.device.id,
            ingest=ingest,
            message_auth=_build_gateway_message_auth(config, envelope_state),
        )
        subscriber = MqttEvidenceInboundSubscriber(
            broker_url=config.gateway.broker_url,
            router=router,
            device_id=config.device.id,
            tls_config=getattr(config.gateway, "tls", {}),
        )
    except Exception:
        logger.exception("[runtime] invalid inbound evidence route configuration")
        return None
    logger.info(
        "[runtime] inbound evidence route enabled on %s (envelope auth=%s)",
        subscriber.topic,
        "enabled" if auth_enabled else "disabled",
    )
    return subscriber


def build_evidence_outbound_publisher(
    config: Config,
    attestor: FirstPartyEvidenceAttestor | None,
    envelope_state: GatewayEnvelopeState | None = None,
) -> MqttEvidenceOutboundPublisher | None:
    """Instantiate the outbound carriage route when configured.

    Requires a gateway and a started attestor: without a ledger there is
    nothing to carry. Envelope authentication covers the courier's
    acknowledgements only; the artifacts themselves are device-signed end to
    end, so an unauthenticated development gateway degrades what a queued
    acknowledgement is worth rather than what the courier receives.
    """
    if not bool(config.gateway.enabled):
        return None
    if attestor is None or not attestor.available:
        return None
    outbox = attestor.outbound
    if outbox is None:
        return None
    auth_cfg = getattr(config.gateway, "auth", {}) or {}
    auth_enabled = bool(auth_cfg.get("enabled", False))
    if not auth_enabled:
        logger.warning(
            "[evidence-outbound] gateway.auth.enabled is false — courier "
            "acknowledgements are applied without envelope verification, so "
            "anything on the site network can retire a queued checkpoint. "
            "Enable gateway.auth for all production deployments."
        )
    try:
        router = EvidenceOutboundAckRouter(
            device_id=config.device.id,
            outbox=outbox,
            message_auth=_build_gateway_message_auth(config, envelope_state),
        )
        publisher = MqttEvidenceOutboundPublisher(
            broker_url=config.gateway.broker_url,
            router=router,
            device_id=config.device.id,
            outbox=outbox,
            tls_config=getattr(config.gateway, "tls", {}),
        )
    except Exception:
        logger.exception("[runtime] invalid outbound evidence route configuration")
        return None
    logger.info(
        "[runtime] outbound evidence route enabled on %s (envelope auth=%s)",
        publisher.topic,
        "enabled" if auth_enabled else "disabled",
    )
    return publisher
