# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-posture/v1 Publication: when a record goes out, and that it never
goes out unsigned, stale or without its inputs."""

import asyncio
import base64
import contextlib
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.gateway.posture_publisher import (
    PostureContent,
    PostureSchedule,
    RuntimePosturePublisher,
    installed_alert_classes,
)
from ori.security.posture import SIGNING_DOMAIN, PostureMembers, build_record
from ori.security.signing_clock import SigningClockUnavailableError

CONTENT = PostureContent(
    device_id="site-a-edge-01",
    release=None,
    deployment_profile="production",
    commissioned_binding=None,
    alert_classes=(),
)
KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"ori runtime-posture/v1 posture A test key").digest()
)


# --- the schedule --------------------------------------------------------------


def test_nothing_is_published_in_the_first_minute() -> None:
    schedule = PostureSchedule(1000.0)
    assert not schedule.due(1059.999, CONTENT)
    assert schedule.due(1060.0, CONTENT)


def test_a_record_is_refreshed_every_sixty_seconds_and_at_once_on_a_change() -> None:
    schedule = PostureSchedule(0.0)
    schedule.published(60.0, 60.0, CONTENT)
    # Due two polls early, so even a late poll finds it within 60 s of the last send.
    assert not schedule.due(117.999, CONTENT)
    assert schedule.due(118.0, CONTENT)
    assert schedule.due(61.0, replace(CONTENT, deployment_profile="staging"))


def test_at_most_two_records_in_any_ten_seconds() -> None:
    schedule = PostureSchedule(0.0)
    schedule.published(60.0, 60.0, CONTENT)
    schedule.published(61.0, 61.0, CONTENT)
    assert not schedule.allowed(69.999)
    assert schedule.allowed(70.0)


def test_at_most_five_records_in_any_minute() -> None:
    schedule = PostureSchedule(0.0)
    for at in (60.0, 70.0, 80.0, 90.0, 100.0):
        schedule.published(at, at, CONTENT)
    assert not schedule.allowed(110.0)
    assert not schedule.allowed(119.999)
    assert schedule.allowed(120.0)


# --- the publisher ---------------------------------------------------------------


class _Signer:
    def __init__(self) -> None:
        self.key_loaded = True
        self.generation: int | None = 1

    def posture_public_key(self) -> bytes | None:
        return KEY.public_key().public_bytes_raw() if self.key_loaded else None

    async def posture_boot_generation(self) -> int | None:
        return self.generation

    def sign_posture_record(self, members: PostureMembers) -> bytes | None:
        return build_record(
            members, public_key=KEY.public_key().public_bytes_raw(), sign=KEY.sign
        )


class _Client:
    def __init__(self, rc: int = 0) -> None:
        self.rc = rc
        self.sent: list[tuple[str, bytes, int, bool]] = []

    def publish(self, topic: str, payload: bytes, *, qos: int, retain: bool) -> Any:
        self.sent.append((topic, payload, qos, retain))
        return SimpleNamespace(rc=self.rc)


def _publisher(
    signer: _Signer, clock: list[float], issued: list[int], content: Any = None
) -> RuntimePosturePublisher:
    def issue() -> int:
        if not issued:
            raise SigningClockUnavailableError("no claimed value")
        return issued.pop(0)

    return RuntimePosturePublisher(
        broker_url="mqtt://127.0.0.1:1883",
        device_id=CONTENT.device_id,
        content=content or (lambda: CONTENT),
        signer=signer,
        issue_time=issue,
        client_factory=lambda **_: None,
        monotonic=lambda: clock[0],
    )


def _verified(record: bytes) -> dict[str, Any]:
    body = json.loads(record)
    signature = base64.b64decode(body.pop("signature"))
    unsigned = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    KEY.public_key().verify(signature, SIGNING_DOMAIN + unsigned)
    return body


async def test_records_go_out_retained_at_qos_1_each_new_and_in_sequence() -> None:
    clock, signer, client = [0.0], _Signer(), _Client()
    publisher = _publisher(signer, clock, [1_000, 2_000, 3_000])
    assert await publisher.publish_if_due(client) is None
    for at in (60.0, 120.0):
        clock[0] = at
        assert await publisher.publish_if_due(client) is not None
    signer.generation = 2
    clock[0] = 180.0
    await publisher.publish_if_due(client)

    assert [(t, q, r) for t, _, q, r in client.sent] == [
        ("ori/site-a-edge-01/runtime/posture", 1, True)
    ] * 3
    records = [_verified(payload) for _, payload, _, _ in client.sent]
    assert [(r["boot_generation"], r["posture_seq"]) for r in records] == [
        (1, 1),
        (1, 2),
        (2, 1),
    ]
    assert len({payload for _, payload, _, _ in client.sent}) == 3


@pytest.mark.parametrize("missing", ["key", "generation", "clock", "content"])
async def test_without_an_input_nothing_is_published(missing: str) -> None:
    clock, signer, client = [60.0], _Signer(), _Client()
    issued = [1_000]
    content: Any = None
    if missing == "key":
        signer.key_loaded = False
    elif missing == "generation":
        signer.generation = None
    elif missing == "clock":
        issued = []
    else:
        content = lambda: None  # noqa: E731
    clock[0] = 0.0
    publisher = _publisher(signer, clock, issued, content)
    clock[0] = 60.0
    assert await publisher.publish_if_due(client) is None
    assert client.sent == []


async def test_a_member_v1_cannot_carry_publishes_nothing() -> None:
    clock, client = [60.0], _Client()
    content = replace(CONTENT, alert_classes=tuple(f"c{i}" for i in range(11)))
    clock[0] = 0.0
    publisher = _publisher(_Signer(), clock, [1_000], lambda: content)
    clock[0] = 60.0
    assert await publisher.publish_if_due(client) is None
    assert client.sent == []


async def test_a_refused_publish_still_counts_and_keeps_its_sequence() -> None:
    """paho can keep a refused message queued and send it on reconnect, so the
    record counts in the windows and its pair is never reissued."""
    clock, client = [0.0], _Client(rc=4)
    publisher = _publisher(_Signer(), clock, [1_000, 2_000])
    clock[0] = 60.0
    with pytest.raises(RuntimeError):
        await publisher.publish_if_due(client)
    client.rc = 0
    clock[0] = 61.0
    assert await publisher.publish_if_due(client) is None
    clock[0] = 120.0
    record = await publisher.publish_if_due(client)
    assert record is not None and _verified(record)["posture_seq"] == 2


async def test_a_record_that_cannot_be_signed_uses_no_sequence() -> None:
    clock, client = [0.0], _Client()
    content = [replace(CONTENT, alert_classes=tuple(f"c{i}" for i in range(11)))]
    publisher = _publisher(_Signer(), clock, [1_000, 2_000], lambda: content[0])
    clock[0] = 60.0
    assert await publisher.publish_if_due(client) is None
    content[0] = CONTENT
    record = await publisher.publish_if_due(client)
    assert record is not None and _verified(record)["posture_seq"] == 1


def test_alert_classes_come_only_from_installed_first_party_handlers() -> None:
    skills = [
        SimpleNamespace(name="energy", first_party=True, triggers=[{"name": "spike"}]),
        SimpleNamespace(name="energy", first_party=False, triggers=[{"name": "x"}]),
        SimpleNamespace(
            name="gen", first_party=True, triggers=[SimpleNamespace(name="run")]
        ),
    ]
    table = {("energy", "spike"): "unusual_consumption_spike", ("energy", "x"): "c"}
    table[("gen", "run")] = "generator_running_too_long"
    assert installed_alert_classes(skills, lambda s, t: table.get((s, t))) == (
        "generator_running_too_long",
        "unusual_consumption_spike",
    )


async def test_the_same_publisher_publishes_when_every_input_is_present() -> None:
    """The control for the refusals above: due and allowed, it does publish."""
    clock, client = [0.0], _Client()
    publisher = _publisher(_Signer(), clock, [1_000])
    clock[0] = 60.0
    assert await publisher.publish_if_due(client) is not None


# --- wiring ------------------------------------------------------------------------


def _config(*, gateway: bool = True) -> Any:
    return SimpleNamespace(
        gateway=SimpleNamespace(
            enabled=gateway, broker_url="mqtt://127.0.0.1:1883", tls={}
        ),
        device=SimpleNamespace(id="site-a-edge-01", deployment_profile="staging"),
    )


def test_the_publisher_exists_only_with_the_gateway_clock_and_key() -> None:
    from ori.runtime._gateway_wiring import build_runtime_posture_publisher

    state: Any = SimpleNamespace(
        signing_clock=SimpleNamespace(issue=lambda: 1, durable=True)
    )
    transient: Any = SimpleNamespace(
        signing_clock=SimpleNamespace(issue=lambda: 1, durable=False)
    )
    signer = _Signer()
    assert build_runtime_posture_publisher(_config(), state, signer, lambda: None)
    assert (
        build_runtime_posture_publisher(
            _config(gateway=False), state, signer, lambda: None
        )
        is None
    )
    assert (
        build_runtime_posture_publisher(_config(), None, signer, lambda: None) is None
    )
    assert build_runtime_posture_publisher(_config(), state, None, lambda: None) is None
    # v1: a clock that does not survive a restart is no signing clock.
    assert (
        build_runtime_posture_publisher(_config(), transient, signer, lambda: None)
        is None
    )


def test_the_content_is_read_from_the_run_with_a_null_release() -> None:
    from ori.runtime._posture import posture_content, posture_key_readback

    runtime = SimpleNamespace(
        _config=_config(),
        _commissioning_state=SimpleNamespace(
            in_force=SimpleNamespace(canonical_hash="sha256:" + "ab" * 32)
        ),
        _loaded_skills=[],
        _evidence_attestor=_Signer(),
    )

    def content() -> Any:
        return posture_content(
            runtime._config, runtime._commissioning_state, runtime._loaded_skills
        )

    assert content() == PostureContent(
        device_id="site-a-edge-01",
        release=None,
        deployment_profile="staging",
        commissioned_binding="sha256:" + "ab" * 32,
        alert_classes=(),
    )
    runtime._commissioning_state = None
    assert content().commissioned_binding is None
    assert posture_key_readback(runtime) == (
        "site-a-edge-01",
        KEY.public_key().public_bytes_raw(),
    )
    runtime._evidence_attestor.key_loaded = False
    assert posture_key_readback(runtime) is None
    assert posture_content(None, None, []) is None


async def test_a_publication_counts_so_the_next_waits_for_its_due_time() -> None:
    clock, client = [0.0], _Client()
    publisher = _publisher(_Signer(), clock, [1_000, 2_000])
    clock[0] = 60.0
    assert await publisher.publish_if_due(client) is not None
    clock[0] = 61.0
    assert await publisher.publish_if_due(client) is None
    assert len(client.sent) == 1


# --- release, from the verified bundle the installation came from -------------


def _release(tmp_path: Any, name: str, manifest: object) -> Any:
    from ori.security.release_bundles import RELEASE_MANIFEST

    release = tmp_path / name
    (release / "venv").mkdir(parents=True)
    if manifest is not None:
        raw = manifest if isinstance(manifest, bytes) else json.dumps(manifest).encode()
        (release / RELEASE_MANIFEST).write_bytes(raw)
    return release


MANIFEST = {
    "schema": "ori.runtime_release_bundle_manifest.v1",
    "runtime_version": "2.5.1",
}


@pytest.mark.parametrize(
    ("name", "manifest", "expected"),
    [
        ("2.5.1", MANIFEST, "2.5.1"),
        ("2.5.1-rc.2", MANIFEST | {"runtime_version": "2.5.1-rc.2"}, "2.5.1-rc.2"),
        ("2.5.1", None, None),
        ("2.5.2", MANIFEST, None),
        ("2.5.1", MANIFEST | {"schema": "other"}, None),
        ("2.5.1beta", MANIFEST | {"runtime_version": "2.5.1beta"}, None),
        ("2.5.1", b"not json", None),
        ("2.5.1", ["2.5.1"], None),
    ],
    ids=[
        "verified",
        "candidate",
        "no manifest",
        "another release's manifest",
        "another schema",
        "not a release version",
        "not json",
        "not an object",
    ],
)
def test_release_is_the_verified_manifest_that_names_its_release(
    tmp_path: Any, name: str, manifest: object, expected: str | None
) -> None:
    from ori.runtime._posture import installed_release

    release = _release(tmp_path, name, manifest)
    installed_release.cache_clear()
    assert installed_release(str(release / "venv")) == expected


def test_code_not_running_from_a_release_venv_has_no_release(tmp_path: Any) -> None:
    from ori.runtime._posture import installed_release

    release = _release(tmp_path, "2.5.1", MANIFEST)
    (release / "env").mkdir()
    installed_release.cache_clear()
    assert installed_release(str(release / "env")) is None


# --- across the awaits: current content, windows judged when sent ------------


class _SlowSigner(_Signer):
    """A boot lookup that waits, as the evidence worker can, and moves time."""

    def __init__(self, clock: list[float], advance: float = 0.0) -> None:
        super().__init__()
        self.clock = clock
        self.advance = advance
        self.release = asyncio.Event()

    async def posture_boot_generation(self) -> int | None:
        await self.release.wait()
        self.clock[0] += self.advance
        return self.generation


async def test_a_change_during_the_boot_lookup_is_what_gets_signed() -> None:
    clock, client = [0.0], _Client()
    signer = _SlowSigner(clock)
    live = [CONTENT]
    publisher = _publisher(signer, clock, [1_000], lambda: live[0])
    clock[0] = 60.0
    task = asyncio.create_task(publisher.publish_if_due(client))
    await asyncio.sleep(0)
    live[0] = replace(CONTENT, commissioned_binding="sha256:" + "c" * 64)
    signer.release.set()
    record = await task

    assert record is not None
    assert _verified(record)["commissioned_binding"] == "sha256:" + "c" * 64


async def test_a_slow_preparation_never_lets_three_through_in_ten_seconds() -> None:
    clock, client = [0.0], _Client()
    signer = _SlowSigner(clock, advance=40.0)
    live = [CONTENT]
    publisher = _publisher(signer, clock, [1_000, 2_000, 3_000], lambda: live[0])
    clock[0] = 60.0
    signer.release.set()
    sent: list[float] = []
    for at, profile in (
        (60.0, "staging"),
        (100.0, "development"),
        (101.0, "production"),
    ):
        if clock[0] < at:
            clock[0] = at
        live[0] = replace(CONTENT, deployment_profile=profile)
        signer.advance = 40.0 if at == 60.0 else 0.0
        if await publisher.publish_if_due(client) is not None:
            sent.append(clock[0])
    assert all(sum(1 for s in sent if t <= s < t + 10) <= 2 for t in sent)


class _TimedClient(_Client):
    """Records when each submission reaches it; *slow* says how long each takes."""

    def __init__(self, clock: list[float], slow: list[float], rc: int = 0) -> None:
        super().__init__(rc)
        self.clock = clock
        self.slow = slow
        self.at: list[float] = []

    def publish(self, topic: str, payload: bytes, *, qos: int, retain: bool) -> Any:
        self.at.append(self.clock[0])
        self.clock[0] += self.slow.pop(0) if self.slow else 0.0
        return super().publish(topic, payload, qos=qos, retain=retain)


async def _poll(
    publisher: RuntimePosturePublisher,
    client: _TimedClient,
    clock: list[float],
    until: float,
) -> None:
    """The publisher's loop: a check, then the poll interval, on one clock."""
    from ori.gateway.posture_publisher import POLL_S

    while clock[0] < until:
        try:
            await publisher.publish_if_due(client)
        except RuntimeError:
            pass
        clock[0] += POLL_S


async def test_a_slow_publish_never_delays_the_refresh_past_sixty_seconds() -> None:
    clock = [0.0]
    client = _TimedClient(clock, slow=[30.0, 30.0])
    publisher = _publisher(_Signer(), clock, list(range(1_000, 9_000, 1_000)))
    await _poll(publisher, client, clock, until=300.0)

    assert len(client.at) >= 4
    assert all(b - a <= 60.0 for a, b in zip(client.at, client.at[1:], strict=False))


async def test_a_slow_publish_is_counted_when_it_returns() -> None:
    clock = [0.0]
    client = _TimedClient(clock, slow=[30.0], rc=4)
    live = [CONTENT]
    publisher = _publisher(_Signer(), clock, [1_000, 2_000, 3_000], lambda: live[0])
    clock[0] = 60.0
    with pytest.raises(RuntimeError):
        await publisher.publish_if_due(client)
    assert clock[0] == 90.0
    client.rc = 0
    for at, profile in ((91.0, "staging"), (92.0, "development")):
        clock[0] = at
        live[0] = replace(CONTENT, deployment_profile=profile)
        await publisher.publish_if_due(client)

    # Counted at 90 and 91: the third, at 92, is held.
    assert client.at == [60.0, 91.0]


async def test_refused_submissions_count_toward_five_in_any_minute() -> None:
    clock = [0.0]
    client = _TimedClient(clock, slow=[], rc=4)
    live = [CONTENT]
    publisher = _publisher(
        _Signer(), clock, list(range(1_000, 9_000, 1_000)), lambda: live[0]
    )
    clock[0] = 60.0
    for n, at in enumerate((60.0, 70.0, 80.0, 90.0, 100.0, 110.0, 119.0)):
        clock[0] = at
        live[0] = replace(CONTENT, deployment_profile=("staging", "development")[n % 2])
        with pytest.raises(RuntimeError) if n < 5 else contextlib.nullcontext():
            await publisher.publish_if_due(client)

    assert client.at == [60.0, 70.0, 80.0, 90.0, 100.0]


async def test_the_installation_manifest_is_read_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    from ori.runtime import OriRuntime
    from tests.package_layout import patch_runtime

    readers: list[bool] = []

    def installed_release() -> None:
        readers.append(threading.current_thread() is threading.main_thread())

    class _Posture:
        async def serve_until(self, _event: asyncio.Event) -> None:
            return None

    patch_runtime(monkeypatch, "installed_release", installed_release)
    patch_runtime(
        monkeypatch, "build_runtime_node_heartbeat_publisher", lambda *_a: None
    )
    patch_runtime(
        monkeypatch, "build_runtime_posture_publisher", lambda *_a: _Posture()
    )
    runtime: Any = OriRuntime(config_path="ori.yaml")

    async def no_operator(*_a: Any) -> None:
        return None

    runtime._start_firmware_mqtt_operator_if_enabled = no_operator
    context = SimpleNamespace(
        config=_config(), gateway_envelope_state=None, evidence_attestor=None
    )
    await runtime._stage_operator_services(context)
    for task in runtime._background_tasks:
        await task

    assert readers == [False]
