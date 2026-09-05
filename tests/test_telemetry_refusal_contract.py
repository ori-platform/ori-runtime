# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's mirror of the product API's telemetry refusal contract.

The exporter under test is the real `HttpTelemetryExporter` driven through a
real `httpx.AsyncClient`; only the socket is replaced, so status handling,
`raise_for_status` and body decoding are httpx's own. Each case is replayed
from the vendored contract rather than from a status code written here, so a
refusal the product API changes cannot pass unnoticed on this side.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from ori.config import TelemetryExportConfig
from ori.network.events import OriEvent, SensorReading
from ori.telemetry import http_export
from ori.telemetry.http_export import (
    TERMINAL_REFUSAL_STATUSES,
    HttpTelemetryExporter,
)

VECTOR_DIR = Path(__file__).parent / "vectors" / "telemetry_refusals"
VECTOR_PATH = VECTOR_DIR / "telemetry_refusals.json"
CONTRACT = json.loads(VECTOR_PATH.read_text())
CASES = {case["name"]: case for case in CONTRACT["cases"]}

API_KEY_ENV = "ORI_ENERGY_DEVICE_API_KEY"

# What the exporter must do with each recorded refusal.
#   "suspend" — stop posting, discard the batch, count it under refused_events
#   "retry"   — requeue the batch and post again on the next flush
EXPECTED_DISPOSITION = {
    "bad_credential": "retry",
    "bad_signature": "retry",
    "malformed_batch": "retry",
    "wrong_content_type": "retry",
    "suspended_device": "suspend",
}


def _config(**overrides: Any) -> TelemetryExportConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "endpoint": "https://api.example.test/runtime/telemetry",
        "api_key_env": API_KEY_ENV,
        "flush_interval_s": 30.0,
        "batch_size": 10,
        "timeout_ms": 3000,
        "max_queue_size": 10,
    }
    values.update(overrides)
    return TelemetryExportConfig(**values)


def _event(value: float = 1250.0) -> OriEvent:
    return OriEvent.from_reading(
        SensorReading(
            sensor_id="phone-main-power",
            sensor_type="usb_power",
            value=value,
            unit="watt",
            timestamp=1_000,
            quality=0.99,
            metadata={"source": "usb_serial"},
        ),
        device_id="phone-01",
    )


class _Endpoint:
    """A recorded refusal, served over a real httpx transport."""

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        headers = {}
        challenge = self.case["www_authenticate"]
        if challenge is not None:
            headers["WWW-Authenticate"] = challenge
        body: dict[str, Any] = {}
        if self.case["detail"] is not None:
            body["detail"] = self.case["detail"]
        return httpx.Response(
            self.case["status"], headers=headers, json=body, request=request
        )


def _install(monkeypatch: pytest.MonkeyPatch, endpoint: _Endpoint) -> None:
    def client_factory(*, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout, transport=httpx.MockTransport(endpoint.handler)
        )

    monkeypatch.setenv(API_KEY_ENV, "device-secret")
    monkeypatch.setattr(http_export, "_HTTPX_AVAILABLE", True)
    monkeypatch.setattr(
        http_export,
        "_httpx",
        type("_Shim", (), {"AsyncClient": staticmethod(client_factory)}),
    )


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_contract_is_the_vendored_artifact_at_the_pinned_revision() -> None:
    """The vendored bytes are the ones the manifest pins, not a local edit."""
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["source_repository"] == "ori-platform/ori-energy"
    assert len(manifest["source_commit"]) == 40
    recorded = manifest["files"][VECTOR_PATH.name]
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == recorded, (
        "the vendored contract has been edited locally; re-vendor with "
        "scripts/refresh-telemetry-refusal-fixture.sh rather than editing it here"
    )


def test_snapshot_capture_is_not_vendored() -> None:
    """Only the normative file is pinned; the full capture is not a contract."""
    assert not (VECTOR_DIR / "telemetry_refusals.snapshot.json").exists()


def test_every_recorded_case_has_a_declared_disposition() -> None:
    """A case the product API adds must be classified here before it can pass."""
    assert CONTRACT["contract_version"] == 1
    assert set(CASES) == set(EXPECTED_DISPOSITION)


def test_terminal_refusals_carry_the_detail_the_contract_records() -> None:
    """The status is half the identity; the recorded detail is the other half.

    The pairs are hand-written in `ori/`, which cannot read a test fixture.
    This is what binds them to the contract: reword the detail upstream and the
    vendored bytes change, the digest check fires, and this fails.
    """
    recorded = {
        CASES[name]["status"]: CASES[name]["detail"]
        for name, disposition in EXPECTED_DISPOSITION.items()
        if disposition == "suspend"
    }
    assert http_export.TERMINAL_REFUSALS == recorded


def test_terminal_statuses_are_exactly_the_cases_declared_terminal() -> None:
    """The terminal set matches the disposition declared for each recorded case.

    The coupling to upstream is `contract_version`, asserted above: the
    producer bumps it when the meaning of a status moves, so a meaning change
    fails here even though the table below is local. Bytes alone would not do
    that -- a status can keep its number and change what it means.
    """
    terminal = {
        CASES[name]["status"]
        for name, disposition in EXPECTED_DISPOSITION.items()
        if disposition == "suspend"
    }
    assert TERMINAL_REFUSAL_STATUSES == terminal


def test_no_terminal_case_offers_an_authentication_challenge() -> None:
    """A challenge means a fresh credential helps, which is not terminal.

    The contract records `www_authenticate` because it is the field that
    distinguishes the two. If a status classified terminal here ever starts
    carrying a challenge upstream, the classification is wrong and this is
    where that has to surface.
    """
    for name, disposition in EXPECTED_DISPOSITION.items():
        case = CASES[name]
        if disposition == "suspend":
            assert case["www_authenticate"] is None, name
        elif case["status"] == 401:
            assert case["www_authenticate"] == "Bearer", name


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(EXPECTED_DISPOSITION))
async def test_recorded_refusal_is_dispositioned_as_declared(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retried refusal is posted again; a terminal one is never posted again."""
    endpoint = _Endpoint(CASES[name])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert len(endpoint.requests) == 1

    await exporter.flush_once()

    if EXPECTED_DISPOSITION[name] == "suspend":
        assert exporter.export_suspended is True
        assert len(endpoint.requests) == 1
        assert exporter.refused_events == 1
        assert exporter.dropped_events == 0
    else:
        assert exporter.export_suspended is False
        assert len(endpoint.requests) == 2
        assert exporter.refused_events == 0


@pytest.mark.asyncio
async def test_suspension_reports_the_recorded_status_and_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The observable state names the status and detail the endpoint returned."""
    case = CASES["suspended_device"]
    endpoint = _Endpoint(case)
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()

    status = exporter.status_snapshot()
    assert status["suspended"] is True
    assert status["refusal_status"] == case["status"]
    assert status["refusal_detail"] == case["detail"]
    assert status["refused_at_ms"] > 0
    assert status["refused_events"] == 1
    assert status["dropped_events"] == 0


@pytest.mark.asyncio
async def test_events_arriving_after_suspension_are_not_counted_as_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once suspended, a refusal never presents as a queue that fell behind.

    Scoped to after suspension deliberately. Events produced while the refused
    request is still in flight are queued, because nothing yet knows the
    endpoint has refused, and a full queue charges them to `dropped_events`.
    That window is one request long and is not what this asserts.
    """
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(max_queue_size=1)
    )
    await exporter.handle_event(_event())
    await exporter.flush_once()

    for _ in range(5):
        await exporter.handle_event(_event())

    assert exporter.dropped_events == 0
    assert exporter.refused_events == 6
    assert len(endpoint.requests) == 1


@pytest.mark.asyncio
async def test_a_challenged_403_is_an_intermediary_and_does_not_suspend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A captive portal answers 403 with a challenge; the endpoint never does.

    Suspending here would stop telemetry for the process lifetime because a
    phone joined a hotel or corporate network, and no recorded case that is
    terminal carries a challenge.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"WWW-Authenticate": 'Basic realm="portal"'},
            content=b"<html>sign in</html>",
            request=request,
        )

    endpoint = _Endpoint(CASES["suspended_device"])
    endpoint.handler = handler  # type: ignore[method-assign]
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()
    await exporter.flush_once()

    assert exporter.export_suspended is False
    assert exporter.refused_events == 0


@pytest.mark.asyncio
async def test_a_403_without_a_challenge_still_suspends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The challenge is the discriminator, so its absence must still suspend."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()

    assert exporter.export_suspended is True


@pytest.mark.parametrize(
    "label,headers,body",
    [
        (
            "portal challenge",
            {"WWW-Authenticate": 'Basic realm="portal"', "Content-Type": "text/html"},
            b"<html>sign in</html>",
        ),
        ("waf html", {"Content-Type": "text/html"}, b"<html>forbidden</html>"),
        ("bare body, no media type", {}, b"forbidden"),
        (
            "json media type, unstructured body",
            {"Content-Type": "application/json"},
            b'"forbidden"',
        ),
        (
            "json object with no detail",
            {"Content-Type": "application/json"},
            b'{"error":"forbidden"}',
        ),
        (
            "json detail that is not a string",
            {"Content-Type": "application/json"},
            b'{"detail":{"code":7}}',
        ),
        # Each conjunct needs a case where only it disqualifies, or dropping
        # that conjunct passes on the strength of the others.
        (
            "structured body under a non-json media type",
            {"Content-Type": "text/html"},
            b'{"detail":"device is suspended"}',
        ),
        (
            "challenge alongside a structured body",
            {"WWW-Authenticate": "Bearer", "Content-Type": "application/json"},
            b'{"detail":"device is suspended"}',
        ),
        (
            "structured body whose detail is not the recorded one",
            {"Content-Type": "application/json"},
            b'{"detail":"access denied"}',
        ),
    ],
)
@pytest.mark.asyncio
async def test_a_403_that_is_not_the_recorded_shape_does_not_suspend(
    label: str,
    headers: dict[str, str],
    body: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the recorded refusal suspends; every other 403 is retried.

    Suspension is irreversible for the process, so an intermediary's 403 must
    never cause it. An absent challenge is not evidence of origin -- a proxy
    returns a bare 403 too -- so the media type and the structured `detail`
    the contract records are required as well.
    """

    attempts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        return httpx.Response(403, headers=headers, content=body, request=request)

    endpoint = _Endpoint(CASES["suspended_device"])
    endpoint.handler = handler  # type: ignore[method-assign]
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()
    await exporter.flush_once()

    assert exporter.export_suspended is False, label
    assert exporter.refused_events == 0, label
    # Posted again rather than parked: the batch survives an intermediary.
    assert len(attempts) == 2, label
    assert exporter._queue.qsize() == 1, label


def test_a_response_carrying_no_headers_is_not_read_as_the_endpoint() -> None:
    """Absent headers cannot be evidence of origin, so they never suspend."""

    class _NoHeaders:
        status_code = 403

        def json(self) -> dict[str, str]:
            return {"detail": "device is suspended"}

    assert http_export._is_terminal_refusal(403, _NoHeaders()) is False


@pytest.mark.asyncio
async def test_the_recorded_refusal_shape_is_what_the_endpoint_actually_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shape required here is the one the contract records, not a guess.

    `_Endpoint` replays the recorded case through `httpx.Response(json=...)`,
    which sets `application/json` and a `detail` object exactly as the product
    API does. If the endpoint stopped sending either, this suspension stops
    happening and the retry path takes over -- visibly, not silently.
    """
    case = CASES["suspended_device"]
    assert case["www_authenticate"] is None
    assert isinstance(case["detail"], str) and case["detail"]

    endpoint = _Endpoint(case)
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()

    sent = endpoint.requests[0]
    assert sent is not None
    assert exporter.export_suspended is True
    assert exporter.status_snapshot()["refusal_detail"] == case["detail"]


@pytest.mark.asyncio
async def test_a_changed_credential_resumes_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Suspension is bound to the refused credential, not to the process.

    A re-issued credential is noticed on the next flush; events produced before
    that flush were refused while the old credential was still in force, so the
    batch that proves resumption is the one queued after it.
    """
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()
    assert exporter.export_suspended is True

    monkeypatch.setenv(API_KEY_ENV, "reissued-secret")
    await exporter.flush_once()
    assert exporter.export_suspended is False

    await exporter.handle_event(_event())
    await exporter.flush_once()

    assert len(endpoint.requests) == 2
    assert endpoint.requests[1].headers["Authorization"] == "Bearer reissued-secret"


@pytest.mark.asyncio
async def test_an_unset_credential_does_not_resume_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing the credential is not a new credential, so nothing is posted."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()

    monkeypatch.delenv(API_KEY_ENV, raising=False)
    await exporter.handle_event(_event())
    await exporter.flush_once()

    assert exporter.export_suspended is True
    assert len(endpoint.requests) == 1


@pytest.mark.asyncio
async def test_the_same_credential_reoffered_does_not_resume_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-reading an unchanged credential is not a change, so nothing is posted."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()

    monkeypatch.setenv(API_KEY_ENV, "device-secret")
    await exporter.handle_event(_event())
    await exporter.flush_once()

    assert exporter.export_suspended is True
    assert len(endpoint.requests) == 1


@pytest.mark.asyncio
async def test_a_network_failure_keeps_retrying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport error is not a refusal, so the batch is retained and retried."""
    attempts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        raise httpx.ConnectError("network down", request=request)

    endpoint = _Endpoint(CASES["suspended_device"])
    endpoint.handler = handler  # type: ignore[method-assign]
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()
    await exporter.flush_once()

    assert exporter.export_suspended is False
    assert exporter.refused_events == 0
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_a_success_after_a_retryable_refusal_exports_the_retained_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained batch is the same events, exported once the endpoint accepts."""
    responses = [CASES["bad_credential"], None]

    def handler(request: httpx.Request) -> httpx.Response:
        case = responses.pop(0)
        if case is None:
            return httpx.Response(200, json={"accepted": 1}, request=request)
        return httpx.Response(case["status"], json={}, request=request)

    endpoint = _Endpoint(CASES["bad_credential"])
    endpoint.handler = handler  # type: ignore[method-assign]
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    assert await exporter.flush_once() == 0
    assert await exporter.flush_once() == 1
    assert exporter.export_suspended is False


def test_export_state_reaches_nothing_outside_the_exporter_and_its_report() -> None:
    """Export state stays outside every path that decides or executes anything.

    Scoping this to a few packages would leave the ones that matter most
    unscanned: `ori/safety` computes the protection claim, and `ori/policy`
    decides entitlement. So the rule is the whole package, with two openings
    named explicitly -- the exporter itself, and the single health helper that
    reports it -- and every spelling that could carry the state across.
    """
    root = Path(__file__).resolve().parents[1] / "ori"
    names = (
        "export_suspended",
        "refused_events",
        "TERMINAL_REFUSAL_STATUSES",
        "status_snapshot",
        "HttpTelemetryExporter",
        "_telemetry_exporter",
        "TelemetryExportRefusedError",
    )
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if relative.parts[0] == "telemetry":
            continue
        text = path.read_text()
        if relative.as_posix() == "runtime.py":
            # The runtime constructs the exporter and reports it. Everything
            # else it does with export state would be a new coupling, so the
            # allowance is the two functions, not the file.
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name in {
                    "_telemetry_export_health",
                    "_start_telemetry_export_if_enabled",
                }:
                    continue
                body = ast.get_source_segment(text, node) or ""
                carrying = [
                    line.strip()
                    for line in body.splitlines()
                    if any(name in line for name in names)
                ]
                if node.name == "__init__":
                    # Holding the exporter is not reading its state. The
                    # declaration is allowed; anything else in __init__ is not.
                    carrying = [
                        line
                        for line in carrying
                        if line
                        != "self._telemetry_exporter: HttpTelemetryExporter | None = None"
                    ]
                if carrying:
                    offenders.append(f"runtime.py::{node.name}")
            continue
        for name in names:
            if name in text:
                offenders.append(f"{relative.as_posix()} ({name})")
    assert offenders == [], (
        f"export state must not reach anything that decides or executes: {offenders}"
    )


@pytest.mark.asyncio
async def test_final_flush_at_shutdown_posts_nothing_while_suspended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shutdown does not retry a refusal the endpoint has already given."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()

    shutdown = asyncio.Event()
    shutdown.set()
    await exporter.serve_until(shutdown)

    assert len(endpoint.requests) == 1


@pytest.mark.asyncio
async def test_a_partial_batch_leaves_no_queue_behind_when_suspended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Events the refused batch did not carry are discarded and counted too."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(
        device_id="phone-01", config=_config(batch_size=2, max_queue_size=10)
    )
    for _ in range(5):
        await exporter.handle_event(_event())

    await exporter.flush_once()

    assert exporter.export_suspended is True
    assert exporter._queue.qsize() == 0
    assert exporter.refused_events == 5
    assert exporter.dropped_events == 0


@pytest.mark.asyncio
async def test_no_response_text_reaches_the_reported_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported detail is the recorded constant, never the endpoint's bytes.

    A response that is not the recorded refusal does not suspend at all, so
    the only detail that can be retained is the one already written down here.
    That leaves no path for remote text of any length to enter a local report.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            headers={"Content-Type": "application/json"},
            content=b'{"detail":"device is suspended"}',
            request=request,
        )

    endpoint = _Endpoint(CASES["suspended_device"])
    endpoint.handler = handler  # type: ignore[method-assign]
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    await exporter.flush_once()

    detail = exporter.status_snapshot()["refusal_detail"]
    assert detail == http_export.TERMINAL_REFUSALS[403]
    assert detail is http_export.TERMINAL_REFUSALS[403]


@pytest.mark.asyncio
async def test_the_status_snapshot_carries_no_credential_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither the credential nor its digest is reportable."""
    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()

    rendered = json.dumps(exporter.status_snapshot())
    assert "device-secret" not in rendered
    assert hashlib.sha256(b"device-secret").hexdigest() not in rendered


@pytest.mark.asyncio
async def test_a_suspension_is_reported_by_the_real_health_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime's own health snapshot carries the condition."""
    from ori.runtime import OriRuntime

    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())
    await exporter.flush_once()

    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "phone-01"
    runtime._telemetry_exporter = exporter
    snapshot = await runtime._build_health_snapshot()

    assert snapshot["telemetry_export"]["enabled"] is True
    assert snapshot["telemetry_export"]["suspended"] is True
    assert snapshot["telemetry_export"]["refusal_status"] == 403
    assert snapshot["telemetry_export"]["refused_events"] == 1


@pytest.mark.asyncio
async def test_a_suspension_does_not_degrade_the_health_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Product account state must not reach the device's health verdict.

    A suspension is reported and nothing else. Degrading `status` would put
    billing state on a path that a fleet consumer reads as the device being
    less able to protect, which it is not.
    """
    from ori.runtime import OriRuntime

    endpoint = _Endpoint(CASES["suspended_device"])
    _install(monkeypatch, endpoint)
    exporter = HttpTelemetryExporter(device_id="phone-01", config=_config())
    await exporter.handle_event(_event())

    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "phone-01"
    runtime._telemetry_exporter = exporter
    before = await runtime._build_health_snapshot()

    await exporter.flush_once()
    assert exporter.export_suspended is True
    after = await runtime._build_health_snapshot()

    assert after.get("status") == before.get("status")
    assert after.get("critical") == before.get("critical")
    assert after.get("degradation_reasons") == before.get("degradation_reasons")


@pytest.mark.asyncio
async def test_health_reports_export_disabled_when_no_exporter_is_running() -> None:
    """A device that exports nothing says so rather than omitting the key."""
    from ori.runtime import OriRuntime

    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "phone-01"
    snapshot = await runtime._build_health_snapshot()

    assert snapshot["telemetry_export"] == {"enabled": False}
