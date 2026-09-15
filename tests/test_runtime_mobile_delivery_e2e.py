# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The Android payload's delivery behaviour, driven through the built binary.

`export.rs` pins `Exporter::flush` against a closure. Nothing pinned the poll
loop that calls it or the function that posts, and the whole of `main.rs` was
covered only by tests that read its text -- so deleting the upload from the loop
outright, or restoring the `?` that ended the process on a failed upload, left
every suite green.

Text cannot catch that. These cases run the binary against a fake PZEM and a
scripted receiver, which is the only place the loop, the transport and the
response rule meet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / "mobile" / "ori-runtime-mobile"
BINARY = CRATE / "target" / "debug" / "ori-runtime-mobile"

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None,
    reason="the Android payload's delivery behaviour needs cargo to build the binary",
)

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="signing a payload config needs cryptography",
)


@pytest.fixture(scope="module")
def payload() -> Path:
    """Build once for the module; a debug build of this crate is a few seconds."""
    result = subprocess.run(
        ["cargo", "build", "--locked"],
        cwd=CRATE,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    assert BINARY.exists(), BINARY
    return BINARY


def _crc16_modbus(frame: bytes) -> int:
    crc = 0xFFFF
    for byte in frame:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


class _FakePzem(threading.Thread):
    """Answers each read with a valid Modbus frame carrying a new value.

    `mode` may be changed while the payload runs: `answer`, `silent` (the
    request is read and nothing is sent, as a meter without mains behaves) or
    `bad_crc`.
    """

    daemon = True

    def __init__(self, mode: str = "answer") -> None:
        super().__init__()
        self.mode = mode
        self.requests = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.served = 0

    def run(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            while True:
                try:
                    if not conn.recv(8):
                        return
                except OSError:
                    return
                self.requests += 1
                if self.mode == "silent" or (
                    self.mode == "alternate" and self.requests % 2 == 0
                ):
                    # Hold the request unanswered. The payload times out and
                    # closes; the next poll opens a new connection.
                    continue
                self.served += 1
                frame = bytes([0x01, 0x03, 0x04]) + struct.pack(
                    ">I", 1000 + self.served
                )
                crc = _crc16_modbus(frame)
                if self.mode == "bad_crc":
                    crc ^= 0xFFFF
                try:
                    conn.sendall(frame + struct.pack("<H", crc))
                except OSError:
                    return


class _Receiver(threading.Thread):
    """A receiver whose answers a case scripts. Stores events per event id."""

    daemon = True

    def __init__(
        self,
        script: list[tuple[str, object]],
        status_script: list[tuple[str, object]] | None = None,
    ) -> None:
        super().__init__()
        self.script = list(script)
        self.status_script = list(status_script or [])
        self.calls: list[dict] = []
        self.status_calls: list[dict] = []
        self.stored: dict[str, float] = {}
        # Until this monotonic time every request is dropped unanswered, as an
        # endpoint the network cannot reach behaves.
        self.down_until = 0.0
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) or b"{}"
                if time.monotonic() < case.down_until:
                    self.close_connection = True
                    return
                if self.path.endswith("/sensor-status"):
                    self._sensor_status(raw)
                    return
                body = json.loads(raw)
                events = body.get("events", [])
                case.calls.append(
                    {
                        "sequence": body.get("sequence"),
                        "count": len(events),
                        "accept_encoding": self.headers.get("Accept-Encoding"),
                        **_request_headers(self.headers),
                    }
                )
                kind, payload = case.script.pop(0) if case.script else ("accept", None)
                if kind == "raw":
                    # The response exactly as written, header section and all.
                    self.wfile.write(payload)
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if kind == "headers":
                    # A status, headers sent exactly as listed (repeats kept),
                    # and a body; `Content-Length` is the body's unless listed.
                    status, headers, raw_body = payload
                    self.send_response(status)
                    for name, value in headers:
                        self.send_header(name, value)
                    if not any(name.lower() == "content-length" for name, _ in headers):
                        self.send_header("Content-Length", str(len(raw_body)))
                    self.end_headers()
                    self.wfile.write(raw_body)
                    if any(name.lower() == "content-length" for name, _ in headers):
                        self.close_connection = True
                    return
                if kind == "store_then_drop":
                    # Committed, and the answer never reaches the payload.
                    for event in events:
                        case.stored[event["event_id"]] = event["reading"]["value"]
                    self.close_connection = True
                    return
                if kind == "accept":
                    new = duplicate = 0
                    for event in events:
                        if event["event_id"] in case.stored:
                            duplicate += 1
                        else:
                            case.stored[event["event_id"]] = event["reading"]["value"]
                            new += 1
                    self._json(
                        200,
                        {
                            "status": "accepted" if new else "duplicate",
                            "accepted_events": new,
                            "duplicate_events": duplicate,
                            "rejected_events": [],
                        },
                    )
                elif kind == "status":
                    self._raw(int(payload), "text/plain", b"nope")
                elif kind == "suspend":
                    self._json(403, {"detail": "device is suspended"})
                elif kind == "bare403":
                    self._raw(403, "text/html", b"<html>Forbidden</html>")
                elif kind == "oversized":
                    # A receiver that stored the readings and then answered too
                    # verbosely to be read. That is the honest shape: the bytes
                    # arrived, and the payload has no way to know it.
                    for event in events:
                        case.stored[event["event_id"]] = event["reading"]["value"]
                    self._json(
                        200,
                        {
                            "status": "accepted",
                            "accepted_events": len(events),
                            "duplicate_events": 0,
                            "rejected_events": [],
                            "note": "x" * (96 * 1024),
                        },
                    )
                elif kind == "challenge403":
                    # The recorded refusal's body and media type, with an
                    # authentication challenge: an auth gateway, not the receiver.
                    raw = json.dumps({"detail": "device is suspended"}).encode()
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("WWW-Authenticate", 'Bearer realm="gateway"')
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                elif kind == "json_under_html403":
                    # The recorded detail, served as a web page.
                    self._raw(403, "text/html", b'{"detail":"device is suspended"}')
                elif kind == "trickle_oversized":
                    # More than the ceiling, then the connection held open with no
                    # end. Only a read bounded by the ceiling finishes before the
                    # client's timeout; an unbounded one waits for an end that
                    # never comes.
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b" " * (80 * 1024))
                    self.wfile.flush()
                    time.sleep(2.0)
                else:  # pragma: no cover - a case named an answer that is not scripted
                    raise AssertionError(kind)

            def _sensor_status(self, raw: bytes) -> None:
                snapshot = json.loads(raw)
                expected = hmac.new(
                    b"e2e-secret",
                    self.headers.get("X-Ori-Timestamp-Ms", "").encode() + b"." + raw,
                    hashlib.sha256,
                ).hexdigest()
                case.status_calls.append(
                    {
                        "at": time.monotonic(),
                        "raw": raw,
                        "snapshot": snapshot,
                        "signed": self.headers.get("X-Ori-Signature")
                        == f"v1={expected}",
                        **_request_headers(self.headers),
                    }
                )
                kind, payload = (
                    case.status_script.pop(0)
                    if case.status_script
                    else ("accept", None)
                )
                if kind == "accept":
                    self._json(
                        200,
                        {
                            "status": "accepted",
                            "accepted_sensors": len(snapshot["sensors"]),
                            "rejected_sensors": [],
                        },
                    )
                elif kind == "http":
                    self._raw(int(payload), "text/plain", b"not here")
                elif kind == "suspend":
                    self._json(403, {"detail": "device is suspended"})
                elif kind == "partial":
                    sensors = snapshot["sensors"]
                    self._json(
                        200,
                        {
                            "status": "partial",
                            "accepted_sensors": len(sensors) - 1,
                            "rejected_sensors": [
                                {
                                    "sensor_id": sensors[0]["sensor_id"],
                                    "reason": "unknown_state",
                                }
                            ],
                        },
                    )
                elif kind == "drop":
                    self.close_connection = True
                elif kind == "raw":
                    self.wfile.write(payload)
                    self.wfile.flush()
                    self.close_connection = True
                else:  # pragma: no cover - a case named an answer that is not scripted
                    raise AssertionError(kind)

            def _raw(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status: int, payload: dict) -> None:
                self._raw(status, "application/json", json.dumps(payload).encode())

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]

    def run(self) -> None:
        self.server.serve_forever()


def _request_headers(headers) -> dict[str, str | None]:
    return {
        "authorization": headers.get("Authorization"),
        "content_type": headers.get("Content-Type"),
        "device_id": headers.get("X-Ori-Device-Id"),
    }


def _signed_config(
    path: Path,
    pzem_port: int,
    endpoint: str,
    queue: int,
    flush_interval_s: float = 30.0,
    extra_sensors: list[dict] | None = None,
) -> str:
    """A config the payload will accept, signed per ori.config_signature.v1."""
    config = {
        "device": {"id": "phone-e2e-01", "deployment_type": "phone"},
        "sensors": [
            {
                "id": "phone-main-power",
                "type": "usb_power",
                "protocol": "usb_serial",
                "device_path": f"socket://127.0.0.1:{pzem_port}",
                "poll_interval_ms": 200,
                "timeout_ms": 400,
            },
            *(extra_sensors or []),
        ],
        "telemetry_export": {
            "enabled": True,
            "endpoint": endpoint,
            "api_key_env": "ORI_DEVICE_API_KEY",
            "timeout_ms": 700,
            "batch_size": 1,
            "max_queue_size": queue,
            "flush_interval_s": flush_interval_s,
        },
    }
    key = ed25519.Ed25519PrivateKey.generate()
    envelope = {
        "config": config,
        "schema": "ori.config_signature.v1",
        "signed_at_ms": 1719000000000,
        "signer_id": "e2e",
    }
    signature = key.sign(
        json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    )
    document = dict(config)
    document["config_signature"] = {
        "schema": "ori.config_signature.v1",
        "signer_id": "e2e",
        "signed_at_ms": 1719000000000,
        "signature": "ed25519:" + base64.b64encode(signature).decode(),
    }
    path.write_text(json.dumps(document))
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def _run(binary: Path, config: Path, anchor: str, seconds: float):
    env = dict(
        os.environ,
        ORI_DEVICE_API_KEY="e2e-secret",
        ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64=anchor,
    )
    process = subprocess.Popen(
        [str(binary), "--config", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
    )
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.05)
    still_running = process.poll() is None
    if still_running:
        process.terminate()
    output, _ = process.communicate(timeout=30)
    return still_running, process.returncode, output


def _counters(output: str) -> dict[str, int | str]:
    """The last export state the payload reported, read from its own output."""
    found: dict[str, int | str] = {}
    for line in output.splitlines():
        if "export state:" in line:
            tail = line.split("export state:")[1]
            found = {
                key: int(value) if value.isdigit() else value
                for key, value in re.findall(r"(\w+)=(\S+)", tail)
            }
    return found


def _drive(
    payload: Path,
    tmp_path: Path,
    script: list,
    seconds: float,
    queue: int = 50,
    *,
    status_script: list | None = None,
    pzem_mode: str = "answer",
    unplugged: bool = False,
    flush_interval_s: float = 30.0,
    schedule: list[tuple[float, str]] | None = None,
    down_for: float = 0.0,
    extra_sensors: list[dict] | None = None,
):
    pzem = _FakePzem(pzem_mode)
    pzem.start()
    port = pzem.port
    if unplugged:
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
    receiver = _Receiver(script, status_script)
    receiver.down_until = time.monotonic() + down_for
    receiver.start()
    config = tmp_path / "ori.yaml"
    anchor = _signed_config(
        config,
        port,
        f"http://127.0.0.1:{receiver.port}/runtime/telemetry",
        queue,
        flush_interval_s,
        extra_sensors,
    )
    for delay, mode in schedule or []:
        timer = threading.Timer(delay, lambda mode=mode: setattr(pzem, "mode", mode))
        timer.daemon = True
        timer.start()
    running, code, output = _run(payload, config, anchor, seconds)
    return running, code, output, receiver, pzem, _counters(output)


def _states(receiver: _Receiver) -> list[tuple[str, str]]:
    """Each snapshot's (state, reason) for the one declared sensor, in order."""
    return [
        (
            call["snapshot"]["sensors"][0]["state"],
            call["snapshot"]["sensors"][0]["reason"],
        )
        for call in receiver.status_calls
    ]


@pytest.mark.slow
def test_a_failed_upload_does_not_end_the_process_and_loses_no_reading(
    payload: Path, tmp_path: Path
) -> None:
    """The defect this change exists for, through the binary that had it.

    Before the fix this process exited 1 on the 503 and the batch went with it.
    """
    running, _code, _out, receiver, pzem, counters = _drive(
        payload, tmp_path, [("accept", None), ("status", 503)], 5.0
    )

    assert running, "a 503 must not end the payload"
    assert counters["dropped"] == 0, counters
    held = counters["queued"] + counters["retained"]
    assert counters["delivered"] + held == pzem.served, (
        f"every reading is delivered or in flight: served={pzem.served} {counters}"
    )
    sequences = [call["sequence"] for call in receiver.calls]
    assert sequences.count(2) == 2, f"the failed batch was re-sent: {sequences}"


@pytest.mark.slow
def test_the_poll_loop_actually_posts(payload: Path, tmp_path: Path) -> None:
    """Deleting the upload from the loop left every other suite green."""
    running, _code, _out, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("accept", None)] * 50, 3.0
    )

    assert running
    assert len(receiver.calls) >= 2, "the loop posted more than once"
    assert receiver.stored, "the receiver holds readings"
    assert counters["delivered"] == len(receiver.stored)
    for call in receiver.calls + receiver.status_calls:
        assert call["authorization"] == "Bearer e2e-secret", call
        assert call["content_type"] == "application/json", call
        assert call["device_id"] == "phone-e2e-01", call


@pytest.mark.slow
def test_a_terminal_refusal_suspends_export_and_keeps_reading(
    payload: Path, tmp_path: Path
) -> None:
    """A 403 arrives on the client's error arm, so reading it is load-bearing.

    Without the arm that recovers the response from that error, a genuinely
    suspended device retries its refused credential forever and no operator ever
    sees the suspension.
    """
    running, _code, output, receiver, pzem, counters = _drive(
        payload, tmp_path, [("accept", None), ("suspend", None)], 4.0
    )

    assert running, "a suspension stops export, not the process"
    assert "export suspended" in output
    assert counters["suspended"] == "true", counters
    assert counters["refused"] > 0, counters
    assert pzem.served > len(receiver.calls), "the meter kept being read"


@pytest.mark.slow
def test_an_intermediarys_bare_403_is_retried_rather_than_suspending(
    payload: Path, tmp_path: Path
) -> None:
    """Suspension is for the life of the credential, so a proxy must not cause it."""
    running, _code, output, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("bare403", None)] * 200, 4.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
    assert counters["refused"] == 0, counters
    assert len(receiver.calls) >= 2, "the batch was retried, not parked"


@pytest.mark.slow
def test_a_response_body_beyond_the_ceiling_is_retained_not_read(
    payload: Path, tmp_path: Path
) -> None:
    """Remote input on a phone's memory is bounded, and the bound is reported."""
    running, _code, output, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("oversized", None)] * 200, 4.0
    )

    assert running
    assert "ceiling" in output, "the ceiling is stated, not silent"
    assert counters["delivered"] == 0, "an unreadable answer is not a delivery"
    assert receiver.stored, "the receiver did store them; the payload cannot know"
    assert counters["retained"] > 0, "so the batch is held for another attempt"


@pytest.mark.slow
def test_an_authentication_challenge_reaches_the_refusal_rule(
    payload: Path, tmp_path: Path
) -> None:
    """The payload must pass the challenge header through to the rule.

    Passing nothing instead would let an auth gateway's 403, carrying a challenge
    and the recorded detail, suspend a phone's export for good.
    """
    running, _code, output, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("challenge403", None)] * 200, 4.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
    assert len(receiver.calls) >= 2, "retried rather than suspended"


@pytest.mark.slow
def test_the_real_media_type_reaches_the_refusal_rule(
    payload: Path, tmp_path: Path
) -> None:
    """A JSON-shaped detail served as a web page does not suspend.

    Were the media type assumed rather than read, any intermediary whose page
    reproduced the detail could suspend the phone.
    """
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("json_under_html403", None)] * 200, 4.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters


@pytest.mark.slow
def test_the_poll_loop_honours_the_retry_backoff(payload: Path, tmp_path: Path) -> None:
    """Against a dead endpoint the loop waits, rather than posting every poll.

    The poll interval here is 200 ms. With the backoff consulted, five seconds of
    503s allow a handful of attempts (1 s, 2 s, 4 s apart); without it, one per
    poll, around twenty-five.
    """
    running, _code, _out, receiver, pzem, _counters = _drive(
        payload, tmp_path, [("status", 503)] * 500, 5.0
    )

    assert running
    assert pzem.served >= 15, "the meter was polled throughout"
    assert len(receiver.calls) <= 7, (
        f"{len(receiver.calls)} posts in five seconds; the backoff was not consulted"
    )


@pytest.mark.slow
def test_a_body_that_never_ends_is_read_no_further_than_the_ceiling(
    payload: Path, tmp_path: Path
) -> None:
    """The read stops at the ceiling rather than waiting for the body to end.

    A receiver or intermediary that streams without end must not hold the read,
    or the phone's memory, for as long as it cares to.
    """
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("trickle_oversized", None)] * 50, 5.0
    )

    assert running
    assert "exceeds the" in output, "the ceiling ended the read and was reported"
    assert counters["delivered"] == 0
    assert counters["unreadable_responses"] >= 1, counters


@pytest.mark.slow
def test_a_configuration_refusal_exits_distinguishably_from_a_stop(
    payload: Path, tmp_path: Path
) -> None:
    """The hosting application tells an operator which of the two happened.

    A single exit code could not, and the constant that separates them was
    implemented and asserted nowhere.
    """
    config = tmp_path / "unsigned.yaml"
    config.write_text(
        json.dumps(
            {
                "device": {"id": "phone-e2e-01", "deployment_type": "phone"},
                "sensors": [],
                "telemetry_export": {
                    "enabled": True,
                    "endpoint": "https://api.example.invalid/runtime/telemetry",
                    "api_key_env": "ORI_DEVICE_API_KEY",
                },
            }
        )
    )
    running, code, output = _run(payload, config, "", 10.0)

    assert not running, "an unsigned config is refused at start-up"
    assert code == 2, f"a start-up refusal exits 2, not {code}: {output[-500:]}"
    assert "signed config" in output


@pytest.mark.slow
def test_a_silent_meter_is_reported_as_not_answering_once(
    payload: Path, tmp_path: Path
) -> None:
    """The bench fault: adapter attached, meter silent, and nothing said so.

    One snapshot, not one per poll: repeated failures of one class are not an
    edge, and the interval is longer than the run.
    """
    running, _code, _out, receiver, _pzem, counters = _drive(
        payload, tmp_path, [], 3.0, pzem_mode="silent"
    )

    assert running
    assert receiver.calls == [], "a silent meter posts no readings"
    assert _states(receiver) == [("never_read", "no_response")], _states(receiver)
    call = receiver.status_calls[0]
    assert call["signed"], "the snapshot is signed with the device key"
    entry = call["snapshot"]["sensors"][0]
    assert entry["sensor_id"] == "phone-main-power"
    assert "last_success_ms" not in entry, "absent, never null, on never_read"
    sent_at = call["snapshot"]["sent_at_ms"]
    assert abs(sent_at - time.time() * 1000) < 60_000, sent_at
    for leak in (b"socket://", b"127.0.0.1", b"e2e-secret", b"Modbus", b"timeout"):
        assert leak not in call["raw"], f"the snapshot carries {leak!r}"
    assert counters["status_accepted"] == 1, counters


@pytest.mark.slow
def test_an_unplugged_adapter_is_a_different_class_from_a_silent_meter(
    payload: Path, tmp_path: Path
) -> None:
    """A cable and a meter send an installer to different places."""
    running, _code, _out, receiver, _pzem, _counters_ = _drive(
        payload, tmp_path, [], 2.5, unplugged=True
    )

    assert running
    assert _states(receiver) == [("never_read", "interface_absent")], _states(receiver)


@pytest.mark.slow
def test_a_corrupted_answer_is_an_integrity_failure(
    payload: Path, tmp_path: Path
) -> None:
    running, _code, _out, receiver, _pzem, _counters_ = _drive(
        payload, tmp_path, [], 2.5, pzem_mode="bad_crc"
    )

    assert running
    assert receiver.calls == []
    assert _states(receiver) == [("never_read", "integrity_failed")], _states(receiver)


@pytest.mark.slow
def test_a_meter_that_stops_and_resumes_is_reported_both_ways(
    payload: Path, tmp_path: Path
) -> None:
    """Worked, then stopped, then worked: three changes, each reported.

    A change is sent once five seconds have passed since the previous snapshot,
    so the stop and the recovery are spaced to show each one and nothing else.
    """
    running, _code, _out, receiver, _pzem, _counters_ = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 400,
        13.5,
        schedule=[(1.0, "silent"), (6.5, "answer")],
    )

    assert running
    states = _states(receiver)
    assert states[0] == ("reading", "none"), states
    assert ("failing", "no_response") in states, states
    assert states[-1] == ("reading", "none"), states
    failing = next(
        call["snapshot"]["sensors"][0]
        for call in receiver.status_calls
        if call["snapshot"]["sensors"][0]["state"] == "failing"
    )
    assert failing["last_success_ms"] > 0, "a failing sensor says when it last read"
    assert len(states) == 3, f"one snapshot per edge and none between: {states}"


@pytest.mark.slow
def test_a_receiver_without_the_status_route_costs_one_request_per_interval(
    payload: Path, tmp_path: Path
) -> None:
    """A 404 on the status route discards the snapshot and grows nothing.

    Readings are unaffected, and the snapshot is not re-sent on every poll: the
    poll interval is 200 ms and the flush interval one second.
    """
    running, _code, output, receiver, _pzem, counters = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 200,
        4.0,
        status_script=[("http", 404)] * 200,
        flush_interval_s=1.0,
    )

    assert running
    assert receiver.stored, "readings are delivered whatever the status route says"
    assert counters["suspended"] == "false", counters
    assert "export suspended" not in output
    assert 2 <= len(receiver.status_calls) <= 6, (
        f"{len(receiver.status_calls)} status posts in four seconds"
    )
    assert counters["status_discarded"] >= 2, counters
    assert counters["status_accepted"] == 0, counters


@pytest.mark.slow
def test_a_terminal_refusal_on_the_status_route_suspends_readings_too(
    payload: Path, tmp_path: Path
) -> None:
    """The refusal is about the credential, so it covers both routes.

    The flush interval is one second, so a payload that kept sending status
    while suspended would post again within the run.
    """
    running, _code, output, receiver, pzem, counters = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 200,
        3.0,
        status_script=[("suspend", None)],
        flush_interval_s=1.0,
    )

    assert running, "a suspension stops export, not the process"
    assert "sensor-status route" in output
    assert counters["suspended"] == "true", counters
    assert len(receiver.status_calls) == 1, "a suspended payload sends no status"
    assert counters["status_discarded"] == 1, "a refused snapshot was not accepted"
    assert len(receiver.calls) <= 1, "and no readings after the refusal"
    assert pzem.served > len(receiver.calls), "the meter kept being read"


@pytest.mark.slow
def test_an_endpoint_unreachable_past_the_bound_drops_only_what_did_not_fit(
    payload: Path, tmp_path: Path
) -> None:
    """Down for three seconds with room for three readings, then back.

    The process keeps running, delivery resumes, and every reading the meter
    gave is delivered, still held, or counted as dropped -- none disappears.
    """
    running, _code, _out, receiver, pzem, counters = _drive(
        payload, tmp_path, [], 7.0, queue=3, down_for=3.0
    )

    assert running
    assert counters["dropped"] > 0, f"the outage outlasted the bound: {counters}"
    assert counters["delivered"] > 0, "delivery resumed when the endpoint returned"
    assert counters["delivered"] == len(receiver.stored), counters
    held = counters["queued"] + counters["retained"]
    assert counters["delivered"] + counters["dropped"] + held == pzem.served, (
        f"served={pzem.served} {counters}"
    )
    # What did not fit is what was dropped. The readings taken first were held
    # through the outage and arrive after it; a payload that dropped an
    # unanswered batch instead would balance the counts above and lose these.
    first_three = sorted(receiver.stored.values())[:3]
    assert first_three == [100.1, 100.2, 100.3], first_three


@pytest.mark.slow
def test_a_lost_acknowledgement_is_resent_as_itself_and_new_readings_are_stored(
    payload: Path, tmp_path: Path
) -> None:
    running, _code, _out, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("store_then_drop", None)], 4.0
    )

    assert running
    sequences = [call["sequence"] for call in receiver.calls]
    assert sequences[:2] == [1, 1], f"the unanswered batch was re-sent: {sequences}"
    assert max(sequences) > 1, "newer readings followed in their own batches"
    assert counters["dropped"] == 0, counters
    assert counters["delivered"] == len(receiver.stored), (
        f"the re-sent batch was delivered as a duplicate, not lost: {counters}"
    )
    assert counters["duplicate"] >= 1, counters


@pytest.mark.slow
def test_a_restarted_payload_loses_no_reading_to_a_reused_sequence(
    payload: Path, tmp_path: Path
) -> None:
    """Every run starts at sequence 1 against the same receiver.

    A receiver keyed on sequence discarded the second run's first batches as
    replays. Keyed per event, every reading each run reports delivered is held.
    """
    receiver = _Receiver([])
    receiver.start()
    config = tmp_path / "ori.yaml"
    delivered = 0
    runs: list[list[int]] = []
    for _run_index in range(3):
        pzem = _FakePzem()
        pzem.start()
        anchor = _signed_config(
            config, pzem.port, f"http://127.0.0.1:{receiver.port}/runtime/telemetry", 50
        )
        before = len(receiver.calls)
        running, _code, output = _run(payload, config, anchor, 1.5)
        assert running
        runs.append([call["sequence"] for call in receiver.calls[before:]])
        delivered += _counters(output)["delivered"]

    assert all(run and run[0] == 1 for run in runs), f"each run restarts: {runs}"
    assert delivered > 0
    assert delivered == len(receiver.stored), (
        f"a reading reported delivered is not held: delivered={delivered} "
        f"stored={len(receiver.stored)}"
    )


_REFUSAL = json.dumps({"detail": "device is suspended"}).encode()


@pytest.mark.slow
def test_no_content_coding_is_requested_and_a_coded_refusal_does_not_suspend(
    payload: Path, tmp_path: Path
) -> None:
    """A plain refusal body labelled `deflate` is unreadable, so not a refusal.

    Read as plain, it suspended this payload and not the Python producer, whose
    client decodes deflate and finds no refusal in the result.
    """
    coded = (
        403,
        [("Content-Type", "application/json"), ("Content-Encoding", "deflate")],
        _REFUSAL,
    )
    running, _code, output, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("headers", coded)] * 200, 3.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
    assert receiver.calls[0]["accept_encoding"] == "identity"


@pytest.mark.slow
def test_a_refusal_under_two_media_types_does_not_suspend(
    payload: Path, tmp_path: Path
) -> None:
    """The client keeps the first `Content-Type`; the rule must see both."""
    doubled = (
        403,
        [("Content-Type", "application/json"), ("Content-Type", "text/html")],
        _REFUSAL,
    )
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("headers", doubled)] * 200, 3.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters


@pytest.mark.slow
def test_a_valid_prefix_of_an_oversized_body_is_not_a_delivery(
    payload: Path, tmp_path: Path
) -> None:
    """Conformant JSON padded to exactly the ceiling, then one byte more.

    Sent without a length, so the body read itself must stop past the ceiling:
    the first 64 KiB alone would parse and confirm the batch.
    """
    answer = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 1,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    padded = _raw_response(
        b"HTTP/1.1 200 OK",
        [b"Content-Type: application/json", b"Connection: close"],
        answer.ljust(64 * 1024, b" ") + b" ",
    )
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("raw", padded)] * 200, 3.0
    )

    assert running
    assert "exceeds the" in output
    assert counters["delivered"] == 0, counters
    assert counters["retained"] > 0, counters


@pytest.mark.slow
def test_a_body_shorter_than_its_declared_length_is_no_answer(
    payload: Path, tmp_path: Path
) -> None:
    """Cut off, it is not read as an unreadable answer: nothing complete arrived."""
    answer = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 1,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    short = (
        200,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(answer) + 50)),
        ],
        answer,
    )
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("headers", short)] * 200, 3.0
    )

    assert running
    assert "got no answer" in output
    assert counters["delivered"] == 0, counters
    assert counters["unreadable_responses"] == 0, counters
    assert counters["retained"] > 0, counters


@pytest.mark.slow
def test_a_meter_answering_every_other_poll_does_not_post_every_poll(
    payload: Path, tmp_path: Path
) -> None:
    """Every poll is a change. Spaced, seven seconds is two snapshots at most."""
    running, _code, _out, receiver, pzem, _counters_ = _drive(
        payload, tmp_path, [("accept", None)] * 400, 7.0, pzem_mode="alternate"
    )

    assert running
    assert pzem.requests >= 10, "the meter was polled throughout"
    assert 1 <= len(receiver.status_calls) <= 2, _states(receiver)


@pytest.mark.slow
def test_a_flapping_meter_costs_a_receiver_without_the_route_one_request(
    payload: Path, tmp_path: Path
) -> None:
    """After a discard only the interval sends, however often a sensor changes."""
    running, _code, _out, receiver, _pzem, _counters_ = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 400,
        7.0,
        pzem_mode="alternate",
        status_script=[("http", 404)] * 50,
    )

    assert running
    assert len(receiver.status_calls) == 1, _states(receiver)


@pytest.mark.slow
def test_rejected_sensor_entries_are_counted_and_logged(
    payload: Path, tmp_path: Path
) -> None:
    running, _code, output, receiver, _pzem, counters = _drive(
        payload,
        tmp_path,
        [],
        2.5,
        pzem_mode="silent",
        status_script=[("partial", None)],
    )

    assert running
    assert len(receiver.status_calls) == 1
    assert counters["status_accepted"] == 1, counters
    assert counters["status_rejected_sensors"] == 1, counters
    assert "rejected 1 sensor status entry" in output


@pytest.mark.slow
def test_a_status_post_with_no_answer_is_discarded_and_ends_nothing(
    payload: Path, tmp_path: Path
) -> None:
    running, _code, output, receiver, _pzem, counters = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 200,
        3.5,
        status_script=[("drop", None)] * 50,
        flush_interval_s=1.0,
    )

    assert running
    assert "sensor status POST got no answer" in output
    assert counters["status_accepted"] == 0, counters
    assert counters["status_discarded"] >= 2, counters
    assert receiver.stored, "readings are delivered whatever happens to status"


@pytest.mark.slow
def test_a_declared_sensor_the_payload_does_not_read_is_in_the_snapshot(
    payload: Path, tmp_path: Path
) -> None:
    battery = {
        "id": "phone-battery",
        "type": "battery_percent",
        "protocol": "android_battery",
        "device_path": "",
    }
    running, _code, _out, receiver, _pzem, _counters_ = _drive(
        payload, tmp_path, [("accept", None)] * 50, 2.5, extra_sensors=[battery]
    )

    assert running
    sensors = receiver.status_calls[0]["snapshot"]["sensors"]
    assert [entry["sensor_id"] for entry in sensors] == [
        "phone-main-power",
        "phone-battery",
    ]
    assert sensors[1] == {
        "sensor_id": "phone-battery",
        "sensor_type": "battery_percent",
        "state": "never_read",
        "reason": "not_configured",
        "consecutive_failures": 0,
    }


def _raw_response(status_line: bytes, fields: list[bytes], body: bytes) -> bytes:
    return (
        status_line + b"\r\n" + b"".join(f + b"\r\n" for f in fields) + b"\r\n" + body
    )


def _chunked(body: bytes) -> bytes:
    return b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"


@pytest.mark.slow
@pytest.mark.parametrize(
    "response",
    [
        pytest.param(
            _raw_response(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b'WWW-Authenticate: Bearer realm="caf\xc3\xa9"',
                    b"Content-Length: %d" % len(_REFUSAL),
                ],
                _REFUSAL,
            ),
            id="non-ascii-challenge",
        ),
        pytest.param(
            _raw_response(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b"Transfer-Encoding: gzip, chunked",
                ],
                _chunked(_REFUSAL),
            ),
            id="transfer-coding-other-than-chunked",
        ),
        pytest.param(
            _raw_response(
                b"HTTP/1.1 403 Forbidden",
                [
                    b"Content-Type: application/json",
                    b"Content-Length: %d" % len(_REFUSAL),
                    b"Content-Length: %d" % (len(_REFUSAL) + 1),
                ],
                _REFUSAL,
            ),
            id="conflicting-content-lengths",
        ),
    ],
)
def test_a_refusal_whose_header_section_is_not_readable_alike_does_not_suspend(
    payload: Path, tmp_path: Path, response: bytes
) -> None:
    """The client drops a non-ASCII value, de-chunks any coding and takes the
    first length. Each of these reads as the recorded refusal to it alone."""
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("raw", response)] * 200, 3.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
    assert "got no answer" in output or "not readable alike" in output


@pytest.mark.slow
def test_a_coded_body_cut_short_is_unreadable_not_no_answer(
    payload: Path, tmp_path: Path
) -> None:
    """The coding is refused before the body is read, as the Python producer refuses it."""
    body = b"\x1f\x8b" + b"\x00" * 10
    response = _raw_response(
        b"HTTP/1.1 200 OK",
        [
            b"Content-Type: application/json",
            b"Content-Encoding: gzip",
            b"Content-Length: %d" % (len(body) + 40),
        ],
        body,
    )
    running, _code, _output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("raw", response)] * 200, 3.0
    )

    assert running
    assert counters["unreadable_responses"] >= 1, counters
    assert counters["delivered"] == 0, counters


@pytest.mark.slow
def test_a_coded_refusal_on_the_status_route_does_not_suspend(
    payload: Path, tmp_path: Path
) -> None:
    """The status route reads its answer under the same rules as readings.

    A plain refusal labelled `deflate`, read as plain, would suspend both
    routes from the route that carries no readings.
    """
    coded = _raw_response(
        b"HTTP/1.1 403 Forbidden",
        [
            b"Content-Type: application/json",
            b"Content-Encoding: deflate",
            b"Content-Length: %d" % len(_REFUSAL),
        ],
        _REFUSAL,
    )
    running, _code, output, receiver, _pzem, counters = _drive(
        payload,
        tmp_path,
        [("accept", None)] * 200,
        3.0,
        status_script=[("raw", coded)] * 50,
        flush_interval_s=1.0,
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
    assert len(receiver.status_calls) >= 2, "the next interval snapshot was sent"


@pytest.mark.slow
@pytest.mark.parametrize(
    "status_line", [b"HTTP/1.1 503 X", b"HTTP/1.1 200 OK", b"HTTP/1.1 403 Forbidden"]
)
def test_a_header_line_without_a_colon_does_not_end_the_payload(
    payload: Path, tmp_path: Path, status_line: bytes
) -> None:
    """The previous client panicked on such a line and the process exited 101."""
    response = _raw_response(
        status_line, [b"Content-Type: application/json", b"NotAHeaderLine"], _REFUSAL
    )
    running, code, output, receiver, pzem, counters = _drive(
        payload, tmp_path, [("raw", response)] * 200, 3.0
    )

    assert running, f"the payload ended with {code}: {output[-800:]}"
    assert "panicked" not in output
    assert counters["suspended"] == "false", counters
    assert len(receiver.calls) >= 2, "the batch was retried"
    assert pzem.served >= 5, "the meter kept being read"


@pytest.mark.slow
def test_early_hints_before_a_confirmation_deliver(
    payload: Path, tmp_path: Path
) -> None:
    """Read as the final answer, a CDN's 103 held every reading for good."""
    answer = json.dumps(
        {
            "status": "accepted",
            "accepted_events": 1,
            "duplicate_events": 0,
            "rejected_events": [],
        }
    ).encode()
    response = (
        b"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n"
        + _raw_response(
            b"HTTP/1.1 200 OK",
            [b"Content-Type: application/json", b"Content-Length: %d" % len(answer)],
            answer,
        )
    )
    running, _code, _output, receiver, _pzem, counters = _drive(
        payload, tmp_path, [("raw", response)] * 200, 3.0
    )

    assert running
    assert counters["delivered"] >= 2, counters
    assert counters["retained"] == 0, counters


@pytest.mark.slow
def test_a_refusal_with_an_invalid_field_name_does_not_suspend(
    payload: Path, tmp_path: Path
) -> None:
    """Dropping the malformed line left a refusal with no challenge, which suspended."""
    response = _raw_response(
        b"HTTP/1.1 403 Forbidden",
        [
            b"Content-Type: application/json",
            b"WWW-Authenticate : Bearer",
            b"Content-Length: %d" % len(_REFUSAL),
        ],
        _REFUSAL,
    )
    running, _code, output, _receiver, _pzem, counters = _drive(
        payload, tmp_path, [("raw", response)] * 200, 3.0
    )

    assert running
    assert "export suspended" not in output
    assert counters["suspended"] == "false", counters
