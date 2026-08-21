# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Operator-facing output must not give the operator a role in the evidence path.

The evidence a device produces constrains the conduct of the site running it.
That only means something while the site cannot reach, influence, or be asked
to carry the record.

What is protectable is narrow, and stating it precisely matters more than
stating it broadly:

  MUST NOT appear — an implementation identity, an endpoint, a deployment
  location, a credential, a key-custody detail, an administrative surface, or
  any instruction implying the operator transfers, registers or forwards
  something.

  MAY appear, and should — generic delivery health, so an operator can see that
  evidence is degraded without learning who it is degraded toward.

Abstract existence is not on that list and cannot be: this runtime is open
source and ships a public contract, so a reader can infer an independent
authority exists. Promising otherwise would be an assertion the repository
itself disproves.

The private component's name is deliberately absent from this file. Writing it
here to assert its absence elsewhere would publish it in a public repository.
Real names arrive through ORI_DISCLOSURE_DENYLIST so a private CI can assert
against them without this repo carrying them.
"""

from __future__ import annotations

import ast
import io
import logging
import os
import pathlib
import re
import zipfile

import pytest

from ori.security import evidence as evidence_module

PACKAGE_ROOT = pathlib.Path(evidence_module.__file__).resolve().parent.parent
REPO_ROOT = PACKAGE_ROOT.parent
EVIDENCE_CHANNELS = re.compile(r"\[(?:evidence|confirmation)\]")


# --------------------------------------------------------------------------
# 1. AST enumeration — not a regex over source
# --------------------------------------------------------------------------
#
# An earlier revision matched `logger.<level>("...")` textually. A single-quoted
# string, an f-string, a module-level alias, a LoggerAdapter, or a message built
# from a variable all bypassed it, and the scan proved nothing about what it had
# not found. Walking the AST removes the bypasses and, more importantly, makes
# an unresolvable message a *reported finding* rather than a silent miss.


LOG_LEVELS = {"debug", "info", "warning", "error", "critical", "exception", "log"}


def _static_text(node: ast.AST) -> str | None:
    """Best-effort literal text of a log message argument.

    Returns None when the message cannot be resolved statically, which is
    itself something the caller must surface rather than skip.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):  # f-string
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{...}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_text(node.left), _static_text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _log_calls(path: pathlib.Path) -> list[tuple[str, int, str | None]]:
    """Every logging call in *path*, whatever the call is spelled as."""
    tree = ast.parse(path.read_text(errors="ignore"))
    found: list[tuple[str, int, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in LOG_LEVELS:
            continue
        # Any receiver: `logger`, `log`, `self._log`, an adapter, an alias.
        args = node.args
        if func.attr == "log" and args:
            args = args[1:]  # logger.log(level, msg, ...)
        message = _static_text(args[0]) if args else None
        found.append((func.attr, node.lineno, message))
    return found


def _evidence_modules() -> list[pathlib.Path]:
    modules = [
        path
        for path in PACKAGE_ROOT.rglob("*.py")
        if EVIDENCE_CHANNELS.search(path.read_text(errors="ignore"))
    ]
    assert modules, "no module logs on the evidence path; the scanner is broken"
    return modules


def _operator_messages() -> list[tuple[str, int, str]]:
    """Every resolved message an operator can see, at any level.

    No level is excluded. `logging.level: INFO` is the default and DEBUG is a
    documented operator choice, so an audit that skips a level is an audit with
    a hole the configuration file tells you how to open. An earlier revision
    excluded DEBUG while arguing DEBUG was operator-visible, which was the same
    inconsistency in the other direction.
    """
    out = []
    for path in _evidence_modules():
        name = str(path.relative_to(PACKAGE_ROOT))
        for level, lineno, message in _log_calls(path):
            if message and EVIDENCE_CHANNELS.match(message):
                out.append((name, lineno, message))
    return out


EVIDENCE_DEDICATED_MODULES = (
    "security/evidence.py",
    "security/firmware_confirmation.py",
    "security/firmware_reconciliation.py",
)


def test_evidence_dedicated_modules_do_not_log_at_debug_at_all():
    """Whole-module rule, so a dynamically built message cannot hide behind it.

    Matching the `[evidence]` prefix only works on messages that resolve
    statically. In a module whose entire purpose is the evidence path, the
    prefix is not needed to know the message belongs to it — so the rule is
    the module, not the string.
    """
    offenders = []
    for name in EVIDENCE_DEDICATED_MODULES:
        path = PACKAGE_ROOT / name
        assert path.exists(), f"{name} moved; update EVIDENCE_DEDICATED_MODULES"
        offenders += [
            f"{name}:{lineno}"
            for level, lineno, _ in _log_calls(path)
            if level == "debug"
        ]
    assert not offenders, (
        "DEBUG logging in a module dedicated to the evidence path. DEBUG is "
        f"operator-selectable; say it at INFO and register it: {offenders}"
    )


def test_no_evidence_channel_logs_at_debug():
    """Nothing on this path logs at DEBUG, so the registry cannot be bypassed.

    Registering DEBUG messages would work too, but forbidding them is the
    stronger rule: DEBUG existed on this path only to hold tracebacks, and
    those are gone. A future `logger.debug("[evidence] connected to ...")`
    fails here rather than slipping past the reviewed set.
    """
    offenders = [
        f"{path.relative_to(PACKAGE_ROOT)}:{lineno} {message!r}"
        for path in _evidence_modules()
        for level, lineno, message in _log_calls(path)
        if level == "debug" and message and EVIDENCE_CHANNELS.match(message)
    ]
    assert not offenders, (
        "evidence-path DEBUG logging; DEBUG is operator-selectable, so say it "
        f"at INFO and register the message instead: {offenders}"
    )


def test_every_evidence_message_resolves_statically():
    """An unresolvable message is a hole, not something to skip over."""
    # DEBUG is not exempt. `logging.level: DEBUG` is a documented operator
    # choice, so an unresolved DEBUG message is an unaudited operator-visible
    # message — `logger.debug(f"[evidence] connected to {endpoint}")` would
    # otherwise pass both this check and the channel-prefix one.
    unresolved = [
        f"{path.relative_to(PACKAGE_ROOT)}:{lineno} ({level})"
        for path in _evidence_modules()
        for level, lineno, message in _log_calls(path)
        if message is None
    ]
    assert not unresolved, (
        "these log calls build their message dynamically, so this file cannot "
        f"audit them; review and add them to the registry: {unresolved}"
    )


# --------------------------------------------------------------------------
# 2. Positive allowlist — a closed set, not another denylist
# --------------------------------------------------------------------------
#
# The previous revision called a list of prohibited regexes a "positive
# allowlist", which it plainly was not. This is the real thing: every message
# an operator can see on the evidence path, reviewed. A new or reworded message
# fails here until someone looks at it.

REVIEWED_OPERATOR_MESSAGES = frozenset(
    {
        # INFO and above. Reviewed: counts, a sanitised exception type, and
        # this device's own local path and own anchor — nothing about who else
        # holds a copy.
        "[evidence] evidence signing is unavailable (%s); Tier C/D "
        "actions continue and are recorded as attestation gaps until "
        "signing is restored.",
        "[evidence] evidence store open at %s; this device's verification anchor is %s",
        "[confirmation] startup drain: %d of %d devices confirmed",
        "[confirmation] reconciled %d of %d outstanding obligations",
        "[evidence] evidence signing is unavailable: this runtime "
        "requires protocol %s with idempotent appends and the local "
        "store does not provide it. Tier C/D actions continue and are "
        "recorded as attestation gaps.",
        "[evidence] failed to sign action_log id=%s tier=%s",
        "[evidence] chain head read failed",
        "[evidence] pending count read failed",
        "[evidence] chain release on evidence thread failed",
        "[evidence] failed to record reconciliation for action id=%s",
        "[evidence] startup reconciliation: %d repaired, %d still unsigned",
        "[evidence] reconciliation scan failed",
        "[evidence] attestation summary read failed",
        "[confirmation] confirmation authority unreachable for %s epoch %s; "
        "remaining confirmation_pending",
        "[confirmation] reconciling %s failed",
        "[confirmation] epoch disagreement for %s: runtime %s, evidence "
        "store %s; quarantining for operator review",
        "[confirmation] no coordinator available; leaving firmware "
        "evidence for %s pending",
        "[confirmation] reconciling %s failed; leaving evidence pending",
        "[confirmation] failed to list pending confirmations",
        "[confirmation] reconciliation cycle failed",
        "[confirmation] pending obligations fill the %d-row window; "
        "devices beyond it wait for earlier ones to resolve",
    }
)


def test_operator_messages_are_all_reviewed():
    """The allowlist is closed: an unreviewed message fails."""
    seen = {message for _, _, message in _operator_messages()}
    unreviewed = seen - REVIEWED_OPERATOR_MESSAGES
    assert not unreviewed, (
        "new or reworded operator-facing evidence messages. Review each against "
        "the disclosure rules, then add it to REVIEWED_OPERATOR_MESSAGES: "
        f"{sorted(unreviewed)}"
    )


def test_the_allowlist_has_no_dead_entries():
    """A registry that drifts from the code stops being a review record."""
    seen = {message for _, _, message in _operator_messages()}
    stale = REVIEWED_OPERATOR_MESSAGES - seen
    assert not stale, f"registry entries no longer emitted anywhere: {sorted(stale)}"


# --------------------------------------------------------------------------
# 3. Behavioural capture — what actually reaches the journal
# --------------------------------------------------------------------------
#
# Static text was never the whole surface. `exc_info=True` attaches an exception
# whose text the format string does not contain: an ImportError for the
# configured artifact carries the private module name, and an error from the
# loaded object can carry its distribution path or shared-library filename.


POISON = "zzz_private_evidence_impl_probe"


def _capture(level: int):
    """Attach one handler and return a restore that removes only it.

    Clearing `logger.handlers` would remove handlers belonging to the test
    runner and to other fixtures, so a later test could lose logging it
    depends on and pass for the wrong reason.
    """
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(level)
    touched = []
    for name in (
        "ori.security.evidence",
        "ori.security.firmware_confirmation",
        "ori.security.firmware_reconciliation",
        "ori.runtime",
    ):
        logger = logging.getLogger(name)
        touched.append((logger, logger.level))
        logger.addHandler(handler)
        logger.setLevel(level)

    def restore() -> None:
        for logger, previous in touched:
            logger.removeHandler(handler)
            logger.setLevel(previous)

    return buffer, restore


@pytest.mark.asyncio
async def test_a_failing_artifact_load_discloses_nothing_to_the_operator(
    monkeypatch, tmp_path
):
    """The traceback, not the message, was the leak.

    Reproduced before it was fixed: the configured module name appeared in the
    operator's journal through `exc_info=True`, where auditing every format
    string would never have found it.
    """
    monkeypatch.setenv("ORI_EVIDENCE_ARTIFACT_MODULE", POISON)
    buffer, restore = _capture(logging.WARNING)
    try:
        attestor = evidence_module.EvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "e.key"),
            device_secret="secret",
            device_id="dev-1",
        )
        assert await attestor.start() is False
        assert POISON not in buffer.getvalue(), (
            "the configured artifact module name reached the operator's journal"
        )
    finally:
        restore()


@pytest.mark.asyncio
async def test_nothing_discloses_even_at_debug(monkeypatch, tmp_path):
    """DEBUG is a documented operator choice, not a private channel.

    An earlier revision asserted the opposite — that the private name *should*
    appear at DEBUG — which made an operator-selectable setting the boundary.
    """
    monkeypatch.setenv("ORI_EVIDENCE_ARTIFACT_MODULE", POISON)
    buffer, restore = _capture(logging.DEBUG)
    try:
        attestor = evidence_module.EvidenceAttestor(
            db_path=str(tmp_path / "e.db"),
            key_path=str(tmp_path / "e.key"),
            device_secret="secret",
            device_id="dev-1",
        )
        await attestor.start()
        assert POISON not in buffer.getvalue()
        assert "module_unavailable" in buffer.getvalue(), (
            "the failure category must survive, or removing disclosure has "
            "removed diagnosability instead"
        )
    finally:
        restore()


def test_no_evidence_path_logging_attaches_an_exception():
    """`exc_info` at any level, including DEBUG.

    `logging.level: DEBUG` is a documented operator choice, so DEBUG is not a
    private channel and relocating a traceback there enforces nothing. Auditing
    the resulting text would be endless; forbidding the attachment is one rule
    that holds for exceptions nobody has thought of yet.
    """
    offenders = []
    for path in _evidence_modules():
        tree = ast.parse(path.read_text(errors="ignore"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr not in LOG_LEVELS:
                continue
            message = _static_text(node.args[0]) if node.args else None
            if not (message and EVIDENCE_CHANNELS.match(message)):
                continue
            for keyword in node.keywords:
                if keyword.arg == "exc_info":
                    offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}")
            if func.attr == "exception":
                offenders.append(
                    f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno} (logger.exception)"
                )
    assert not offenders, (
        "evidence-path logging attaches an exception. DEBUG is operator-"
        "selectable, so reduce the detail with safe_failure_reason() instead "
        f"of relocating it: {offenders}"
    )


# --------------------------------------------------------------------------
# 4. Structured schemas — health, heartbeat, doctor
# --------------------------------------------------------------------------


EVIDENCE_HEALTH_KEYS = {
    "enabled",
    "available",
    "public_key_hex",
    "protocol_version",
    "action_event_type",
    "chain_head_hash",
    "pending_export_count",
    "last_attested_action_id",
    "attestation_gap_count",
    "status_counts",
}

EVIDENCE_HEARTBEAT_KEYS = {
    "chain_head_hash",
    "attestation_gap_count",
    "available",
    "action_event_type",
}


@pytest.mark.asyncio
async def test_health_evidence_block_matches_ori_specs_runtime_health_v2():
    """The field set is a published contract, not a local choice.

    `artifact_version` is absent because `ori-specs/runtime-health/v2` removes
    it. It was briefly removed during this audit and restored while v1 still
    required it — the disclosure argument did not license changing a published
    structured response ahead of the contract defining it.
    """
    from ori.runtime import OriRuntime

    runtime = object.__new__(OriRuntime)
    runtime._evidence_attestor = None
    runtime._config = None
    runtime._state_store = None

    health = await runtime._evidence_health()
    assert set(health) == EVIDENCE_HEALTH_KEYS


def test_heartbeat_evidence_block_matches_its_reviewed_schema():
    """The heartbeat leaves the device, so its field list is a closed set."""
    source = (PACKAGE_ROOT / "gateway" / "node_heartbeat.py").read_text()
    marker = 'payload["evidence"] = {'
    assert marker in source, (
        "the heartbeat evidence block moved or was reformatted; update the "
        "marker rather than deleting this check"
    )
    keys = set(re.findall(r'"([a-z_]+)":', source.split(marker)[1].split("}")[0]))
    assert keys, "parsed no keys from the heartbeat evidence block"
    assert keys == EVIDENCE_HEARTBEAT_KEYS


def test_doctor_exposes_no_evidence_surface():
    """A guard, because today there is nothing to schema.

    `ori doctor` reports no evidence state at all. That is fine — health and
    the heartbeat carry it. This fails the moment an evidence check is added,
    so the disclosure question is asked then rather than discovered later.
    """
    doctor_source = (PACKAGE_ROOT / "doctor.py").read_text()
    assert "evidence" not in doctor_source.lower(), (
        "doctor now reports evidence state; review it against the disclosure "
        "rules and schema it here"
    )


@pytest.mark.asyncio
async def test_degraded_evidence_stays_visible_to_the_operator():
    """Silence is not the goal: degradation must remain noticeable."""
    from ori.runtime import OriRuntime

    runtime = object.__new__(OriRuntime)
    runtime._evidence_attestor = None
    runtime._config = None
    runtime._state_store = None

    health = await runtime._evidence_health()
    for field in ("enabled", "available", "attestation_gap_count", "status_counts"):
        assert field in health


# --------------------------------------------------------------------------
# 5. Shapes that are never acceptable
# --------------------------------------------------------------------------


SHAPE_PATTERNS = {
    "url or endpoint": r"https?://|mqtts?://",
    "bare hostname": r"\b[a-z0-9-]+\.(?:com|net|io|dev|internal|local)\b",
    "ip address": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "credential value": r"(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S",
    "custody or administration": r"\b(?:kms|hsm|vault|admin panel|console)\b",
}

INSTRUCTION_PATTERNS = (
    r"\bregister\b(?!ed\b|s\b|y\b)",
    r"\bupload\b",
    r"\bforward\b(?!ed\b)",
    r"\btransfer\b",
    r"\bcontact\b",
    r"\boff-device\b",
)


@pytest.mark.parametrize("label,pattern", sorted(SHAPE_PATTERNS.items()))
def test_operator_messages_disclose_no_endpoint_or_custody(label, pattern):
    offenders = [
        f"{where}:{line} {msg}"
        for where, line, msg in _operator_messages()
        if re.search(pattern, msg, re.IGNORECASE)
    ]
    assert not offenders, f"operator message exposes {label}: {offenders}"


@pytest.mark.parametrize("pattern", INSTRUCTION_PATTERNS)
def test_no_operator_message_instructs_the_operator(pattern):
    offenders = [
        f"{where}:{line} {msg}"
        for where, line, msg in _operator_messages()
        if re.search(pattern, msg, re.IGNORECASE)
    ]
    assert not offenders, (
        f"operator message directs the operator ({pattern}): {offenders}"
    )


# --------------------------------------------------------------------------
# 6. What actually ships
# --------------------------------------------------------------------------


PRIVATE_IDENTIFIER = "prohibited private identifier"


def _opaque(location: str, category: str = PRIVATE_IDENTIFIER) -> str:
    """A finding that says where and what kind, never what.

    Every denylist-backed assertion runs in a public release workflow, so a
    failure that quotes the term, the matching passage, a distribution name or
    a binary string publishes exactly what the check exists to keep private —
    into a log that outlives the run. Locations are indices for the same
    reason: a filename can itself be the disclosure.

    A maintainer holding the denylist reproduces the detail locally in one
    command. Nobody reading the public log learns anything.
    """
    return f"{location}: {category}"


def _supplied_denylist() -> list[str]:
    raw = os.environ.get("ORI_DISCLOSURE_DENYLIST", "")
    return [term.strip().lower() for term in raw.split(",") if term.strip()]


VENDORED_IMPLEMENTATION = re.compile(
    r"(?:evidence|attest|ledger|chain)[-_]?(?:chain|store|db|impl|core)", re.IGNORECASE
)


@pytest.fixture(scope="session")
def built_wheel(tmp_path_factory) -> pathlib.Path:
    """Build the deliverable and inspect that, not the source tree.

    An earlier revision took whichever wheel happened to be in `dist/`, then
    installed metadata, then the source tree. With no wheel present it fell
    through to source — which proves nothing about what a wheel contains, and
    the wheel is the artifact the acceptance criterion is about.
    """
    import subprocess
    import sys

    out = tmp_path_factory.mktemp("wheel")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--outdir",
            str(out),
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"wheel build unavailable: {result.stderr.strip()[-200:]}")
    wheels = sorted(out.glob("*.whl"))
    assert wheels, "build produced no wheel"
    return wheels[-1]


def _wheel_names(wheel: pathlib.Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        return archive.namelist()


def _wheel_member(wheel: pathlib.Path, suffix: str) -> str:
    with zipfile.ZipFile(wheel) as archive:
        members = [n for n in archive.namelist() if n.endswith(suffix)]
        return archive.read(members[0]).decode(errors="ignore") if members else ""


def _wheel_record(wheel: pathlib.Path) -> str:
    return _wheel_member(wheel, "RECORD")


def _wheel_metadata(wheel: pathlib.Path) -> str:
    return _wheel_member(wheel, "METADATA")


def test_the_built_wheel_carries_no_compiled_artifact(built_wheel):
    """A compiled extension carries symbols and a filename no text audit finds."""
    compiled = [
        name
        for name in _wheel_names(built_wheel)
        if name.endswith((".so", ".dylib", ".pyd", ".dll"))
    ]
    assert not compiled, f"compiled artifacts ship in the wheel: {compiled}"


def test_the_built_wheel_names_no_evidence_implementation(built_wheel):
    offenders = [
        name
        for name in _wheel_names(built_wheel)
        if VENDORED_IMPLEMENTATION.search(name)
    ]
    assert not offenders, f"wheel entries name an evidence implementation: {offenders}"


def test_wheel_metadata_and_record_disclose_nothing_structural(built_wheel):
    """Structural fields only: RECORD paths, and METADATA's declared fields.

    METADATA embeds the README as the long description, and the README states
    the boundary in prose — that private artifacts exist and integrate through
    public contracts, with their source coordinates deliberately absent. That
    sentence is the honest position, not a leak, so a filename matcher must not
    be run over free text and called a finding.
    """
    record = _wheel_record(built_wheel)
    assert record, "wheel has no RECORD to inspect"
    offenders = [
        line.split(",")[0]
        for line in record.splitlines()
        if line and VENDORED_IMPLEMENTATION.search(line.split(",")[0])
    ]
    assert not offenders, f"wheel RECORD ships: {offenders}"

    metadata = _wheel_metadata(built_wheel)
    assert metadata, "wheel has no METADATA to inspect"
    declared = [
        line.strip()
        for line in metadata.splitlines()
        if line.startswith(("Requires-Dist:", "Name:", "Provides-Extra:"))
    ]
    assert declared, "wheel METADATA declares no fields to inspect"
    offenders = [line for line in declared if VENDORED_IMPLEMENTATION.search(line)]
    assert not offenders, f"wheel METADATA declares: {offenders}"


def test_no_evidence_implementation_is_declared_as_a_dependency():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    offenders = [
        line.strip()
        for line in pyproject.splitlines()
        if VENDORED_IMPLEMENTATION.search(line)
    ]
    assert not offenders, f"pyproject declares an evidence implementation: {offenders}"


def _wheelhouse_dir() -> pathlib.Path:
    """Where the wheelhouse actually is.

    The release workflow builds into `ORI_WHEELHOUSE_OUT`, not into the
    checkout. An earlier revision looked only at `REPO_ROOT/wheelhouse`, so its
    claim that a release job could not pass without auditing the wheelhouse was
    simply untrue — the job builds elsewhere and never ran this.
    """
    configured = os.environ.get("ORI_WHEELHOUSE_OUT", "").strip()
    return pathlib.Path(configured) if configured else REPO_ROOT / "wheelhouse"


def _printable_strings(blob: bytes, minimum: int = 4) -> str:
    """Printable runs from a binary, as `strings(1)` would extract them.

    A neutral filename can still carry an identity-bearing symbol, an embedded
    build path, or a hostname inside the compiled object. Listing member names
    never sees any of it.
    """
    out, run = [], bytearray()
    for byte in blob:
        if 32 <= byte < 127:
            run.append(byte)
        else:
            if len(run) >= minimum:
                out.append(run.decode("ascii", "ignore"))
            run = bytearray()
    if len(run) >= minimum:
        out.append(run.decode("ascii", "ignore"))
    return "\n".join(out)


@pytest.mark.disclosure_release
def test_wheelhouse_distributions_disclose_nothing():
    """The wheelhouse is what actually reaches the device.

    The private compiled component ships here, not inside the pure-Python
    runtime wheel, so this is the check that covers the compiled-artifact and
    binary-inspection criteria. It cannot run in a plain checkout, because
    building a wheelhouse requires the private artifact.

    That makes it a release-job obligation. `ORI_REQUIRE_WHEELHOUSE_AUDIT=1`
    turns every skip below into a failure, including the absence of a denylist
    — a job that audits binaries without knowing what to look for has audited
    nothing.
    """
    required = os.environ.get("ORI_REQUIRE_WHEELHOUSE_AUDIT") == "1"

    def _skip_or_fail(reason: str) -> None:
        if required:
            pytest.fail(f"ORI_REQUIRE_WHEELHOUSE_AUDIT=1 but {reason}")
        pytest.skip(f"{reason}; the release job must run this")

    wheelhouse = _wheelhouse_dir()
    if not wheelhouse.exists():
        _skip_or_fail(f"no wheelhouse at {wheelhouse}")

    terms = _supplied_denylist()
    if not terms:
        _skip_or_fail("ORI_DISCLOSURE_DENYLIST is not set")

    distributions = sorted(wheelhouse.rglob("*.whl"))
    if not distributions:
        _skip_or_fail(f"wheelhouse at {wheelhouse} contains no distributions")

    # Report *that* something matched and *where*, never *what*.
    #
    # This audit runs in a public release workflow. An earlier revision put the
    # matching term into the failure message, so the check that exists to stop
    # the identity being published would have published it — in a log that
    # outlives the run. Secret masking cannot be relied on here either: it
    # knows the whole comma-separated secret, not every individual term, and
    # certainly not the surrounding binary string.
    def _denied(text: str) -> str | None:
        """A supplied private term. A leak wherever it appears, prose included."""
        lowered = text.lower()
        return PRIVATE_IDENTIFIER if any(term in lowered for term in terms) else None

    def _implementation_named(text: str) -> str | None:
        """An identifier shaped like an evidence implementation.

        Scope matters here as much as the pattern. This matcher is for names —
        a distribution, an archive member, a RECORD path, a declared metadata
        field. Run over free text it fires on the README, which METADATA
        embeds as the long description, and which states the boundary in
        deliberate prose: that private artifacts exist and integrate through
        public contracts, with their coordinates absent. That sentence is the
        honest public position rather than a disclosure, so treating it as a
        finding would fail every release over the project describing itself
        accurately. The sibling wheel test already draws this line; this audit
        did not, and a wheelhouse built from a real tag is what showed it.
        """
        if VENDORED_IMPLEMENTATION.search(text):
            return "evidence-implementation naming"
        return None

    def _category(text: str) -> str | None:
        """Both checks, for an input that is an identifier rather than prose."""
        return _denied(text) or _implementation_named(text)

    def _declared_fields(member_name: str, text: str) -> list[str]:
        """The structural lines of a metadata member, excluding prose."""
        if member_name.endswith("RECORD"):
            return [line.split(",")[0] for line in text.splitlines() if line]
        if member_name.endswith("METADATA"):
            return [
                line.strip()
                for line in text.splitlines()
                if line.startswith(("Name:", "Requires-Dist:", "Provides-Extra:"))
            ]
        # WHEEL carries no long description; every line of it is structural.
        return [line.strip() for line in text.splitlines() if line.strip()]

    failures: list[str] = []
    inspected_binaries = 0
    for path in distributions:
        # Distribution names are printed only when they do not themselves
        # match; the location of an offending wheel is its index, not its name.
        location = f"distribution #{distributions.index(path) + 1}"
        found = _category(path.name)
        if found:
            failures.append(_opaque(f"{location} (distribution name)", found))
        with zipfile.ZipFile(path) as archive:
            for index, name in enumerate(archive.namelist()):
                member = f"{location} member #{index + 1}"
                found = _category(name)
                if found:
                    failures.append(_opaque(f"{member} (member name)", found))
                if name.endswith((".so", ".dylib", ".pyd", ".dll")):
                    inspected_binaries += 1
                    found = _category(_printable_strings(archive.read(name)))
                    if found:
                        failures.append(_opaque(f"{member} (compiled strings)", found))
                if name.endswith(("METADATA", "RECORD", "WHEEL")):
                    text = archive.read(name).decode("utf-8", "ignore")
                    # A supplied private identifier is a leak anywhere in the
                    # file, so this half reads the whole text.
                    found = _denied(text)
                    if found:
                        failures.append(_opaque(f"{member} (wheel metadata)", found))
                    # The naming pattern reads declared fields only.
                    for field in _declared_fields(name, text):
                        found = _implementation_named(field)
                        if found:
                            failures.append(
                                _opaque(f"{member} (declared field)", found)
                            )
                            break

    assert not failures, (
        "the wheelhouse reaching the device carries a prohibited identifier. "
        "Locations are given without the matching text, deliberately — this "
        f"audit runs in a public workflow: {failures}"
    )
    print(
        f"audited {len(distributions)} distributions, "
        f"{inspected_binaries} compiled members"
    )


@pytest.mark.disclosure_release
def test_built_wheel_discloses_nothing_supplied(built_wheel):
    terms = _supplied_denylist()
    if not terms:
        pytest.skip("ORI_DISCLOSURE_DENYLIST not set; a private CI supplies it")
    surfaces = {
        "namelist": "\n".join(_wheel_names(built_wheel)),
        "METADATA": _wheel_metadata(built_wheel),
        "RECORD": _wheel_record(built_wheel),
    }
    offenders = [
        _opaque(f"built wheel {label}")
        for label, text in surfaces.items()
        if any(term in text.lower() for term in terms)
    ]
    assert not offenders, f"the built wheel carries a prohibited term: {offenders}"


@pytest.mark.disclosure_release
def test_package_contents_disclose_nothing_supplied():
    terms = _supplied_denylist()
    if not terms:
        pytest.skip("ORI_DISCLOSURE_DENYLIST not set; a private CI supplies it")
    # Indices, not paths: a filename can carry the term as readily as a body.
    sources = sorted(PACKAGE_ROOT.rglob("*.py"))
    offenders = [
        _opaque(f"package source #{index + 1}")
        for index, path in enumerate(sources)
        if any(
            term in path.read_text(errors="ignore").lower() or term in path.name.lower()
            for term in terms
        )
    ]
    assert not offenders, (
        f"package sources carry a prohibited term ({len(sources)} scanned): {offenders}"
    )


@pytest.mark.disclosure_release
def test_installed_distributions_disclose_nothing_supplied():
    terms = _supplied_denylist()
    if not terms:
        pytest.skip("ORI_DISCLOSURE_DENYLIST not set; a private CI supplies it")
    from importlib import metadata

    installed = sorted(
        name for dist in metadata.distributions() if (name := dist.metadata["Name"])
    )
    offenders = [
        _opaque(f"installed distribution #{index + 1}")
        for index, name in enumerate(installed)
        if any(term in name.lower() for term in terms)
    ]
    assert not offenders, (
        f"an installed distribution name carries a prohibited term "
        f"({len(installed)} scanned): {offenders}"
    )


# --------------------------------------------------------------------------
# 7. Operator-facing documents
# --------------------------------------------------------------------------


OPERATOR_DOCS = (
    "ori.yaml.example",
    "ori.linux.yaml.example",
    "ori.yaml.phone.example",
    "docs/linux-install.md",
    "docs/linux-setup.md",
    "docs/android-phone-install.md",
    "docs/releases/evidence/systemd-host-runbook.md",
)


def test_operator_documents_exist_to_be_audited():
    """A document list that silently matches nothing audits nothing."""
    present = [name for name in OPERATOR_DOCS if (REPO_ROOT / name).exists()]
    assert len(present) >= 4, f"expected operator documents are missing: {present}"


EVIDENCE_TOPIC = re.compile(
    r"evidence|attestation|verification anchor|chain head", re.IGNORECASE
)


def _evidence_passages(path: pathlib.Path) -> list[str]:
    """Passages about evidence, selected by document kind.

    A configuration example is not prose: its `evidence:` block is the passage,
    and treating the whole file as paragraphs matched a Modbus register table
    and a gateway broker URL — both legitimate, neither about evidence. Bare
    `chain` and `anchor` are dropped from the selector for the same reason.
    """
    text = path.read_text(errors="ignore")
    if path.suffix in {".example", ".yaml", ".yml"} or path.name.endswith(".example"):
        block = re.search(r"\nevidence:\n(?:[ \t]+.*\n|\n)*", text)
        return [block.group(0)] if block else []
    return [para for para in re.split(r"\n\s*\n", text) if EVIDENCE_TOPIC.search(para)]


@pytest.mark.disclosure_release
@pytest.mark.parametrize("name", OPERATOR_DOCS)
def test_operator_documents_hold_the_whole_invariant(name):
    """Passages, not lines, and the full invariant rather than verbs alone.

    An earlier revision matched single lines containing an evidence keyword and
    applied only the instruction patterns. A multi-line instruction, or an
    endpoint or custody detail a sentence away from the keyword, passed
    untouched.
    """
    path = REPO_ROOT / name
    if not path.exists():
        pytest.skip(f"{name} is not present in this checkout")

    failures = []
    for passage_index, passage in enumerate(_evidence_passages(path)):
        flat = " ".join(passage.split())
        for pattern in INSTRUCTION_PATTERNS:
            if re.search(pattern, flat, re.IGNORECASE):
                failures.append(f"instruction ({pattern}): {flat[:120]}")
        for label, pattern in SHAPE_PATTERNS.items():
            if re.search(pattern, flat, re.IGNORECASE):
                failures.append(f"{label}: {flat[:120]}")
        for term in _supplied_denylist():
            if term in flat.lower():
                # The passage itself is the disclosure; report its position.
                failures.append(_opaque(f"passage #{passage_index + 1}"))
                break
    assert not failures, f"{name} discloses on the evidence path: {failures}"


def test_document_audit_actually_reads_evidence_passages():
    """A selector that matches nothing audits nothing."""
    total = sum(
        len(_evidence_passages(REPO_ROOT / name))
        for name in OPERATOR_DOCS
        if (REPO_ROOT / name).exists()
    )
    assert total >= 3, (
        f"only {total} evidence passages found across operator documents; "
        "the selector or the document list is wrong"
    )


# --------------------------------------------------------------------------
# 8. The failure category is a closed set
# --------------------------------------------------------------------------


class _IdentityBearingError(RuntimeError):
    """Stands in for a private component raising its own exception type.

    The class name is the leak: `type(exc).__name__` would print it, and a
    private component is free to name its exceptions after itself or after a
    deployment.
    """


@pytest.mark.parametrize(
    "exc,expected",
    [
        (
            ModuleNotFoundError("no module named acme_private_chain"),
            "module_unavailable",
        ),
        (
            ImportError("cannot import name from acme_private_chain"),
            "module_unavailable",
        ),
        (PermissionError("/opt/acme/private.key"), "permission_denied"),
        (TimeoutError(), "timeout"),
        (AttributeError("object has no attribute append_event"), "interface_mismatch"),
        (_IdentityBearingError("host acme.internal unreachable"), "internal_error"),
        (Exception("acme_private_chain exploded"), "internal_error"),
    ],
)
def test_failure_reason_is_a_category_never_derived_text(exc, expected):
    # Equality against a literal is the whole check: a reason built from the
    # exception could not equal one of these. Anything further added here —
    # that the class name is absent, that "acme" is absent — is implied by it,
    # and reads as a check while testing nothing. The invariants that are not
    # implied are below: the set of categories is closed, and it is mapped
    # from builtins only.
    assert evidence_module.safe_failure_reason(exc) == expected


# The categories a reviewer has cleared for an operator to see. The test owns
# this set rather than importing it — a new category is new text on an
# operator's screen, so it fails here until someone has read it.
REVIEWED_FAILURE_CATEGORIES = frozenset(
    {
        "module_unavailable",
        "permission_denied",
        "not_found",
        "timeout",
        "resource_exhausted",
        "io_error",
        "invalid_value",
        "invalid_type",
        "interface_mismatch",
        "internal_error",
    }
)


def test_declared_failure_categories_are_all_reviewed():
    declared = {
        category for _, category in evidence_module._PUBLIC_FAILURE_CATEGORIES
    } | {evidence_module._UNCATEGORISED_FAILURE}
    assert declared == REVIEWED_FAILURE_CATEGORIES, (
        "the categories an operator can be shown changed; review the wording "
        "against the disclosure boundary before listing it here"
    )


def test_failure_categories_are_mapped_from_builtin_types_only():
    """Why a private class name cannot reach the mapping in the first place.

    Every entry keys on a builtin, so the table cannot come to depend on a
    private component's exception hierarchy — which is how the class name
    would get back into an operator's view after being removed from the text.
    """
    for exception_type, _ in evidence_module._PUBLIC_FAILURE_CATEGORIES:
        assert exception_type.__module__ == "builtins", (
            f"{exception_type.__name__} is not a builtin exception; the "
            "category table must not reference a private component's types"
        )


def test_failure_reason_never_returns_the_exception_class_name():
    """The subtler version of the traceback leak."""
    reason = evidence_module.safe_failure_reason(_IdentityBearingError("x"))
    assert "_IdentityBearingError" not in reason
    assert reason == "internal_error"


# --------------------------------------------------------------------------
# 9. The wheelhouse audit, exercised against a wheel built to defeat it
# --------------------------------------------------------------------------


def _adversarial_wheelhouse(root: pathlib.Path) -> pathlib.Path:
    """A wheel whose names are neutral and whose bytes are not.

    This is the case member-name listing cannot catch: the distribution and
    every path inside it look ordinary, while the compiled object carries a
    symbol and a build path naming the private component.
    """
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(parents=True, exist_ok=True)
    wheel = wheelhouse / "neutral_pkg-1.0-cp312-cp312-linux_x86_64.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "neutral_pkg/_native.so",
            b"\x7fELF\x00\x00pad\x00_acmechain_connect\x00/build/acmechain/src\x00",
        )
        archive.writestr("neutral_pkg-1.0.dist-info/METADATA", "Name: neutral-pkg\n")
        archive.writestr(
            "neutral_pkg-1.0.dist-info/RECORD", "neutral_pkg/_native.so,,\n"
        )
    return wheelhouse


@pytest.mark.disclosure_release
def test_wheelhouse_audit_catches_a_neutral_wheel_with_a_bearing_binary(
    tmp_path, monkeypatch
):
    """Regression: filename listing passes this; byte inspection must not."""
    wheelhouse = _adversarial_wheelhouse(tmp_path)
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(wheelhouse))
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", "acmechain")
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    with pytest.raises(AssertionError) as excinfo:
        test_wheelhouse_distributions_disclose_nothing()

    report = str(excinfo.value)
    assert "compiled strings" in report, "byte inspection did not fire"
    # The audit must not publish what it caught. It runs in a public workflow,
    # so a failure that quotes the term defeats the purpose of the check.
    assert "acmechain" not in report.lower()
    assert "/build/" not in report
    assert "_native.so" not in report


@pytest.mark.disclosure_release
def test_a_clean_wheelhouse_passes_the_audit(tmp_path, monkeypatch):
    """The audit must not fail on everything, or failing proves nothing."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "ordinary_pkg-2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ordinary_pkg/__init__.py", "VERSION = '2.0'\n")
        archive.writestr("ordinary_pkg-2.0.dist-info/METADATA", "Name: ordinary-pkg\n")
        archive.writestr(
            "ordinary_pkg-2.0.dist-info/RECORD", "ordinary_pkg/__init__.py,,\n"
        )
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(wheelhouse))
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", "acmechain")
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    test_wheelhouse_distributions_disclose_nothing()


# The README sentence, verbatim in shape: METADATA embeds the long description,
# and the project states its boundary there on purpose.
_BOUNDARY_PROSE = (
    "Private evidence-chain and edge-firmware artifacts integrate through the "
    "public contracts in this repository. Their source coordinates are "
    "deliberately absent."
)


def _wheel_with_metadata(wheelhouse: pathlib.Path, name: str, metadata: str) -> None:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheelhouse / f"{name}-1.0-py3-none-any.whl", "w") as archive:
        archive.writestr(f"{name}/__init__.py", "VERSION = '1.0'\n")
        archive.writestr(f"{name}-1.0.dist-info/METADATA", metadata)
        archive.writestr(f"{name}-1.0.dist-info/RECORD", f"{name}/__init__.py,,\n")


@pytest.mark.disclosure_release
def test_the_boundary_stated_in_prose_is_not_a_finding(tmp_path, monkeypatch):
    """Our own wheel must survive its own README.

    The naming pattern matches identifiers, and METADATA carries the README as
    its long description. Run over that free text it matches the sentence the
    project publishes on purpose — that private artifacts exist and integrate
    through public contracts, with their coordinates absent — and the release
    would fail on every tag over an accurate self-description with nothing
    disclosed in it. A real wheelhouse built from a tag is what surfaced this;
    no synthesised fixture had a long description in it to fire on.
    """
    wheelhouse = tmp_path / "wheelhouse"
    _wheel_with_metadata(
        wheelhouse,
        "ori_runtime",
        f"Metadata-Version: 2.1\nName: ori-runtime\nVersion: 1.0\n\n{_BOUNDARY_PROSE}\n",
    )
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(wheelhouse))
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", "acmechain")
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    test_wheelhouse_distributions_disclose_nothing()


@pytest.mark.disclosure_release
def test_the_same_naming_in_a_declared_field_is_a_finding(tmp_path, monkeypatch):
    """The other half: narrowing the scope must not disarm the check.

    The identical string, moved from the long description into a declared
    dependency, is an implementation actually being shipped.
    """
    wheelhouse = tmp_path / "wheelhouse"
    _wheel_with_metadata(
        wheelhouse,
        "ori_runtime",
        "Metadata-Version: 2.1\nName: ori-runtime\nVersion: 1.0\n"
        "Requires-Dist: evidence-chain-core>=1.0\n",
    )
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(wheelhouse))
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", "acmechain")
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    with pytest.raises(AssertionError, match="prohibited identifier"):
        test_wheelhouse_distributions_disclose_nothing()


@pytest.mark.disclosure_release
def test_a_private_term_in_prose_is_still_a_finding(tmp_path, monkeypatch):
    """Scope narrowed for the pattern only, never for a supplied real name."""
    wheelhouse = tmp_path / "wheelhouse"
    _wheel_with_metadata(
        wheelhouse,
        "ori_runtime",
        "Metadata-Version: 2.1\nName: ori-runtime\nVersion: 1.0\n\n"
        "Talks to the acmechain host during provisioning.\n",
    )
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(wheelhouse))
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", "acmechain")
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    with pytest.raises(AssertionError, match="prohibited identifier"):
        test_wheelhouse_distributions_disclose_nothing()


# --------------------------------------------------------------------------
# 10. The audit must never publish what it catches
# --------------------------------------------------------------------------
#
# Every denylist-backed check runs in a public release workflow, which invokes
# them by keyword rather than one at a time. Sanitising a single assertion was
# not enough: the others still quoted the term, the matching passage, or a
# distribution name.


# A term present in this repository so the checks below actually fire, and
# deliberately *not* part of this file's own vocabulary. An earlier attempt
# used "evidence", which appears in the audit's own prose — "discloses on the
# evidence path" — so the regression flagged the describing text rather than a
# matched value. It stands in for the real private name, never written here.
POISON_TERM = "sealed"


DENYLIST_BACKED_CHECKS = (
    "test_package_contents_disclose_nothing_supplied",
    "test_installed_distributions_disclose_nothing_supplied",
    "test_wheelhouse_distributions_disclose_nothing",
    "test_operator_documents_hold_the_whole_invariant",
)


def test_no_denylist_backed_check_prints_what_it_matched(tmp_path, monkeypatch):
    """Run each one against a poisoned denylist and read its failure report.

    Asserts the mechanism, not one message: a future check that forgets to go
    through `_opaque` fails here the moment it is added to the tuple, and the
    membership assertion below makes leaving it out visible too.
    """
    monkeypatch.setenv("ORI_DISCLOSURE_DENYLIST", POISON_TERM)
    monkeypatch.setenv("ORI_WHEELHOUSE_OUT", str(_adversarial_wheelhouse(tmp_path)))
    monkeypatch.setenv("ORI_REQUIRE_WHEELHOUSE_AUDIT", "1")

    import sys

    module = sys.modules[__name__]
    fired = 0
    for name in DENYLIST_BACKED_CHECKS:
        check = getattr(module, name)
        try:
            if name == "test_operator_documents_hold_the_whole_invariant":
                check("ori.yaml.example")
            else:
                check()
        except AssertionError as failure:
            fired += 1
            report = str(failure).lower()
            assert POISON_TERM not in report, (
                f"{name} printed the matched term into its failure report"
            )
            assert PRIVATE_IDENTIFIER in report, (
                f"{name} failed without going through _opaque()"
            )
        except Exception:
            # Skips and environment problems are not what this test is about.
            continue
    assert fired >= 2, (
        f"only {fired} denylist-backed checks fired; the poison term is not "
        "reaching them and this test would pass vacuously"
    )


# Meta-tests reason *about* the denylist rather than matching against it, so
# they name the helper without being subject to the rule.
_SANITISATION_META_TESTS = frozenset(
    {
        "test_no_denylist_backed_check_prints_what_it_matched",
        "test_every_denylist_backed_check_is_sanitised",
    }
)


def _denylist_backed_test_bodies() -> dict[str, str]:
    source = pathlib.Path(__file__).read_text()
    bodies = {}
    for name in re.findall(r"def (test_\w+)\(", source):
        body = source.split(f"def {name}(", 1)[1].split("\ndef ", 1)[0]
        if "_supplied_denylist()" in body and name not in _SANITISATION_META_TESTS:
            bodies[name] = body
    return bodies


def test_every_denylist_backed_check_carries_the_release_marker():
    """The release job selects by marker; an unmarked check never runs there.

    Selecting by name substring omitted the document audit, which reads the
    denylist but carries neither "wheelhouse" nor "supplied" in its name. A
    marker cannot be missed by accident in the same way, and this asserts the
    two stay in step.
    """
    source = pathlib.Path(__file__).read_text()
    unmarked = []
    for name, body in _denylist_backed_test_bodies().items():
        definition = source.split(f"def {name}(", 1)[0]
        preceding = definition[definition.rindex("\n\n") :]
        if "disclosure_release" not in preceding:
            unmarked.append(name)
    assert not unmarked, (
        "these checks read the private denylist but are not marked "
        f"disclosure_release, so the release job will not run them: {unmarked}"
    )


def test_every_denylist_backed_check_is_sanitised():
    """Structural, so it also covers checks the behavioural test cannot call.

    `test_built_wheel_discloses_nothing_supplied` takes a session fixture and
    cannot simply be invoked, but its failure path is subject to the same rule.
    Requiring every denylist-backed body to route its finding through
    `_opaque()` covers both kinds.
    """
    bodies = _denylist_backed_test_bodies()
    assert bodies, "found no denylist-backed checks; the scanner is broken"
    unsanitised = [name for name, body in bodies.items() if "_opaque(" not in body]
    assert not unsanitised, (
        "these checks read the private denylist but do not route findings "
        f"through _opaque(): {sorted(unsanitised)}"
    )
