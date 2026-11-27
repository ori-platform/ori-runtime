# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The release audit finds each supported release from SECURITY.md, reads what
it puts on devices from git as data, and names the release in every finding."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit_locks  # noqa: E402
import audit_releases as releases  # noqa: E402

PIN = "x==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"


def test_only_a_supported_row_names_a_line() -> None:
    text = (
        "| Version | Supported |\n| ------- | --------- |\n"
        "| `2.5.x` (stable) | Yes |\n| `2.4.x` | No |\n| `<2.4.0` | No |\n"
    )
    assert releases.supported_lines(text) == [(2, 5)]
    assert releases.supported_lines(text + "| `3.0.x` | Yes |\n") == [(2, 5), (3, 0)]


_HEADER = "| Version | Supported |\n| ------- | --------- |\n"


def test_no_supported_line_fails_closed() -> None:
    with pytest.raises(ValueError, match="no supported release line"):
        releases.supported_lines(_HEADER + "| `2.5.x` | No |\n")


def test_no_version_table_fails_closed() -> None:
    with pytest.raises(ValueError, match="has no"):
        releases.supported_lines("| `2.5.x` (stable) | Yes |\n")


def test_only_the_version_table_is_read() -> None:
    """A later table quoting values in backticks is not a version table."""
    text = (
        _HEADER
        + "| `2.5.x` (stable) | Yes |\n\nPlatforms:\n\n"
        + "| Platform | Architecture | Python | Status |\n| --- | --- | --- | --- |\n"
        + "| Raspberry Pi OS Trixie | `aarch64` | 3.13 (stock) | Production-supported |\n"
    )
    assert releases.supported_lines(text) == [(2, 5)]


def test_the_real_security_policy_names_its_supported_lines() -> None:
    text = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text()
    yes_rows = [line for line in text.splitlines() if line.rstrip().endswith("| Yes |")]
    assert len(releases.supported_lines(text)) == len(yes_rows) >= 1


@pytest.mark.parametrize(
    "text",
    [
        _HEADER + "| `2.5.x` | Yes |\n\n| `2.4.x` | Yes |\n",
        _HEADER + "| `2.5.x` | Yes |\nnote\n| `2.4.x` | Yes |\n",
        _HEADER + "| `2.5.x` | Yes |\n\n" + _HEADER + "| `2.4.x` | Yes |\n",
        _HEADER + "| `2.4.x` | Yes | No |\n| `2.5.x` | Yes |\n",
        "```\n"
        + _HEADER
        + "| `2.9.x` | Yes |\n```\n"
        + _HEADER
        + "| `2.5.x` | Yes |\n",
    ],
    ids=["blank-line", "note-in-table", "second-table", "three-cells", "fenced-copy"],
)
def test_a_supported_line_the_parser_would_not_read_fails_closed(text: str) -> None:
    with pytest.raises(ValueError):
        releases.supported_lines(text)


def test_crlf_and_alignment_colons_still_read() -> None:
    text = "| Version | Supported |\r\n| :---: | :---: |\r\n| `2.5.x` | Yes |\r\n"
    assert releases.supported_lines(text) == [(2, 5)]


def test_the_newest_final_patch_is_audited_and_a_prerelease_never() -> None:
    tags = ["v2.5.0-rc.13", "v2.5.9", "v2.5.10", "v2.4.7", "v2.5.11-rc.1", "v2.50.0"]
    assert releases.newest_final_tag(tags, (2, 5)) == "v2.5.10"
    with pytest.raises(ValueError):
        releases.newest_final_tag(["v2.5.0-rc.1"], (2, 5))


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def _tagged_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "release")
    _git(repo, "tag", "v2.5.0")
    return repo


def test_a_release_is_audited_for_what_it_puts_on_devices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _tagged_repo(
        tmp_path,
        {
            "requirements/runtime.txt": PIN.replace("x==", "runtime==", 1),
            "requirements/pi.txt": PIN.replace("x==", "pi==", 1),
            "requirements/dev.txt": PIN.replace("x==", "dev==", 1),
            "requirements/build.txt": PIN.replace("x==", "build==", 1),
            "requirements/runtime.in": "runtime\n",
            "mobile/ori-runtime-mobile/Cargo.lock": (
                'version = 4\n\n[[package]]\nname = "rustls"\nversion = "0.23.45"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            ),
        },
    )
    monkeypatch.chdir(repo)
    assert releases.release_packages("v2.5.0") == [
        ("PyPI", "pi", "1.0"),
        ("PyPI", "runtime", "1.0"),
        ("crates.io", "rustls", "0.23.45"),
    ]


def test_a_release_without_its_runtime_lock_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _tagged_repo(tmp_path, {"requirements/pi.txt": PIN})
    monkeypatch.chdir(repo)
    with pytest.raises(ValueError):
        releases.release_packages("v2.5.0")


def test_every_finding_names_its_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _tagged_repo(
        tmp_path,
        {
            "SECURITY.md": _HEADER + "| `2.5.x` (stable) | Yes |\n",
            "requirements/runtime.txt": PIN,
        },
    )
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        audit_locks, "audit", lambda packages: (["PyPI x 1.0: GHSA-1 bad"], [])
    )
    assert releases.main() == 1
    assert "v2.5.0: PyPI x 1.0: GHSA-1 bad" in capsys.readouterr().err

    monkeypatch.setattr(audit_locks, "audit", lambda packages: ([], []))
    assert releases.main() == 0


def test_an_outage_fails_the_release_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _tagged_repo(
        tmp_path,
        {
            "SECURITY.md": _HEADER + "| `2.5.x` | Yes |\n",
            "requirements/runtime.txt": PIN,
        },
    )
    monkeypatch.chdir(repo)

    def _down(packages: object) -> object:
        raise OSError("OSV unreachable")

    monkeypatch.setattr(audit_locks, "audit", _down)
    assert releases.main() == 1


@pytest.mark.parametrize(
    "row",
    [
        "| **`2.6.x`** | Yes |",
        "| `2.6.x` | **Yes** |",
        "| `2.6.x` | yes |",
        "| `2.6.x` | Yes (security only) |",
        "| `2.6.x` | Yes",
    ],
)
def test_a_version_row_it_cannot_read_fails_rather_than_drops_a_line(row: str) -> None:
    with pytest.raises(ValueError):
        releases.supported_lines(_HEADER + "| `2.5.x` (stable) | Yes |\n" + row + "\n")


def test_a_tag_is_read_as_exactly_major_minor_patch() -> None:
    assert releases.newest_final_tag(["v2.5.1", "v2.505", "v2.5.09"], (2, 5)) == (
        "v2.5.1"
    )


def test_one_unreadable_release_does_not_hide_another_releases_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = _tagged_repo(
        tmp_path,
        {
            "SECURITY.md": _HEADER + "| `2.4.x` | Yes |\n| `2.5.x` | Yes |\n",
            "requirements/runtime.txt": PIN,
        },
    )
    _git(repo, "rm", "-q", "requirements/runtime.txt")
    _git(repo, "commit", "-q", "-m", "a release without its lock")
    _git(repo, "tag", "v2.4.0")
    monkeypatch.chdir(repo)
    monkeypatch.setattr(
        audit_locks, "audit", lambda packages: (["PyPI x 1.0: GHSA-1 bad"], [])
    )
    assert releases.main() == 1
    err = capsys.readouterr().err
    assert "v2.5.0: PyPI x 1.0: GHSA-1 bad" in err
    assert "v2.4.0: audit could not complete" in err
