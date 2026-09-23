# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""No Ori process leaves lgpio's notify pipe in the directory it ran from.

The real `lgpio` changes the working directory to `LG_WD` when imported, or
stays put when that is unset, fails when that directory is missing, and creates
`.lgd-nfy0` there by a relative path. The stub does the same, so the real entry
points are driven in subprocesses on any host. A stub `board` imports it, as
Blinka's does on a Pi.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ori.hardware import lgpio_workdir

REPO = Path(__file__).resolve().parent.parent

_LGPIO_STUB = """\
import os
os.chdir(os.environ.get("LG_WD") or os.getcwd())
if os.path.lexists(".lgd-nfy0"):
    os.unlink(".lgd-nfy0")
os.mkfifo(".lgd-nfy0")
"""

_BOARD_STUB = """\
import os
import lgpio
open(os.environ["ORI_TEST_BOARD_IMPORTED"], "w").close()
"""


def _stubs(tmp_path: Path) -> Path:
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    for name, text in (
        ("lgpio.py", _LGPIO_STUB),
        ("board.py", _BOARD_STUB),
        ("busio.py", ""),
    ):
        if not (stubs / name).exists():
            (stubs / name).write_text(text)
    return stubs


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "ori.yaml"
    path.write_text(
        textwrap.dedent(f"""\
            device:
              id: bench-01
              name: Bench
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: load-current
                type: ads1115_current
                protocol: i2c
                address: 0x48
                channel: 0
                poll_interval_ms: 1000
                calibration:
                  sensitivity_v_per_amp: 0.0333
                  mains_frequency_hz: 50
            skills: []
            reasoning:
              default_tier: rule
            actions:
              relay:
                enabled: false
                gpio_pin: 26
            database:
              path: {tmp_path / "ori_state.db"}
            logging:
              level: INFO
              file: {tmp_path / "ori.log"}
            """),
        encoding="utf-8",
    )
    return path


def _clean_env(**extra: str) -> dict[str, str]:
    """This process's environment without the lgpio directory it was given."""
    environ = {
        key: value
        for key, value in os.environ.items()
        if key not in (lgpio_workdir.LG_WD, "RUNTIME_DIRECTORY")
    }
    environ.update(extra)
    return environ


def _run(
    tmp_path: Path, args: list[str], **env: str
) -> tuple[Path, subprocess.CompletedProcess]:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    environ = {
        key: value
        for key, value in os.environ.items()
        if key not in (lgpio_workdir.LG_WD, "RUNTIME_DIRECTORY")
    }
    environ["PYTHONPATH"] = os.pathsep.join([str(_stubs(tmp_path)), str(REPO)])
    environ["ORI_TEST_BOARD_IMPORTED"] = str(tmp_path / "board-imported")
    environ.update(env)
    completed = subprocess.run(
        [sys.executable, *args], cwd=work, env=environ, capture_output=True, text=True
    )
    return work, completed


def test_an_ori_process_keeps_the_pipe_out_of_its_working_directory(tmp_path):
    """Imported in any order, lgpio writes into a directory the process owns and removes."""
    work, completed = _run(
        tmp_path,
        [
            "-c",
            "import ori, os, lgpio; print(os.environ['LG_WD']); print(os.getcwd())",
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert list(work.iterdir()) == []
    lg_wd, cwd = completed.stdout.split()
    assert Path(cwd).resolve() == work.resolve(), "lgpio moved the process"
    private = Path(lg_wd)
    assert private.name.startswith("ori-lgpio-")
    assert not private.exists(), "the private directory outlived its process"


@pytest.mark.parametrize(
    "command",
    [
        ["config", "validate"],
        ["commissioning", "inventory"],
        ["commissioning", "binding-export"],
    ],
    ids=lambda command: " ".join(command),
)
def test_a_bridge_read_imports_no_gpio_library_and_leaves_its_directory_alone(
    tmp_path, command
):
    """Validating a configuration reads the I2C schemas, never the board's GPIO library."""
    config = _config(tmp_path)

    work, completed = _run(
        tmp_path, ["-m", "ori.cli_bridge", *command, "--path", str(config)]
    )

    assert json.loads(completed.stdout)["schema_version"] == 1, completed.stderr
    assert list(work.iterdir()) == []
    assert not (tmp_path / "board-imported").exists(), (
        "reading a configuration imported the board library"
    )


def test_the_i2c_drivers_still_load_when_a_sensor_connects(tmp_path):
    """Deferred, not dropped: a connect imports the board library, into LG_WD."""
    work, completed = _run(
        tmp_path,
        [
            "-c",
            textwrap.dedent("""\
                import asyncio
                from ori.hal.base import AdapterConnectionError
                from ori.hal.i2c_adapter import I2CAdapter
                config = {
                    "sensor_id": "load-current",
                    "sensor_type": "ads1115_current",
                    "address": 0x48,
                    "calibration": {
                        "sensitivity_v_per_amp": 0.0333,
                        "mains_frequency_hz": 50,
                    },
                }
                import os
                try:
                    asyncio.run(I2CAdapter().connect(config))
                except AdapterConnectionError as exc:
                    pass
                print(os.getcwd())
                """),
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert (tmp_path / "board-imported").exists(), completed.stdout
    assert Path(completed.stdout.strip()).resolve() == work.resolve()
    assert list(work.iterdir()) == []


def test_a_service_uses_its_runtime_directory(tmp_path, monkeypatch):
    """systemd's runtime directory is the service's own, and it is left for systemd."""
    monkeypatch.setattr(lgpio_workdir, "_RUNTIME_ROOT", tmp_path)
    runtime = tmp_path / "ori"
    runtime.mkdir()
    environ = {"RUNTIME_DIRECTORY": f"{runtime}:{tmp_path / 'second'}"}

    assert lgpio_workdir.contain(environ) == str(runtime)
    assert environ[lgpio_workdir.LG_WD] == str(runtime)


def test_an_ambient_runtime_directory_outside_run_is_not_trusted(tmp_path):
    """XDG_RUNTIME_DIR and RUNTIME_DIRECTORY both set to the cwd prove nothing."""
    work = tmp_path / "work"
    work.mkdir()

    _, completed = _run(
        tmp_path,
        ["-c", "import ori, os, lgpio; print(os.environ['LG_WD'])"],
        RUNTIME_DIRECTORY=str(work),
        XDG_RUNTIME_DIR=str(work),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() != str(work)
    assert list(work.iterdir()) == []


def test_an_inherited_lg_wd_is_never_kept(tmp_path):
    """LG_WD=$PWD from the data directory would plant the pipe there again."""
    work = tmp_path / "work"
    work.mkdir()

    _, completed = _run(
        tmp_path,
        ["-c", "import ori, os, lgpio; print(os.environ['LG_WD'])"],
        LG_WD=str(work),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() != str(work)
    assert list(work.iterdir()) == []


def test_a_runtime_directory_outside_the_runtime_roots_is_not_used(tmp_path):
    """RUNTIME_DIRECTORY set by hand to the working directory is not a runtime dir."""
    work = tmp_path / "work"
    work.mkdir()

    _, completed = _run(
        tmp_path,
        ["-c", "import ori, os, lgpio; print(os.environ['LG_WD'])"],
        RUNTIME_DIRECTORY=str(work),
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() != str(work)
    assert list(work.iterdir()) == []


def test_no_directory_leaves_lg_wd_unset_rather_than_missing(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise OSError("read-only temporary directory")

    monkeypatch.setattr(lgpio_workdir.tempfile, "mkdtemp", refuse)
    environ = {lgpio_workdir.LG_WD: "/nonexistent/ori-lgpio"}

    assert lgpio_workdir.contain(environ) is None
    assert lgpio_workdir.LG_WD not in environ


def test_relative_paths_resolve_against_the_callers_directory_after_lgpio(tmp_path):
    """lgpio's import moves the process; the move is undone before anything resolves."""
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "ori.yaml").write_text("marker")

    work, completed = _run(
        tmp_path,
        [
            "-c",
            "import ori, lgpio; from pathlib import Path; "
            "print(Path('ori.yaml').read_text())",
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "marker"


def test_a_driver_failing_unexpectedly_raises_its_cause_every_time(tmp_path):
    """A failed load is not recorded as loaded, so the cause is never lost."""
    stubs = _stubs(tmp_path)
    (stubs / "board.py").write_text(
        "raise FileNotFoundError(2, 'No such file or directory', '.lgd-nfy-3')\n"
    )

    _, completed = _run(
        tmp_path,
        [
            "-c",
            textwrap.dedent("""\
                import ori.hal.i2c_adapter as m
                for _ in range(2):
                    try:
                        m.i2c_driver_unavailable_reason("ads1115_current")
                    except FileNotFoundError as exc:
                        print("raised", exc.filename)
                """),
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split("\n")[:2] == ["raised .lgd-nfy-3"] * 2


def test_no_usable_temporary_base_leaves_lg_wd_unset(tmp_path, monkeypatch):
    """With nowhere else to go, lgpio keeps its old behaviour; nothing is made in the cwd."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lgpio_workdir, "_TEMPORARY_BASES", (str(tmp_path / "gone"),))
    environ = {"TMPDIR": str(tmp_path / "also-gone")}

    assert lgpio_workdir.contain(environ) is None
    assert lgpio_workdir.LG_WD not in environ
    assert list(tmp_path.iterdir()) == []


def test_running_from_the_temporary_directory_still_contains(tmp_path):
    """From the temporary base itself, the private directory goes to another base."""
    base = tmp_path / "tmpbase"
    base.mkdir()

    completed = subprocess.run(
        [sys.executable, "-c", "import os, ori; print(os.environ.get('LG_WD'))"],
        cwd=base,
        env=_clean_env(TMPDIR=str(base), PYTHONPATH=str(REPO)),
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    private = Path(completed.stdout.strip())
    assert private.is_absolute()
    assert not private.resolve().is_relative_to(base.resolve())


@pytest.mark.parametrize("where", ["cwd", "below"])
def test_a_killed_process_leaves_no_pipe_under_its_working_directory(tmp_path, where):
    """TMPDIR at or below the cwd would keep the pipe there when no exit handler runs."""
    work = tmp_path / "work"
    (work / "sub").mkdir(parents=True)
    tmpdir = work if where == "cwd" else work / "sub"

    _, completed = _run(
        tmp_path,
        ["-c", "import os, ori, lgpio; os._exit(0)"],
        TMPDIR=str(tmpdir),
    )

    assert completed.returncode == 0, completed.stderr
    leftovers = [
        path
        for path in work.rglob("*")
        if path.name.startswith(("ori-lgpio-", ".lgd-nfy"))
    ]
    assert leftovers == []


def test_ori_imports_from_a_deleted_working_directory(tmp_path):
    """An operator's cwd removed under them is not a reason to fail every command."""
    gone = tmp_path / "gone"
    gone.mkdir()
    base = tmp_path / "tmpbase"
    base.mkdir()
    program = (
        "import os; os.chdir({gone!r}); os.rmdir({gone!r}); "
        "import ori; print(os.environ.get('LG_WD'))"
    ).format(gone=str(gone))

    completed = subprocess.run(
        [sys.executable, "-c", program],
        env=_clean_env(TMPDIR=str(base), PYTHONPATH=str(REPO)),
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert Path(completed.stdout.strip()).parent == base
    assert list(base.iterdir()) == [], "the private directory was not removed"


def test_the_wrapped_loader_still_answers_as_lgpios_own(tmp_path):
    work, completed = _run(
        tmp_path,
        ["-c", "import ori, lgpio; print(lgpio.__loader__.get_filename('lgpio'))"],
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().endswith("lgpio.py")


def test_a_working_directory_that_cannot_be_listed_is_still_restored(tmp_path):
    """Entering a directory needs no permission to read it; neither may the restore."""
    work = tmp_path / "work"
    work.mkdir()
    work.chmod(0o311)
    try:
        _, completed = _run(
            tmp_path, ["-c", "import ori, os, lgpio; print(os.getcwd())"]
        )
    finally:
        work.chmod(0o700)

    assert completed.returncode == 0, completed.stderr
    assert Path(completed.stdout.strip()).resolve() == work.resolve()


def test_the_wrapped_loader_survives_a_copy(tmp_path):
    _, completed = _run(
        tmp_path,
        ["-c", "import copy, ori, lgpio; copy.copy(lgpio.__loader__); print('copied')"],
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "copied"


def test_a_relative_temporary_base_is_skipped(tmp_path, monkeypatch):
    """TMPDIR=. would make the private directory in the caller's own directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lgpio_workdir, "_TEMPORARY_BASES", ())
    environ = {"TMPDIR": ".", "TMP": "relative"}

    assert lgpio_workdir.contain(environ) is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", ["save", "restore"])
def test_a_working_directory_that_cannot_be_kept_is_reported(
    failure, monkeypatch, caplog
):
    """Relative paths resolving in lgpio's directory is never silent."""

    def refuse(*_args, **_kwargs):
        raise OSError("refused")

    if failure == "save":
        monkeypatch.setattr(lgpio_workdir.os, "open", refuse)
        monkeypatch.setattr(lgpio_workdir.os, "getcwd", refuse)
    else:
        monkeypatch.setattr(lgpio_workdir.os, "fchdir", refuse)
        monkeypatch.setattr(lgpio_workdir.os, "chdir", refuse)

    with caplog.at_level("WARNING", logger=lgpio_workdir.__name__):
        with lgpio_workdir._working_directory_kept():
            pass

    assert "could not return to the working directory" in caplog.text
