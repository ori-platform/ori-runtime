# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Keep the board GPIO library's notify pipe out of the caller's directory.

`lgpio` changes the process's working directory to `LG_WD` when imported, or
stays where it is when that is unset, and creates `.lgd-nfy<N>` there by a
relative path, never removing it. An operator command run from the data
directory therefore left a named pipe in the install root, which the installer
refuses on the next upgrade. So every Ori process points `LG_WD` at a directory
it owns, and the working directory lgpio moves the process out of is restored as
soon as its import finishes, before any relative path is resolved against the
wrong directory. The directory must exist when lgpio is imported, or the import
fails, and with it the relay.

The working directory is process-wide, so for the moment lgpio's import runs,
any other thread resolving a relative path resolves it in `LG_WD`. Only
importing lgpio at a single-threaded point would close that window; the service
is unaffected, since its working directory is its `LG_WD`.
"""

from __future__ import annotations

import atexit
import importlib.abc
import importlib.machinery
import logging
import os
import shutil
import sys
import tempfile
from collections.abc import Generator, MutableMapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

LG_WD = "LG_WD"
_TEMPORARY_BASES = ("/tmp", "/var/tmp", "/usr/tmp")
_RUNTIME_ROOT = Path("/run")

logger = logging.getLogger(__name__)


def contain(environ: MutableMapping[str, str] = os.environ) -> str | None:
    """Point `LG_WD` at a directory this process owns, before any GPIO import.

    A systemd service uses its runtime directory. Anything else gets a private
    temporary directory, removed when the process exits. An inherited `LG_WD`
    is never kept: it may name the directory this exists to spare, and a child
    process is better served by a directory of its own. Returns the directory,
    or None when none could be made, in which case `LG_WD` is left unset and
    lgpio falls back to the working directory as it always has.
    """
    _keep_working_directory_across_lgpio()
    environ.pop(LG_WD, None)
    runtime = environ.get("RUNTIME_DIRECTORY", "").split(":")[0]
    if runtime and _is_runtime_directory(runtime) and _usable(runtime):
        environ[LG_WD] = runtime
        return runtime
    private = _private_directory(environ)
    if private is not None:
        environ[LG_WD] = private
        atexit.register(shutil.rmtree, private, True)
    return private


def _private_directory(environ: MutableMapping[str, str]) -> str | None:
    """A new 0700 directory under an absolute temporary base.

    tempfile's own choice falls back to the working directory when no temporary
    directory is writable, which is the directory this exists to spare, so the
    bases are named here instead. A base at or below the working directory is
    skipped too, relative ones included: a process killed before its exit
    handler runs leaves the directory, and the pipe in it, behind.
    """
    try:
        cwd: Path | None = Path.cwd().resolve()
    except OSError:
        cwd = None
    bases = [environ.get(name, "") for name in ("TMPDIR", "TEMP", "TMP")]
    for base in [*bases, *_TEMPORARY_BASES]:
        if not base or not os.path.isabs(base):
            continue
        if cwd is not None and Path(base).resolve().is_relative_to(cwd):
            continue
        try:
            return tempfile.mkdtemp(prefix="ori-lgpio-", dir=base)
        except OSError:
            continue
    return None


def _is_runtime_directory(directory: str) -> bool:
    """Under /run, where systemd creates runtime directories for system and user units.

    Only root writes there, apart from a user's own /run/user/<uid>, so an
    ambient RUNTIME_DIRECTORY cannot name the working directory elsewhere.
    """
    return os.path.isabs(directory) and Path(directory).resolve().is_relative_to(
        _RUNTIME_ROOT.resolve()
    )


def _usable(directory: str) -> bool:
    return Path(directory).is_dir() and os.access(directory, os.W_OK | os.X_OK)


def _moved(reason: object) -> None:
    logger.warning(
        "could not return to the working directory after importing lgpio (%s); "
        "relative paths now resolve in %s",
        reason,
        os.environ.get(LG_WD, "the lgpio directory"),
    )


@contextmanager
def _working_directory_kept() -> Generator[None, None, None]:
    # Held open where possible, so the restore returns to this directory even
    # if its path is removed or taken by another directory meanwhile. O_PATH
    # needs no permission to list the directory, only to be in it.
    descriptor: int | None = None
    path: str | None = None
    try:
        descriptor = os.open(".", getattr(os, "O_PATH", os.O_RDONLY))
    except OSError:
        try:
            path = os.getcwd()
        except OSError as exc:
            _moved(exc)
    try:
        yield
    finally:
        try:
            if descriptor is not None:
                os.fchdir(descriptor)
            elif path is not None:
                os.chdir(path)
        except OSError as exc:
            _moved(exc)
        finally:
            if descriptor is not None:
                os.close(descriptor)


class _RestoringLoader(importlib.abc.Loader):
    """Runs lgpio's own loader, then puts the working directory back.

    The move happens while `lgpio.py` executes: its extension, `_lgpio`, leaves
    the working directory alone when initialised (measured on the Trixie
    `python3-lgpio` 0.2.2 build).
    """

    def __init__(self, loader: importlib.abc.Loader) -> None:
        self._loader = loader

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        return self._loader.create_module(spec)

    def exec_module(self, module: ModuleType) -> None:
        with _working_directory_kept():
            self._loader.exec_module(module)

    def __getattr__(self, name: str) -> object:
        # Read from the instance dictionary: a copy or unpickle builds the
        # object without __init__, and `self._loader` would come back here.
        loader = self.__dict__.get("_loader")
        if loader is None:
            raise AttributeError(name)
        return getattr(loader, name)


class _LgpioFinder(importlib.abc.MetaPathFinder):
    """Wraps lgpio's loader, whoever imports it: Blinka, gpiozero or a caller."""

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname != "lgpio":
            return None
        for finder in sys.meta_path:
            if finder is self or not hasattr(finder, "find_spec"):
                continue
            spec = finder.find_spec(fullname, path, target)
            if spec is not None and spec.loader is not None:
                spec.loader = _RestoringLoader(spec.loader)
                return spec
        return None


def _keep_working_directory_across_lgpio() -> None:
    if not any(isinstance(finder, _LgpioFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _LgpioFinder())
