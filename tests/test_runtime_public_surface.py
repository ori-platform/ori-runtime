# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``ori.runtime`` exports its interface and nothing else.

``OriRuntime`` is composed from one class per domain, each in a private module
under ``ori/runtime/``, and the module-level helpers live in private modules by
concern. ``ori.runtime`` exports ``OriRuntime``, ``main``, and the functions and
constants other code reads from it. As a single module it also exposed every
private helper and every name it imported; those are not re-exported, because
nothing outside the runtime read them, and a re-export kept for no reader is a
shim. A test that needs a private name imports it from the module that defines
it.
"""

import importlib.metadata
import inspect
import types

import ori.runtime

#: The interface. A name is added here only when code outside ``ori/runtime/``
#: reads it.
INTERFACE: frozenset[str] = frozenset(
    {
        "EVIDENCE_POSTURE_AUTHORITY_KEYS_INCOMPLETE",
        "EVIDENCE_POSTURE_AUTHORITY_KEYS_MISSING",
        "EVIDENCE_POSTURE_AUTHORITY_KEYS_REFUSED",
        "EVIDENCE_POSTURE_CUSTODY_UNCONFIGURED",
        "EVIDENCE_POSTURE_SIGNING_UNAVAILABLE",
        "EVIDENCE_SHUTDOWN_FLUSH_TIMEOUT_S",
        "MEASUREMENT_REFUSALS_BEFORE_DEGRADED",
        "MEASUREMENT_WINDOWS_TO_RECOVER",
        "OriRuntime",
        "adapter_connect_config",
        "main",
        "measurement_notice_stage_due",
    }
)


def _namespace() -> set[str]:
    """Names ``ori.runtime`` binds, less the package's own private modules."""
    return {
        name
        for name, value in vars(ori.runtime).items()
        if not name.startswith("__")
        and not (
            isinstance(value, types.ModuleType)
            and value.__name__.startswith("ori.runtime.")
        )
    }


def test_ori_runtime_binds_exactly_its_interface() -> None:
    names = _namespace()
    assert names - INTERFACE == set(), "names added to ori.runtime"
    assert INTERFACE - names == set(), "names ori.runtime no longer binds"


def test_all_lists_the_interface() -> None:
    assert set(ori.runtime.__all__) == INTERFACE
    assert len(ori.runtime.__all__) == len(INTERFACE)


def test_every_export_is_defined_inside_the_package() -> None:
    """A name another package defines is imported from there, not through here."""
    for name in INTERFACE:
        value = getattr(ori.runtime, name)
        if inspect.isclass(value) or inspect.isfunction(value):
            assert value.__module__.startswith("ori.runtime."), name


def test_the_console_script_resolves_to_main() -> None:
    (entry,) = [
        ep
        for ep in importlib.metadata.entry_points(group="console_scripts")
        if ep.name == "ori-runtime"
    ]
    assert entry.value == "ori.runtime:main"
    assert entry.load() is ori.runtime.main


def test_python_dash_m_runs_main() -> None:
    import ori.runtime.__main__ as dunder_main

    assert dunder_main.main is ori.runtime.main
