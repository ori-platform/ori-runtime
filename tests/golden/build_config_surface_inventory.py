# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Build the runtime configuration surface inventory.

Generated, never transcribed. A schema hand-written from documentation rejected
34 shipped fields; copying keys by hand would reproduce that failure with more
steps.

# Why this tracks receivers

An earlier version recorded every ``.get()`` and subscript inside a parse
function, whatever object it was called on. That captures dictionary accesses,
not configuration paths: signature blocks, environment lookups and local
bookkeeping dicts were flattened in beside real settings, so ``verified`` and
``signed_at_ms`` appeared as though an operator could set them.

So this walks each parse function with a small environment mapping local names
to the configuration path they hold. A read is recorded only when its receiver
is in that environment, and a sub-section binding extends the path rather than
starting a new one. A key nobody can trace back to the parsed document is not a
configuration key.

# What is mechanical, and what is not

Mechanical: the path, the function that reads it, whether it is required, its
literal default, and whether the shipped example sets that exact path.

Not mechanical, and marked ``review`` rather than guessed: types, constraints,
conditional dependencies, disposition, authority and destination. Types and
constraints live in validation code; disposition and authority are decisions.
Defaulting 208 entries to "retain" under "provisioning" would be asserting both
while claiming to refuse guesses.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
from typing import Any

# Resolved from this file's location, never from an absolute path: the output
# is committed to a public repository, and a checkout path is neither portable
# nor anyone else's business.
RUNTIME = pathlib.Path(__file__).resolve().parents[2]
CONFIG = RUNTIME / "ori" / "config.py"
EXAMPLE = RUNTIME / "ori.yaml.example"
HAL = RUNTIME / "ori" / "hal"

REQUIRE_HELPERS = {"_require_str", "_require_int", "_require_float", "_require_bool"}

#: Parse function -> the configuration path its parameter holds. Written out
#: because the mapping is a fact about this module's structure, and deriving it
#: from call sites would be another broad match.
ENTRY_POINTS = {
    "_parse_device": "device",
    "_parse_sensors": "sensors",
    "_parse_skills": "skills",
    "_parse_reasoning": "reasoning",
    "_parse_gateway": "gateway",
    "_parse_gateway_broker_posture": "gateway.broker_posture",
    "_parse_telemetry_export": "telemetry_export",
    "_parse_device_policy": "device_policy",
    "_parse_health_socket": "health_socket",
    "_parse_firmware_mqtt_provisioning": "firmware_mqtt_provisioning",
    "_parse_os_sandbox": "os_sandbox",
    "_parse_database_path": "database",
    "_parse_security": "security",
    "_parse_actions": "actions",
    "_parse_hal": "hal",
    "_parse_state": "state",
    "_parse_state_encryption": "state.encryption",
    "_parse_evidence": "evidence",
    "_parse_logging": "logging",
}

#: The only disposition this artifact asserts. Inventing a retirement is how a
#: shipped feature disappears in a schema change.
RELOCATE = {
    "device.rated_capacity_amps": {
        "authority": "commissioning",
        "destination": "commissioned-safety-binding/v1 zone rated_capacity",
        "why": (
            "A release-owned multiplier turns it into a trip point, so whoever "
            "supplies it decides when a cutoff fires."
        ),
    }
}


def _string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _default(node: ast.Call) -> Any:
    if len(node.args) < 2:
        return None
    try:
        return ast.literal_eval(node.args[1])
    except Exception:
        return "<expression>"


def _receiver(node: ast.AST) -> str | None:
    """Name of the object a read is performed on, if it is a plain name."""
    return node.id if isinstance(node, ast.Name) else None


class SectionWalker(ast.NodeVisitor):
    """Walk one parse function, tracking which locals hold configuration."""

    def __init__(self, base_path: str, param: str, function: str):
        self.env: dict[str, str] = {param: base_path}
        self.function = function
        self.rows: dict[str, dict[str, Any]] = {}

    # -- recording --------------------------------------------------------

    def record(self, prefix: str, key: str, required: bool, default: Any) -> None:
        path = f"{prefix}.{key}" if prefix else key
        row = self.rows.setdefault(
            path,
            {
                "path": path,
                "key": key,
                "read_by": self.function,
                "presence": "optional",
                "default": None,
            },
        )
        if required:
            row["presence"] = "required"
        if row["default"] is None and default is not None:
            row["default"] = default

    def read(self, node: ast.AST) -> tuple[str, str, bool, Any] | None:
        """Return (prefix, key, required, default) if node reads configuration."""
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr == "get" and node.args:
                prefix = self.env.get(_receiver(fn.value) or "")
                key = _string(node.args[0])
                if prefix is not None and key:
                    return prefix, key, False, _default(node)
            if (
                isinstance(fn, ast.Name)
                and fn.id in REQUIRE_HELPERS
                and len(node.args) >= 2
            ):
                prefix = self.env.get(_receiver(node.args[0]) or "")
                key = _string(node.args[1])
                if prefix is not None and key:
                    return prefix, key, True, None
            # dict(x) / list(x) keep the binding alive
            if isinstance(fn, ast.Name) and fn.id in {"dict", "list"} and node.args:
                prefix = self.env.get(_receiver(node.args[0]) or "")
                if prefix is not None:
                    return prefix, "", False, None
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            prefix = self.env.get(_receiver(node.value) or "")
            key = _string(node.slice)
            if prefix is not None and key:
                return prefix, key, True, None
        return None

    # -- traversal --------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        hit = self.read(node.value)
        if hit is not None:
            prefix, key, required, default = hit
            if key:
                self.record(prefix, key, required, default)
            child = f"{prefix}.{key}" if key else prefix
            for target in node.targets:
                name = _receiver(target)
                if name:
                    # `x = data.get("sms") or {}` and `x = dict(raw)` both bind
                    # a sub-section; the path extends rather than restarting.
                    self.env[name] = child
        else:
            # `x = data.get("sms") or {}` — the read is inside a BoolOp
            if isinstance(node.value, ast.BoolOp) and node.value.values:
                inner = self.read(node.value.values[0])
                if inner is not None:
                    prefix, key, required, default = inner
                    if key:
                        self.record(prefix, key, required, default)
                    child = f"{prefix}.{key}" if key else prefix
                    for target in node.targets:
                        name = _receiver(target)
                        if name:
                            self.env[name] = child
                else:
                    self.clear(node.targets, node.value)
            else:
                self.clear(node.targets, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """`for item in data:` and `for i, item in enumerate(data):`.

        Without this the entire list-of-object surface vanishes: sensors and
        skills are parsed by iterating, so every key under them was invisible
        while the inventory reported a confident total.
        """
        source = node.iter
        if (
            isinstance(source, ast.Call)
            and isinstance(source.func, ast.Name)
            and source.func.id in {"enumerate", "list", "reversed"}
            and source.args
        ):
            source = source.args[0]
        base = self.env.get(_receiver(source) or "")
        if base is not None:
            element = f"{base}[]"
            target = node.target
            if isinstance(target, ast.Tuple):
                # enumerate() yields (index, item); the item is the last element.
                for part in target.elts[1:]:
                    name = _receiver(part)
                    if name:
                        self.env[name] = element
            else:
                name = _receiver(target)
                if name:
                    self.env[name] = element
        self.generic_visit(node)

    def derives_from_config(self, node: ast.AST) -> bool:
        """Does any part of this expression read configuration?

        Checked over the whole subtree, not just its root. `x = str(data.get(
        "k"))` derives from configuration even though its outermost node is a
        call to str, and clearing on the root alone silently dropped the entire
        security section.
        """
        for child in ast.walk(node):
            if self.read(child) is not None:
                return True
            # `data = data or {}` and `raw = dict(raw)` normalise in place. The
            # value reads nothing, and clearing on that alone emptied the
            # environment on the first statement of several parse functions.
            if isinstance(child, ast.Name) and child.id in self.env:
                return True
        # `if data is None: data = {}` normalises an absent section to an empty
        # one. It is the same section, and treating it as a rebind emptied the
        # environment on the first statement of _parse_security.
        if isinstance(node, ast.Dict) and not node.keys:
            return True
        if isinstance(node, ast.List) and not node.elts:
            return True
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        return False

    def clear(self, targets: list[ast.expr], value: ast.AST) -> None:
        """A name rebound to something unrelated stops holding configuration."""
        if self.derives_from_config(value):
            return
        for target in targets:
            name = _receiver(target)
            if name and name in self.env:
                del self.env[name]

    def generic_visit(self, node: ast.AST) -> None:
        hit = self.read(node)
        if hit is not None:
            prefix, key, required, default = hit
            if key:
                self.record(prefix, key, required, default)
        super().generic_visit(node)


def parse_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        n.name: n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name in ENTRY_POINTS
    }


def collect(tree: ast.Module) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for name, fn in sorted(parse_functions(tree).items()):
        if not fn.args.args:
            continue
        walker = SectionWalker(ENTRY_POINTS[name], fn.args.args[0].arg, name)
        for stmt in fn.body:
            walker.visit(stmt)
        for path, row in walker.rows.items():
            if path in rows and rows[path]["presence"] == "required":
                continue
            rows[path] = row
    return [rows[p] for p in sorted(rows)]


def example_paths() -> set[str]:
    import yaml

    doc = yaml.safe_load(EXAMPLE.read_text())
    found: set[str] = set()

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, sub in value.items():
                child = f"{path}.{key}" if path else str(key)
                found.add(child)
                walk(sub, child)
        elif isinstance(value, list):
            for item in value:
                walk(item, f"{path}[]")

    walk(doc, "")
    return found


def adapter_metadata() -> dict[str, dict[str, Any]]:
    """What each adapter reads from the dict runtime.py hands to connect()."""
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(HAL.glob("*.py")):
        tree = ast.parse(path.read_text())
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            keys: dict[str, Any] = {}
            for node in ast.walk(cls):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and node.args
                    and _receiver(node.func.value) in {"config", "cfg", "_config"}
                ):
                    key = _string(node.args[0])
                    if key:
                        keys.setdefault(key, _default(node))
                if (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.slice, ast.Constant)
                    and _receiver(node.value) in {"config", "cfg", "_config"}
                ):
                    key = _string(node.slice)
                    if key:
                        keys.setdefault(key, "<required>")
            if keys:
                out[cls.name] = dict(sorted(keys.items()))
    return dict(sorted(out.items()))


def in_example_exact(path: str, example: set[str]) -> bool:
    """Exact path membership.

    A function rather than an inline `in` so it is testable. Suffix matching
    credited every `enabled`, `port` and `mode` to whichever section happened to
    contain one, and the resulting count was reproducible and wrong.
    """
    return path in example


def coverage(entries: list[dict[str, Any]], in_example: set[str]) -> dict[str, Any]:
    """What this inventory does not cover, stated rather than implied.

    The walk covers ori/config.py's parse functions. Keys read elsewhere are
    not covered: runtime.py assembles the dict handed to adapter.connect(), and
    adapters read from it directly.

    Adapter correlation applies to ``sensors[]`` paths only. An earlier version
    matched any path whose final segment appeared in any adapter, which credited
    ``actions.coap.timeout_s`` and ``actions.sms.gsm.port`` to sensor adapters
    that merely happen to read ``timeout_s`` and ``port``. Sharing a leaf name
    with an unrelated adapter is not evidence of anything.
    """
    extracted = {e["path"] for e in entries}
    adapters = adapter_metadata()
    missing = sorted(in_example - extracted)
    leaves = [p for p in missing if not any(o.startswith(p + ".") for o in in_example)]

    sensor_metadata: list[dict[str, Any]] = []
    unparsed_elsewhere: list[str] = []
    name_absent: list[str] = []

    for path in leaves:
        key = path.rsplit(".", 1)[-1]
        if path.startswith("sensors[]"):
            readers = sorted(name for name, keys in adapters.items() if key in keys)
            entry: dict[str, Any] = {"path": path, "read_by_adapters": readers}
            if ".calibration." in path:
                # runtime.py passes calibration as its own nested block rather
                # than merging it into metadata, so its inner keys are read from
                # config["calibration"] and never appear as top-level adapter
                # reads. An empty reader list here is expected, not a finding.
                entry["nested_block"] = "calibration"
            sensor_metadata.append(entry)
            continue
        # Outside sensors[] no adapter claim is made. The only mechanical thing
        # left to say is whether the key name occurs in the package at all,
        # which is evidence of probable dead configuration and not proof.
        found = subprocess.run(
            ["grep", "-rlq", f'"{key}"', str(RUNTIME / "ori")], check=False
        )
        if found.returncode == 0:
            unparsed_elsewhere.append(path)
        else:
            name_absent.append(path)

    return {
        "note": (
            "Paths the shipped example sets that ori/config.py's parse functions "
            "do not read. Adapter correlation is applied to sensors[] only, "
            "because a shared leaf name elsewhere proves nothing."
        ),
        "example_leaf_paths_not_parsed": len(leaves),
        "sensor_metadata": sensor_metadata,
        "read_elsewhere_in_ori": sorted(unparsed_elsewhere),
        "leaf_name_absent_from_ori": {
            "caveat": (
                "The leaf key name does not appear as a quoted string anywhere "
                "in ori/. Strong evidence of configuration nothing reads; not "
                "proof, since a key could be assembled dynamically."
            ),
            "paths": sorted(name_absent),
        },
    }


def main() -> None:
    commit = subprocess.run(
        ["git", "-C", str(RUNTIME), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()

    in_example = example_paths()
    entries = []
    for row in collect(ast.parse(CONFIG.read_text())):
        reloc = RELOCATE.get(row["path"])
        entries.append(
            {
                **row,
                "type": "review",
                "constraints": "review",
                "conditional_on": "review",
                # Exact path match. Suffix matching credited every `enabled` and
                # `port` to whichever section happened to contain one.
                "in_example": in_example_exact(row["path"], in_example),
                "disposition": "relocate" if reloc else "review",
                "authority": reloc["authority"] if reloc else "review",
                "destination": reloc["destination"] if reloc else "review",
            }
        )

    json.dump(
        {
            "artifact": "runtime configuration surface inventory",
            "normative": False,
            "purpose": (
                "Evidence for designing runtime-config/v2. Not a contract, not a "
                "versioned baseline entry."
            ),
            "runtime_commit": commit,
            "source": "ori/config.py",
            "example": "ori.yaml.example",
            "method": (
                "Per-function AST walk of ori/config.py with an environment mapping "
                "local names to configuration paths. A read is recorded only when "
                "its receiver holds configuration, so intermediate dictionaries are "
                "not flattened in beside real settings. Types, constraints, "
                "conditional dependencies, disposition, authority and destination "
                "are marked 'review': the first three live in validation code, and "
                "the last three are decisions this artifact has no standing to make."
            ),
            "sensor_metadata_note": (
                "sensors[] is open by construction. _parse_sensors keeps id, type, "
                "protocol, poll_interval_ms and calibration, and routes every other "
                "key into metadata, validated only for protocol coap. runtime.py "
                "merges metadata into the dict passed to adapter.connect(), so the "
                "accepted metadata surface is whatever each adapter reads. "
                "adapter_metadata is that surface."
            ),
            "entries": entries,
            "coverage": coverage(entries, in_example),
            "adapter_metadata": adapter_metadata(),
        },
        sys.stdout,
        indent=1,
    )
    print()


if __name__ == "__main__":
    main()
