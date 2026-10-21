# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Build a release's health export `items[0]` from that release's own source.

gateway-api/v2's health-transition corpus mutates real runtime exports, so its
baselines must come from the producer, never from a hand-trimmed fixture. This
extracts `ori/` at a git ref, builds `OriRuntime._build_health_snapshot` there,
unstarted, on a fixed clock, with device id `dev-01`, and prints the JSON.

    python scripts/health_export_baseline.py v2.5.0 > items0-v2.5.0.json

An unstarted runtime reports `safety` as null, an empty `health_socket_path`
and `uptime_s` 0; a served export comes from a started one. The output names
no path, secret or user value.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tarfile
import tempfile
import time
from io import BytesIO
from pathlib import Path

FIXED_S = 1_790_000_000.0
DEVICE_ID = "dev-01"


def _extract(ref: str, into: Path) -> None:
    repository = Path(__file__).resolve().parent.parent
    archive = subprocess.run(
        ["git", "-C", str(repository), "archive", ref, "ori"],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=BytesIO(archive)) as tar:
        tar.extractall(into, filter="data")


def build(ref: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tree:
        _extract(ref, Path(tree))
        sys.path.insert(0, tree)
        import ori.runtime as runtime_module

        if not str(runtime_module.__file__).startswith(tree):
            raise SystemExit("the extracted tree did not load; run from outside it")
        time.time = lambda: FIXED_S
        time.monotonic = lambda: 1_000.0
        for module in list(sys.modules.values()):
            if getattr(module, "__name__", "").startswith("ori") and hasattr(
                module, "now_ms"
            ):
                module.now_ms = lambda: int(FIXED_S * 1000)  # type: ignore[attr-defined]
        runtime = runtime_module.OriRuntime(config_path="ori.yaml")
        runtime._device_id = DEVICE_ID
        return asyncio.run(runtime._build_health_snapshot())


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: health_export_baseline.py <git ref>", file=sys.stderr)
        return 2
    json.dump(build(argv[1]), sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
