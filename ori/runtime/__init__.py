# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Ori Runtime — main entry point.

Wires every component built into a running system:

    runtime = OriRuntime(config_path="ori.yaml")
    asyncio.run(runtime.start())

Or via the CLI entry point::

    ori-runtime --config /path/to/ori.yaml
"""

from ori.runtime._main import main
from ori.runtime._runtime import OriRuntime

__all__ = ["OriRuntime", "main"]
