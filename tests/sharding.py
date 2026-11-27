# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Split the suite across CI runners: `--ori-shard K/N` keeps the tests whose
node id hashes to shard K of N. Run on one collection, as the shards of a CI
run are, the N shards together run every test once.

An option, not an environment variable: the pytest runs that tests start
themselves would inherit a variable and filter their own collection.
"""

from __future__ import annotations

import re
import zlib

import pytest

OPTION = "--ori-shard"
_SPEC = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")


def parse(spec: str) -> tuple[int, int]:
    """Return (K, N) for "K/N" with 1 <= K <= N, or raise UsageError."""
    match = _SPEC.fullmatch(spec)
    if match is None or int(match[1]) > int(match[2]):
        raise pytest.UsageError(
            f"{OPTION} takes K/N with 1 <= K <= N, such as 2/3; got {spec!r}"
        )
    return int(match[1]), int(match[2])


def shard_of(nodeid: str, shards: int) -> int:
    """The shard, 1 to *shards*, that runs *nodeid*: the same for the same id in
    every process. A few ids embed the checkout's path, so a shard's tests
    can differ between two checkouts."""
    return zlib.crc32(nodeid.encode("utf-8")) % shards + 1


def add_option(parser: pytest.Parser) -> None:
    parser.addoption(
        OPTION,
        default=None,
        metavar="K/N",
        help="run only shard K of N of the collected tests",
    )


def select(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Deselect every item outside this run's shard, if one was asked for."""
    spec = config.getoption(OPTION)
    if spec is None:
        return
    shard, shards = parse(spec)
    kept: list[pytest.Item] = []
    dropped: list[pytest.Item] = []
    for item in items:
        (kept if shard_of(item.nodeid, shards) == shard else dropped).append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept
