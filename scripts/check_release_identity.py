#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Prove a release tag and the packaged version name the same build.

The workflow trigger is a glob and admits any `v*.*.*-*` tag. This is the
authority that decides whether such a tag may be built and signed, and it runs
in the preflight job — before a bundle exists and before any signing credential
is issued — so a tag that cannot produce a coherent release fails while the tag
is the only thing that has been published.

`v2.4.0-rc.1` and `v2.4.0-rc.2` were spent proving this: both passed the
protection preflight and the full test matrix, and both failed later, at a
point where the tag was already immutable.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import Sequence

from ori.security.release_bundles import ReleaseBundleError, distribution_version


def resolve_release_identity(tag: str, pyproject: Path) -> str:
    """Return the runtime version *tag* names, or raise if it names none.

    The tag is the SemVer spelling and the packaged version is the PEP 440 one,
    so they are compared through the single conversion authority rather than as
    strings — `v2.4.0-rc.3` and `2.4.0rc3` are the same build, `v2.4.0-rc.3` and
    `2.4.0` are not.
    """
    if not tag.startswith("v"):
        raise ValueError(f"release tag {tag!r} does not start with 'v'")
    runtime_version = tag[1:]

    try:
        expected = distribution_version(runtime_version)
    except ReleaseBundleError as exc:
        raise ValueError(
            f"release tag {tag!r} is not a canonical release identity "
            f"(expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N): "
            f"{exc.detail}"
        ) from exc

    try:
        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
            "version"
        ]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"could not read a project version from {pyproject}") from exc

    if declared != expected:
        raise ValueError(
            f"release tag {tag!r} needs {pyproject.name} version {expected!r}, "
            f"found {declared!r}"
        )
    return runtime_version


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag, including the 'v'")
    parser.add_argument("--pyproject", default="pyproject.toml", type=Path)
    args = parser.parse_args(argv)

    try:
        runtime_version = resolve_release_identity(args.tag, args.pyproject)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Consumed as a step output; the bundle, the artifact name and the
    # signature envelope all take their version from here.
    print(f"version={runtime_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
