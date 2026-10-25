# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Which skills ship with the runtime, and the community trust anchor."""

import base64
import binascii
import functools
import importlib.metadata
import importlib.util
import json
import logging
import os
import sysconfig
import tomllib
import urllib.parse
from pathlib import Path

from ori.security.ed25519_keys import refused_public_key_clause
from ori.security.published_test_keys import PUBLISHED_TEST_KEYS
from ori.skills._manifest import (
    MAX_MANIFEST_BYTES,
)
from ori.utils.strict_json import unique_members

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")
# The value a build ships with until a Hub signing key exists. Compared as a
# sentinel rather than against the constant itself, so a deployment that
# configures a real anchor is not called unconfigured by a build that has one.
UNCONFIGURED_HUB_ANCHOR = "PENDING_REPLACE_AT_HUB_LAUNCH"
HUB_ROOT_PUBLIC_KEY_B64 = UNCONFIGURED_HUB_ANCHOR
HUB_TRUST_ANCHOR_ENV = "ORI_HUB_ROOT_PUBLIC_KEY_B64"


def anchor_fault_of(trust_anchor_b64: str, source: str) -> str | None:
    """Why this anchor can authenticate nothing, or ``None`` if it can.

    Every way an anchor fails is answered here, because the caller asks two
    questions with one answer: whether to refuse the skill being read, and
    whether the deployment can admit community skills at all. Leaving the
    malformed cases to the shared verifier answered only the first — it
    refuses per skill, in a vocabulary that never reaches a health report, so
    a device with an anchor that decodes to nothing refused every community
    skill while reporting the anchor usable.

    One fault still yields one message: this refuses first, so
    `verify_signed_payload` is never reached with an anchor it would also
    reject. What it adds is the source a deployment actually configured, which
    the shared verifier cannot know.

    An empty anchor has no branch here because it cannot arrive: an empty
    constructor value and an empty environment variable both fall through to
    the shipped sentinel, which the caller answers before this is reached.
    """
    try:
        raw = base64.b64decode(trust_anchor_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return f"{source} is not valid base64"
    if base64.b64encode(raw).decode("ascii") != trust_anchor_b64:
        return f"{source} is not canonical base64"
    if len(raw) != 32:
        return (
            f"{source} does not decode to a 32-byte Ed25519 public key; it "
            f"decodes to {len(raw)} bytes"
        )
    if raw in PUBLISHED_TEST_KEYS:
        return (
            f"{source} names a key whose private seed is "
            "published test material in this repository, so anyone holding a "
            "clone can sign a community skill this runtime would accept. A "
            "forged skill cannot reach Tier D, which today is confined to "
            "skills shipped with the runtime, but it can declare Tier B "
            "triggers that act without approval. Generate a Hub signing key "
            "that has never left the producer and configure its public half "
            "instead."
        )
    clause = refused_public_key_clause(raw)
    if clause is not None:
        return (
            f"{source} is refused ({clause}): it is not an Ed25519 public key a "
            "private key can stand behind, so it can authenticate no skill. "
            "Configure the public half of a Hub signing key."
        )
    return None


# Where first-party skills live. A source checkout keeps them beside the
# package; an installed wheel puts them under the interpreter's data path.
# Both are shipped with the runtime and reviewed with it.
_SKILLS_DATA_DIR = Path("share") / "ori-runtime" / "skills"
_DISTRIBUTION = "ori-runtime"


@functools.cache
def _source_checkout(module_file: str) -> Path | None:
    """The source checkout this module runs from, or None when it is installed.

    Beside an installed package is site-packages, where any distribution can
    install a ``skills`` directory or a ``pyproject.toml``, so no file found
    there is evidence. The runtime's own installation record decides first: a
    distribution whose RECORD owns this module was installed from a wheel and
    has no checkout, whatever any other record says and in whatever order the
    records are found; an editable one names its source directory. Only a
    module no installation owns falls back to the checkout's own declaration.

    Read once per process: an installation changed in place takes effect at
    the next start, which is how the installer applies one.
    """
    module = Path(module_file)
    root = module.parents[2]
    dists = list(importlib.metadata.distributions(name=_DISTRIBUTION))
    if any(_record_owns(dist, module) for dist in dists):
        return None
    if any(_editable_source(dist) == root for dist in dists):
        return root
    return root if _declares_distribution(root / "pyproject.toml") else None


def _record_owns(dist: importlib.metadata.Distribution, module: Path) -> bool:
    """Whether a wheel installation's RECORD lists *module* as installed.

    Compared by the file each entry locates, as the filesystem identifies it
    (device and inode), never by how the entry is spelled. RECORD may name a
    file relative to site-packages, by an absolute path, or relative with
    ``..``, and on a case- or normalisation-insensitive filesystem in any case
    or Unicode form; each of those names the same file. Only RECORD counts. A
    legacy ``.egg-info`` in a checkout lists the checkout's own sources, which
    is not an installation.
    """
    try:
        if dist.read_text("RECORD") is None:
            return False
        target = os.stat(module)
    except (OSError, ValueError):
        return False
    identity = (target.st_dev, target.st_ino)
    for entry in dist.files or ():
        try:
            located = os.stat(str(dist.locate_file(entry)))
        except (OSError, ValueError):
            continue
        if (located.st_dev, located.st_ino) == identity:
            return True
    return False


def _editable_source(dist: importlib.metadata.Distribution) -> Path | None:
    try:
        raw = dist.read_text("direct_url.json")
        record = json.loads(raw, object_pairs_hook=unique_members()) if raw else {}
        if record.get("dir_info", {}).get("editable") is True:
            url = urllib.parse.urlparse(str(record["url"]))
            if url.scheme == "file":
                return Path(urllib.parse.unquote(url.path)).resolve()
    except (OSError, ValueError, KeyError, AttributeError, TypeError):
        # An unreadable or malformed record names no checkout, so the module
        # falls back to the stricter declaration check.
        return None
    return None


def _declares_distribution(pyproject: Path) -> bool:
    try:
        with pyproject.open("rb") as handle:
            data = tomllib.loads(handle.read(MAX_MANIFEST_BYTES).decode("utf-8"))
    except (OSError, ValueError):
        return False
    project = data.get("project")
    return isinstance(project, dict) and project.get("name") == _DISTRIBUTION


def first_party_skill_roots() -> tuple[Path, ...]:
    """Every directory whose contents ship with the runtime.

    This is the single definition of first-party provenance. It was previously
    duplicated — the loader knew only about the source checkout while
    ``bundled_skill_path()`` also resolved the installed layout, so a packaged
    skill loaded from a wheel was classified as untrusted community content and
    refused. Both call this now, because two definitions of "shipped with the
    runtime" is one more than a trust boundary can have.

    Only roots that exist are returned, so a layout that does not apply cannot
    contribute a directory an attacker might otherwise create.
    """
    candidates = [Path(sysconfig.get_path("data")) / _SKILLS_DATA_DIR]
    checkout = _source_checkout(str(Path(__file__).resolve()))
    if checkout is not None:
        candidates.insert(0, checkout / "skills")
    roots: list[Path] = []
    for candidate in candidates:
        try:
            if candidate.is_dir():
                roots.append(candidate.resolve())
        except OSError:  # unreadable or unresolvable — not a usable root
            continue
    return tuple(roots)


def is_skill_directory(path: Path) -> bool:
    """A real directory holding a manifest, as discovery counts one."""
    try:
        return (
            path.is_dir() and not path.is_symlink() and (path / "skill.yaml").exists()
        )
    except OSError:
        return False


def packaged_skill_names() -> frozenset[str]:
    """Directory names of every skill that ships with the runtime.

    Read from the packaged roots rather than a hard-coded list so a skill added
    to the package is protected from impersonation without a second edit.
    """
    names: set[str] = set()
    for root in first_party_skill_roots():
        try:
            for child in root.iterdir():
                if (child / "skill.yaml").is_file():
                    names.add(child.name)
        except OSError:
            continue
    return frozenset(names)
