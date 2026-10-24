# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reading a configuration document: admission, the bounded YAML loader, and the
environment variables it names."""

import errno
import os
import stat
from typing import Any

import yaml

from ori.config._env import _ENV_VAR_RE, expand_env_vars
from ori.config._fields import ConfigValidationError
from ori.utils.path_utils import shown


class _ConfigDocumentLimitError(Exception):
    """Raised by the bounded loader when a document exceeds a structural limit."""


class _BoundedConfigSafeLoader(yaml.SafeLoader):
    """Safe YAML loader with bounded structure and no aliases.

    ``Config.load`` reads a document the runtime did not write: on a phone it
    arrives from an onboarding API, on a Pi it can arrive through a remote
    policy fetch. Parsing happens before any of it is validated, and before a
    signature is checked, so these limits apply to content nothing has yet
    decided to trust.

    Aliases are refused rather than bounded, because a depth limit that allows
    them does not bound anything. Each alias composes at its own shallow depth
    while referencing an already-composed node, so a chain of them builds an
    object graph arbitrarily deeper than any node this loader ever saw, and the
    ordinary recursive visitors downstream are what then exhaust the stack. No
    shipped configuration uses an anchor.

    Limits match the skill manifest loader, which bounds the same hazard for
    the same reason. The deepest shipped example reaches depth 6 with 579
    nodes and 17 entries in its widest collection, and its longest scalar is
    54 characters.

    Scalar length is bounded here rather than left to the interpreter, because
    the interpreter's limit is neither general nor fixed: it applies to decimal
    conversion only, so a hex, octal or binary literal of any length is built
    without complaint, and ``PYTHONINTMAXSTRDIGITS=0`` removes it entirely from
    a process the runtime does not control.
    """

    max_depth = 32
    max_nodes = 20_000
    max_collection_entries = 1_000
    max_scalar_length = 4_096

    expand_env = False

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._depth = 0
        self._node_count = 0
        self._in_key_position = False

    def _limit_error(self, detail: str) -> _ConfigDocumentLimitError:
        return _ConfigDocumentLimitError(detail)

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            event = self.peek_event()
            raise self._limit_error(
                f"YAML aliases are not permitted (*{event.anchor}). Write the "
                "value out in full — a device configuration is a declaration, "
                "not a program."
            )

        self._node_count += 1
        if self._node_count > self.max_nodes:
            raise self._limit_error(f"more than {self.max_nodes} nodes")

        self._depth += 1
        if self._depth > self.max_depth:
            raise self._limit_error(f"nesting deeper than {self.max_depth} levels")
        # PyYAML composes a mapping key as `compose_node(node, None)` and its
        # value as `compose_node(node, key_node)`; a sequence item passes an
        # integer index and the root passes neither. Inherited downwards, so
        # everything inside a complex (`?`) key counts as key material too.
        was_in_key = self._in_key_position
        # Compared through a local so that narrowing `index` to `None` here
        # does not follow it into the `super()` call below, whose stub types
        # the parameter as `int`.
        position: Any = index
        self._in_key_position = was_in_key or (
            isinstance(parent, yaml.MappingNode) and position is None
        )
        try:
            return super().compose_node(parent, index)
        finally:
            self._in_key_position = was_in_key
            self._depth -= 1

    def compose_scalar_node(self, anchor: Any) -> Any:
        if self.expand_env and not self._in_key_position:
            self._expand_scalar_event()
        node = super().compose_scalar_node(anchor)
        if len(node.value) > self.max_scalar_length:
            raise self._limit_error(
                f"a scalar longer than {self.max_scalar_length} characters"
            )
        return node

    def _expand_scalar_event(self) -> None:
        """Substitute environment values into one scalar, and only into it.

        Expansion used to be a textual substitution over the whole document,
        performed after the signature was verified and before a second parse.
        A value carrying a quote and a newline therefore did not stay inside
        the scalar it was substituted into: it could close the quote and add
        keys, so a variable the document merely named could rewrite the
        document the runtime ran on — `device.rated_capacity_amps` included.

        Substituting into a scalar that the parser has already delimited makes
        that impossible. The value can be anything at all and it is still one
        scalar, because the document's structure was fixed before any
        environment value was consulted.

        A key is never expanded. Substituting into one would let an
        environment value choose a key name — `rated_capacity_${SUFFIX}`
        becoming `rated_capacity_amps`, or a value of `<<` becoming a merge
        key that rewrites the whole mapping — which is the same authority a
        textual substitution had, reached a different way.

        An unquoted scalar keeps its implicit typing: the tag is resolved from
        the substituted text, so a plain `${PORT}` still becomes an integer,
        exactly as the re-parse used to make it. A quoted scalar stays a
        string, because that is what quoting already meant, and an explicitly
        tagged one keeps its tag.
        """
        event = self.peek_event()
        if "${" not in event.value:
            return
        # Only the value is substituted. An explicit tag and a quoting style
        # both survive, because both already decided how the scalar is read,
        # so neither re-resolves against the substituted text.
        expanded = expand_env_vars(event.value)
        if event.style is None:
            # A plain scalar has its surrounding whitespace stripped by the
            # parser, and the textual substitution happened before that ran.
            # Stripping here keeps a value with a stray trailing space typing
            # as it did — otherwise `poll_interval_ms: ${PORT}` with "1000 "
            # becomes a string and a working deployment stops loading.
            expanded = expanded.strip()
        event.value = expanded

    def compose_sequence_node(self, anchor: Any) -> Any:
        node = super().compose_sequence_node(anchor)
        if len(node.value) > self.max_collection_entries:
            raise self._limit_error(
                f"a sequence with more than {self.max_collection_entries} entries"
            )
        return node

    def compose_mapping_node(self, anchor: Any) -> Any:
        node = super().compose_mapping_node(anchor)
        if len(node.value) > self.max_collection_entries:
            raise self._limit_error(
                f"a mapping with more than {self.max_collection_entries} keys"
            )
        return node

    def construct_config_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[str, Any]:
        """Refuse a repeated key rather than keeping the last of them.

        The signature is computed over the parsed document, so a last-wins
        duplicate means a reviewer reading the file top to bottom sees one
        rated capacity and the runtime uses another, both consistent with a
        valid signature. There is no document in which repeating a key is
        meaningful, and the field it silently changes is a Tier D input.

        The skill manifest loader and the commissioned-binding loader already
        refuse duplicates for this reason; this loader took their structural
        limits without their mapping constructor.
        """
        self.flatten_mapping(node)
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    "while constructing a configuration mapping",
                    node.start_mark,
                    f"configuration keys must be strings, got {type(key).__name__}",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a configuration mapping",
                    node.start_mark,
                    f"duplicate configuration key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        """Give every constructor failure a position instead of a bare traceback.

        A constructor is free to raise whatever its underlying conversion
        raises: an oversized integer literal reaches the interpreter's digit
        limit as ``ValueError``, and an out-of-range timestamp raises from
        ``datetime``. Neither is a ``YAMLError``, so neither carries a mark.
        Re-raising with the node's mark is what lets the refusal name the line
        rather than the exception type alone.
        """
        try:
            return super().construct_object(node, deep=deep)
        except (yaml.YAMLError, _ConfigDocumentLimitError):
            raise
        except Exception as exc:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"cannot construct value: {exc}",
                node.start_mark,
            ) from exc


_BoundedConfigSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _BoundedConfigSafeLoader.construct_config_mapping,
)


class _ExpandingConfigSafeLoader(_BoundedConfigSafeLoader):
    """The same loader, resolving `${VAR}` inside each scalar as it composes."""

    expand_env = True


def _load_config_document(text: str, path: str, *, expand_env: bool = False) -> Any:
    """Parse a configuration document, answering any parser failure with a refusal.

    The two known shapes are not special-cased. The loader's contract is that
    a bad document produces ``ConfigValidationError`` naming the file, so
    anything the parser raises is classified here rather than reaching the
    caller as an interpreter error.
    """
    loader = _ExpandingConfigSafeLoader if expand_env else _BoundedConfigSafeLoader
    try:
        return yaml.load(text, Loader=loader)
    except _ConfigDocumentLimitError as exc:
        raise ConfigValidationError(
            f"Config file {shown(path)} exceeds document limits: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigValidationError(
            f"YAML parse error in {shown(path)}: {exc}"
        ) from exc
    except Exception as exc:
        raise ConfigValidationError(
            f"Config file {shown(path)} could not be parsed: {type(exc).__name__}: {exc}"
        ) from exc


# A configuration document is admitted before it is parsed. The largest shipped
# example is 31 KB; this is roughly thirty times that, and matches the cap the
# skill manifest loader applies for the same reason.
_MAX_CONFIG_BYTES = 1024 * 1024
_CONFIG_READ_CHUNK = 65536


def read_config_bytes(path: str, *, max_bytes: int = _MAX_CONFIG_BYTES) -> bytes:
    """Admit and read a configuration document, bounding what that costs.

    Shared with `ori/config/installer.py`, which admits a *generated* document
    under a tighter cap of its own before installing it. Both need the same
    admission: the whole file used to be read with no size cap, the path was
    followed if it was a symlink, and a FIFO blocked in `read()` with no
    refusal and no timeout.

    `O_NONBLOCK` is what makes a FIFO refusable at all — without it the open
    itself blocks — and `fstat` on the descriptor, rather than a check on the
    path, is what makes the regular-file test hold for the file actually read.
    `O_NOFOLLOW` matches a decision the Linux installer already makes at write
    time, where a symlinked configuration path or parent is refused as an
    unsafe destination. It covers the final component only; a symlinked parent
    directory is still followed, as it is everywhere else on the platform.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ConfigValidationError(
                f"Config file {shown(path)} is a symbolic link, which is refused. "
                "Point the configuration path at the file itself."
            ) from exc
        raise ConfigValidationError(
            f"Cannot read config file {shown(path)}: {exc}"
        ) from exc

    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ConfigValidationError(
                f"Config file {shown(path)} is not a regular file. A FIFO, device or "
                "directory cannot be a configuration document."
            )
        # Read one byte past the cap rather than trusting the size `fstat`
        # reported: the file may grow between the two.
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            # Never more than one byte past the cap: enough to know the file
            # is oversized, and no more of it read than that.
            chunk = os.read(descriptor, min(_CONFIG_READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as exc:
        raise ConfigValidationError(
            f"Cannot read config file {shown(path)}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)

    if total > max_bytes:
        raise ConfigValidationError(
            f"Config file {shown(path)} is larger than the {max_bytes} byte "
            "limit for a configuration document."
        )
    return b"".join(chunks)


def _read_config_text(path: str) -> str:
    """Read a configuration document, bounding what it costs to obtain it.

    Admission is `read_config_bytes`; the encoding is fixed here rather than
    taken from the host locale, because a signed configuration must decode to
    the same document on every device that reads it.
    """
    raw = read_config_bytes(path)

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigValidationError(
            f"Config file {shown(path)} is not valid UTF-8: {exc}"
        ) from exc


def read_config_document(path: str) -> Any:
    """Admit, parse and classify a configuration document, without building it.

    `Config.load` is not the only reader of `ori.yaml`. The installer resolves
    a device id from it, the doctor re-reads it to report profile fields after
    a strict refusal, and identity resolution decides from it whether an
    existing installation would be stranded. Each parsed independently and
    caught only `yaml.YAMLError`, so a hostile literal escaped all three as a
    raw interpreter error — one of them from inside a function whose docstring
    says it must not raise.

    They share this rather than each growing a guard, so a bound added here
    applies to every reader of the file. Callers translate the refusal into
    their own vocabulary; what they must not do is let an interpreter error
    through.
    """
    return _load_config_document(_read_config_text(path), path)


def config_env_placeholders(config_path: str) -> frozenset[str] | None:
    """Every environment variable this document's values name, before expansion.

    Answers what the document asks the environment for, which is what decides
    whether a file supplying variables supplied anything to *this* document.
    Collected from values only, because expansion never reaches a key.

    Returns ``None`` when the document cannot be read, which is unknown rather
    than none: a caller deciding whether an unsigned source contributed must
    not read silence as proof that it did not.
    """
    try:
        raw = _load_config_document(_read_config_text(config_path), config_path)
    except Exception:
        return None

    names: set[str] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            names.update(_ENV_VAR_RE.findall(node))
        elif isinstance(node, dict):
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for value in node:
                _walk(value)

    _walk(raw)
    return frozenset(names)
