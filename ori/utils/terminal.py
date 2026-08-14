# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Portable terminal styling for operator-facing commands.

Colour is decoration, never meaning: every status is also carried by a text
label, so output stays correct on a monochrome terminal, for a colour-blind
operator, and in a support ticket someone pasted from a log.

Styling is suppressed whenever the destination is not an interactive terminal,
so piping into a file, ``grep``, or a log collector never embeds escape codes.
"""

from __future__ import annotations

import os
import sys
from typing import IO, Final

# Bright variants (90-97) are universally supported by current terminals and
# stay legible on both dark and light backgrounds. Plain white is deliberately
# absent: bright white is close to invisible on a light background, so headings
# use bold on the terminal's own foreground colour instead.
RESET: Final = "\033[0m"
BOLD: Final = "\033[1m"
DIM: Final = "\033[2m"
GREEN: Final = "\033[92m"
YELLOW: Final = "\033[93m"
RED: Final = "\033[91m"
CYAN: Final = "\033[96m"

PASS: Final = "PASS"
WARN: Final = "WARN"
FAIL: Final = "FAIL"

_STATUS_COLOURS: Final = {PASS: GREEN, WARN: YELLOW, FAIL: RED}


def colour_enabled(stream: IO[str] | None = None) -> bool:
    """Return whether ``stream`` should receive ANSI styling.

    ``NO_COLOR`` is honoured regardless of value, per the convention, and
    ``TERM=dumb`` identifies terminals that cannot render escapes.
    """
    target = sys.stdout if stream is None else stream
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    try:
        return bool(target.isatty())
    except (AttributeError, ValueError):
        return False


def style(text: str, *codes: str, stream: IO[str] | None = None) -> str:
    """Wrap ``text`` in ``codes`` when the destination supports styling."""
    if not codes or not colour_enabled(stream):
        return text
    return "".join(codes) + text + RESET


def status_label(status: str, *, stream: IO[str] | None = None) -> str:
    """Render a fixed-width status label that reads without colour."""
    normalised = status.upper()
    colour = _STATUS_COLOURS.get(normalised)
    if colour is None:
        raise ValueError(f"unknown status: {status!r}")
    return style(normalised, colour, BOLD, stream=stream)


def heading(text: str, *, stream: IO[str] | None = None) -> str:
    return style(text, CYAN, BOLD, stream=stream)


def path(text: str, *, stream: IO[str] | None = None) -> str:
    return style(text, CYAN, stream=stream)


def warning(text: str, *, stream: IO[str] | None = None) -> str:
    return style(text, YELLOW, stream=stream)


def failure(text: str, *, stream: IO[str] | None = None) -> str:
    return style(text, RED, BOLD, stream=stream)


def success(text: str, *, stream: IO[str] | None = None) -> str:
    return style(text, GREEN, stream=stream)


def muted(text: str, *, stream: IO[str] | None = None) -> str:
    """Advisory only: some terminals render dim identically to normal."""
    return style(text, DIM, stream=stream)
