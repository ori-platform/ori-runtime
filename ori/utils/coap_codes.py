# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reading a CoAP response code, shared by the sensor adapter and the executor."""

from __future__ import annotations

# The response class that is a success (2.xx); every other class is not.
COAP_SUCCESS_CLASS = 2


def response_code_error(code: object) -> str | None:
    """Why a response code is not a success, or None for a 2.xx.

    A code is one byte: its class in the top three bits and its detail in the
    low five (RFC 7252 section 3), which aiocoap's `Code` carries as an int. A
    code that cannot be read is not taken as a success.
    """
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFF:
        return f"a response code that cannot be read ({code!r})"
    if code >> 5 == COAP_SUCCESS_CLASS:
        return None
    dotted = f"{code >> 5}.{code & 0x1F:02d}"
    name = getattr(code, "name", None)
    return f"response code {dotted} {name}" if name else f"response code {dotted}"
