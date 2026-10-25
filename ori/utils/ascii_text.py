# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""ASCII-only text handling for inbound authentication and approval input."""

#: The ASCII characters `str.strip()` treats as whitespace, and only those. A
#: Unicode strip would make a reply carrying, say, a leading no-break space
#: read as one without it.
ASCII_WHITESPACE = " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f"
