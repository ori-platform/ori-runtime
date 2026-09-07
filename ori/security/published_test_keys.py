# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Public keys whose private seeds are published test material in this repository.

A trust anchor is an authority only while its private half is secret. Every seed under
`tests/`, in vectors, fixtures and source literals alike, is committed, so a signature from one of these keys proves
nothing about who produced the document. They exist to drive verifiers against
known material, and configuring one on a device makes that device accept forged
documents from anyone holding a clone.

`tests/test_published_test_keys.py` re-derives this set from tracked files, so
a newly committed seed cannot quietly escape it.

The set is **append-only**. A seed rotated out of the working tree stays in
history, so the key it derives stays forgeable and must stay refused. Nothing
here is ever removed, and no test asserts the set contains only what the
current tree publishes -- such a test would force exactly that removal. Over-
refusal costs nothing: these are 32-byte values, and a genuine key collides
with one at 2**-256.
"""

from __future__ import annotations

import base64
from typing import Final

PUBLISHED_TEST_KEYS_B64: Final[tuple[str, ...]] = (
    "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=",
    "11l5O7wTooGagnx2rbb7qKSa7gB/SfLQmS2ZuCWtLEg=",
    "5zTqbCtiV95yNV5HKqBaTEh+a0Y8Ap7TBt8vAbVja1g=",
    "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
    "E9mQinCSWZLtVGAH0n9Q2mi6chfvYqw8ynhFKf8QRxw=",
    "F0VTtFbd38aQjsqxwQH+arIeK6oGF3lbfUOmNIKZP9U=",
    "F8t5+ytBIPKx7GXkGY1uCLKOgT/rAeSkAIObheGAgM4=",
    "IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=",
    "Ivwpd5Lwtv/Av8/bftsMCqFOAlo2XsDjQuhuOCnLdLY=",
    "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=",
    "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=",
    "My6+jSfLcyOzpAHBwTtd1kvMwOEOzaHCtdEaA3eaheU=",
    "NLTZBDFWy23PC+sKKUm3VZyUDSvLbb6MU6mzAnjjp0Y=",
    "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
    "T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy+ZcQ=",
    "aEYOvvOxOBZOx/2GEOlYAN91mPcPLy6n21FyrHTrwUQ=",
    "dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU=",
    "fVnFYj3UCnSqTVoyrGRdOz+V2urkwiviVHbdakhvc4I=",
    "gUci3nHFsU50jf8yKuf3xBXO5Vh2ZJUpLNbEwKap3yg=",
    "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=",
    "skkdlQKuKGMKK6yy4MdFEP/N0yjDNP8+E5PnWy0x59w=",
    "xoImN8fTEOxXYnvgC6JZ0lN0n0qvZERwz/vlOjX3MkI=",
    "yFOtDwzSthmuqSzuxP1Wok1kmdWEznklfkXP2BObYKc=",
    "ylfu0w5KcnTvTGSPVvWPiAsg0solcl2eXBPIPAjAmus=",
    "zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o=",
)

PUBLISHED_TEST_KEYS: Final[frozenset[bytes]] = frozenset(
    base64.b64decode(key) for key in PUBLISHED_TEST_KEYS_B64
)
