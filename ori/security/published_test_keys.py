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
    "/FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU=",
    "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=",
    "11l5O7wTooGagnx2rbb7qKSa7gB/SfLQmS2ZuCWtLEg=",
    "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
    "3eO8zsfzpmoRFfRdcg9NwTXDrnxOItyjj9se/WpJX/g=",
    "5KoEo9B6i5O77+8jr/x0+USx57OuOd9T6lZ08nbGmTU=",
    "5zTqbCtiV95yNV5HKqBaTEh+a0Y8Ap7TBt8vAbVja1g=",
    "6Qt+B4qE7/bRc0GIW4KRnJ82NyJdebPOHjQTJfkNrbw=",
    "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
    "DDR976kScrPVYbNkFU4sE5i4TvamP/fY0V0OwaxLRgg=",
    "E9mQinCSWZLtVGAH0n9Q2mi6chfvYqw8ynhFKf8QRxw=",
    "F0VTtFbd38aQjsqxwQH+arIeK6oGF3lbfUOmNIKZP9U=",
    "F8t5+ytBIPKx7GXkGY1uCLKOgT/rAeSkAIObheGAgM4=",
    "IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=",
    "Ivwpd5Lwtv/Av8/bftsMCqFOAlo2XsDjQuhuOCnLdLY=",
    "JUO5L/EJVRFHatyDadtt3JM2ZaEZeN2hQE7hBmypVZ0=",
    "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=",
    "MFu6n+w+PkgGfsBJkVN6bO3uQv7s84xuOBmqWWyqw/g=",
    "My6+jSfLcyOzpAHBwTtd1kvMwOEOzaHCtdEaA3eaheU=",
    "NLTZBDFWy23PC+sKKUm3VZyUDSvLbb6MU6mzAnjjp0Y=",
    "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
    "P3cI1fXMK8YztZ0rOi7ZLnR5IgxvCK3iCL682FgKuTs=",
    "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=",
    "R4nQzebuj1pjnCpAWhYvnecSZIH4InZKrOsLYoNNsUk=",
    "Swz7WkiOjIwH7tr74ZfNkBgCFWhd/r7LQrrmchCu8VA=",
    "T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy+ZcQ=",
    "aEYOvvOxOBZOx/2GEOlYAN91mPcPLy6n21FyrHTrwUQ=",
    "bw8O6z+/+SXGbQPhnc5I1e3J/+5RzSaucd055W9/3aI=",
    "dPyio7OJ+xpk2b9SzA3UwpZPOATAz3x1XoUTxtuBmNw=",
    "dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU=",
    "fVnFYj3UCnSqTVoyrGRdOz+V2urkwiviVHbdakhvc4I=",
    "gUci3nHFsU50jf8yKuf3xBXO5Vh2ZJUpLNbEwKap3yg=",
    "i3R4U/RXjJd3QG1Tm9eZOVpvEY4KWTizN8iJJuC6yTE=",
    "i7BOHBuD3d8xH1vN33xQ7ePAgC9H7HluKhMc9BKY2fM=",
    "ivC0z71ruLNOSRqZ47jQ1QJrDBavwYc+Wb3DEk8RAwk=",
    "ncD5PLGaHZB2WOaVbZgsExrIPb2aqvMTpJLLoaM2Swo=",
    "nrnipCyE+VlyHkHP7iIj+EptRSYfYFxNRfoPjmlW1AE=",
    "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=",
    "skkdlQKuKGMKK6yy4MdFEP/N0yjDNP8+E5PnWy0x59w=",
    "wGlTlhWM04I+ailc3+2iOiKSKWq8c6XlRBNVvxzYi5Q=",
    "xoImN8fTEOxXYnvgC6JZ0lN0n0qvZERwz/vlOjX3MkI=",
    "yFOtDwzSthmuqSzuxP1Wok1kmdWEznklfkXP2BObYKc=",
    "ylfu0w5KcnTvTGSPVvWPiAsg0solcl2eXBPIPAjAmus=",
    "zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o=",
)

# Each key under both signs of x: its seed's holder signs under the negation
# too, with -a, so a check that knows the key by its bytes must know both.
PUBLISHED_TEST_KEYS: Final[frozenset[bytes]] = frozenset(
    variant
    for key in PUBLISHED_TEST_KEYS_B64
    for raw in (base64.b64decode(key),)
    for variant in (raw, raw[:31] + bytes([raw[31] ^ 0x80]))
)


def is_published_seed(seed: bytes) -> bool:
    """Whether a private seed derives a key this repository publishes.

    The refused set holds public keys, because the boundaries it was written for
    receive public material. A boundary receiving the private half derives the
    key and asks here, so there is one list rather than two that could drift.

    Deliberately no exception handling: a seed whose key cannot be derived is
    not a seed that may be used, and swallowing that would let a signing key
    through on the one path where the check could not be made. Callers wrap this
    in their own refusal so the failure keeps their vocabulary.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return public in PUBLISHED_TEST_KEYS
