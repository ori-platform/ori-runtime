# Commissioned safety binding — vector tools

Authoring and checking tools for the corpus defined by
`ori-specs/commissioned-safety-binding/v1.md`. The contract repository holds the
authority. `tests/vectors/commissioned_safety_binding/` is a vendored copy whose
`MANIFEST.json` records the ori-specs commit it came from and the digest of the
file; `scripts/refresh-evidence-vectors.sh` compares both against ori-specs in
CI, which is what detects upstream drift. Nothing here re-derives that.

`generate_commissioned_binding_vectors.py` reproduces the corpus byte-for-byte,
so a proposed change can be regenerated and reviewed rather than hand-edited.
There is no default write path: a consumer repository must not be able to
regenerate its own expectations casually, since the point of a vendored corpus
is that it came from the contract rather than from us.

    python tests/golden/generate_commissioned_binding_vectors.py --check CORPUS
    python tests/golden/generate_commissioned_binding_vectors.py --output PATH

`verify_commissioned_binding_vectors.py` drives the runtime's verifier, written
from the contract text, which shares no code with the generator. It implements the closed grammar, the
key-selection and authority split either side of signature verification, the
proof rules, and the bounds, disambiguation and posture checks, and it asserts
that each reject case is refused at exactly its declared stage having passed
every earlier one — a case that refuses for the right reason at the wrong stage
is not evidence that the named check exists. The suite drives it through
`tests/test_commissioned_binding_vectors.py`; it also runs standalone.

    python tests/golden/verify_commissioned_binding_vectors.py CORPUS

It is a thin driver now: the verifier it exercises is the runtime's own,
`ori/security/commissioning/binding.py`, which is the first consumer of the
contract. The generator still shares no code with it.

Both tools are Python, so this is reproduction without language independence.
It demonstrates internal consistency and catches design errors; it does not
show the canonical-byte rules are unambiguous across Python, Go and C, which is
the actual interoperability boundary. The contract does not ratify until a
non-Python implementation reproduces these bytes.
