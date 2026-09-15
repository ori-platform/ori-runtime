# Telemetry delivery vectors

`delivery_cases.json` is authored here, not vendored from another repository,
and carries no `MANIFEST.json` for that reason. Everything else under
`tests/vectors/` is a copy of an upstream artefact pinned by digest; this one is
the runtime's own.

It exists because `runtime-telemetry/v2` makes the ingest response the only
thing that says whether a reading was stored, and two programs in this
repository have to read it the same way:

- the Python exporter, `ori/telemetry/http_export.py`, via
  `ori/telemetry/delivery.py`
- the Android payload, `mobile/ori-runtime-mobile`

Both evaluate every case. A rule can therefore only be implemented one way in
each, and a disagreement fails a test somewhere rather than being discovered on
a phone.

`runtime-telemetry/v2` ships no corpus of its own and says so. This is not that
corpus: it covers one producer decision — how an answer is read — and not the
receiver's side of it. A receiver's agreement would make the set three-way, and
that coordination is tracked with the product.
