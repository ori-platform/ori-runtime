# Runtime Release Signing Authority

This document records the public, non-secret identity and current operational
posture of the authority used to sign Ori Runtime Linux release bundles. It
does not contain private key material, AWS credentials, recovery data, or CI
secrets.

## Active verification key

| Field | Value |
| --- | --- |
| Ori key ID | `ori-runtime-release-2026-01` |
| AWS region | `eu-west-1` |
| KMS alias | `alias/ori-runtime-release-2026-01` |
| KMS key spec | `ECC_NIST_EDWARDS25519` |
| KMS usage | `SIGN_VERIFY` |
| Ori signing algorithm | `ED25519_SHA_512` |
| Ori message type | `RAW` |
| Public key, standard padded Base64 | `aDlW3MqinQM8y96szEqNske2ytKkxbmMDl87CuLbAQ8=` |
| Raw public-key SHA-256 | `d4f44308d60fb78a33f709eebc85271f2b8c0d4e59e50bb77bf08f5864918c90` |
| Confirmation date | `2026-08-11` |

The key was generated non-exportably inside AWS KMS. During the key ceremony,
the public key was retrieved from and confirmed against the exact KMS key ID;
the Base64 value and SHA-256 fingerprint above matched that result. The Runtime
repository packages only this public verification material in
`ori/installer/release-keys.json`. The private key is not exportable and is not
present in this repository or ordinary CI secrets.

`status: active` in the packaged registry means release bundles signed by this
key are accepted for verification. It does not by itself claim that release
publication is operationally production-ready.

## Outstanding operational gates

The following remain required before declaring production release publication
ready:

- replace broad administrator-derived signing access with an explicitly named,
  least-privilege release signer principal;
- configure durable CloudTrail logging for KMS events beyond Event History's
  limited retention;
- formally assign the emergency-disable owner and backup administrator;
- independently verify that GitHub and CI hold no long-lived AWS credentials;
- restrict automated signing to protected immutable releases using short-lived
  identity federation.

The public key and fingerprint are normatively pinned in
`ori-specs/runtime-release-bundle/v1` by the merged contract amendment in
`ori-specs#63`.

Until those gates are evidenced, the local installer verification path may be
tested against signed artifacts, but protected production release publication
must remain disabled.
