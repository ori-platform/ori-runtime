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

## Authenticated Linux bootstrap

[`scripts/install-linux.sh`](../scripts/install-linux.sh) is the standalone
bootstrap that will be attached to an immutable Runtime release. It requires an
explicit version until protected release publication can safely generate the
`latest` convenience flow:

```sh
curl -fsSL \
  https://github.com/ori-platform/ori-runtime/releases/download/v2.3.0/install-linux.sh \
  | bash -s -- --version 2.3.0 -- --scope user
```

For unattended provisioning, pass `--unattended` and every required identity
field after the separator. Interactive piped installs reopen `/dev/tty`; if no
terminal exists, the bootstrap fails instead of selecting defaults.

The host must provide Python 3.11 or 3.12, Bash, and OpenSSL 3 or newer with
Ed25519 `pkeyutl` support. Missing or older OpenSSL fails explicitly as
`crypto_unavailable`; it is never reported as a bad release signature.

The bootstrap downloads only from the approved GitHub HTTPS release origin
and permits redirects only to GitHub-controlled HTTPS asset hosts. It checks
the requested version and detected Linux/Python target, verifies the exact
bundle size and digest, and verifies the KMS-backed Ed25519 signature against
the public key pinned in this repository and the normative contract. Only then
does it safely extract the bundle, independently verify the manifest and full
file set, and create a temporary installer environment exclusively from the
verified, hash-locked wheelhouse. The installed `ori-install-linux` command
re-verifies the bundle before performing the transactional installation.

The initial `curl | bash` still trusts HTTPS and GitHub release delivery for
the bootstrap script itself; the embedded key cannot authenticate the file
that contains it. The high-assurance path is to download the immutable-tag
script, verify `install-linux.sh.sha256` against an independently obtained
release record, inspect it, and then run it locally. Release publication must
ship both files atomically; that protected publication control is not enabled
by this implementation.
