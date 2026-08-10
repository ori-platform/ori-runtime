# Runtime Release Bundle Signing

This document describes the implementation boundary for
[`runtime-release-bundle/v1`](https://github.com/ori-platform/ori-specs/blob/main/runtime-release-bundle/v1.md).
The contract remains a design target until the installer and release pipeline
are complete.

## Build without signing authority

A trusted native Linux builder produces the hash-locked wheelhouse and exact
unsigned bundle without access to any private release key:

```bash
ORI_WHEELHOUSE_TARGET=generic \
ORI_RELEASE_BUNDLE_VERSION=2.3.0 \
SOURCE_DATE_EPOCH=1700000000 \
bash scripts/build-wheelhouse.sh
```

The output under `dist/releases/` contains the deterministic `.tar.gz` bundle
and its convenience `.sha256` file. The checksum detects transport corruption;
it does not authenticate the release.

The builder accepts only the v1 Linux/Python targets defined by the contract.
It excludes the legacy wheelhouse `MANIFEST.sha256` because that file contains
builder-specific paths; `BUNDLE-MANIFEST.json` is the exact portable manifest.

## Sign in the approved signing environment

`scripts/sign-release-bundle.py` is a local adapter for an isolated signing
environment. It is intentionally disabled when `GITHUB_ACTIONS=true`. It does
not read private keys from environment variables, repository configuration, or
`ori.yaml`.

```bash
python scripts/sign-release-bundle.py \
  --artifact dist/releases/ori-runtime-2.3.0-linux-x86_64-python3.12.tar.gz \
  --runtime-version 2.3.0 \
  --target linux-x86_64-python3.12 \
  --key-id ori-runtime-release-2026-01 \
  --key-registry /trusted/release-keys.json \
  --private-key-file /signer/ori-runtime-release-2026-01.pem \
  --output dist/releases/ori-runtime-2.3.0-linux-x86_64-python3.12.signature.json
```

The private-key file must be a non-symlink regular file with no group or other
permissions. Its Ed25519 public key must exactly match an `active`,
`runtime_release_bundle` entry in the pinned registry. A `verify_only` or
`revoked` key cannot sign a new release.

This local adapter is not authorization to copy production private keys onto a
general-purpose CI runner. The protected release workflow must call the
approved external signing system and receive only the detached signature or
signed envelope. That system's identity, authentication, and API remain an
explicit prerequisite for release-workflow implementation.

## Trust-anchor ceremony

Before the first usable installer release:

1. generate the dedicated Ed25519 key inside the approved signing system;
2. export only its raw 32-byte public key;
3. assign a stable key ID and add it as `active` to the reviewed pinned
   `ori.runtime_release_keys.v1` registry;
4. embed or ship that registry with the reviewed installer bootstrap;
5. publish the public key fingerprint through an independent operator channel;
6. verify a candidate bundle through the same code path the installer uses;
7. retain recovery and revocation procedures without exporting the private key.

The repository intentionally contains no production release private key and no
placeholder public key that could be mistaken for production authority.
