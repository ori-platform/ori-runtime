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

## Release publication preconditions

The release workflow refuses to run until these exist. They are checked in a
preflight job rather than assumed, because GitHub creates a referenced
environment *without* protection rules the first time a workflow names it — so
`environment: release-signing` on its own gates nothing.

| Precondition | Why |
| --- | --- |
| Repository immutable releases enabled | `gh release create --verify-tag` verifies a tag exists; it does not freeze assets. Immutability is a separate repository setting. **Operator-verified:** its endpoint requires administration scope and returns 403 to `GITHUB_TOKEN`, which cannot be granted that scope. The workflow instead proves the published release object reports `immutable: true`, and refuses to promote otherwise. |
| `release-signing` environment exists | Named environments are auto-created unprotected on first use. |
| Required reviewer with self-review prevented | Otherwise signing is unattended, or one maintainer can approve their own release. Both are asserted from the environment's `required_reviewers` rule. |
| No administrator bypass | Not exposed as an assertable field; this remains an operator obligation. |
| Custom deployment policy naming a version-tag pattern | Otherwise any ref reaching the job could assume the signer role. Presence of a policy is not enough: the entries must all be tag-typed and cover `v*`. |
| Active tag ruleset covering `refs/tags/v*` that restricts deletion and update, with no ref exclusions | Otherwise a published release tag can be moved after signing. A ruleset protecting unrelated tags does not count, blocking deletion alone still allows a force-move, and an exclusion could carve the real release tags back out of a broad include. |
| AWS OIDC trust policy bound to the environment subject | Restricting on repository alone lets any workflow in the repository assume the signer role. Bind `sub` to `repo:<owner>/<repo>:environment:release-signing`. |

Immutable releases must be confirmed by an operator before a release run,
because no token available to the workflow can read that setting:

```sh
gh api repos/ori-platform/ori-runtime/immutable-releases
# {"enabled":true,"enforced_by_owner":false}
```

Record that output with the date as release-readiness evidence; it contains no
secret. The same script performs this check when run locally with operator
credentials and `--with-admin-reads`, which the workflow never passes.

`scripts/check_release_protections.py` proves each of these before any
credential is issued, and reports every gap in one run with the remedy.

Publication is draft-first: the workflow reconfirms the tag still points at the
built commit, creates a draft, uploads the complete asset set, confirms the
draft carries exactly the staged files, and only then marks it public. A
failure therefore leaves an unpublished draft rather than a partially published
release.

## What constitutes release approval

The workflow proves that the signed tag and the workflow event agree on one
commit. It cannot, on its own, prove that commit was the one a human approved —
nothing in the repository binds a commit to an out-of-band approval record.

The `release-signing` environment deployment is therefore defined as the
authoritative approval event:

- the protected deployment names the exact tag and full commit SHA being
  released, and the reviewer sees both before approving;
- approving that deployment **is** the release approval, and its timestamp is
  the approval timestamp;
- the signed-tag check binds the approved deployment's commit to a verified
  annotated tag, so approval, tag, and built bytes cannot diverge;
- any earlier approval recorded in text or YAML is superseded the moment the
  final release commit changes — a release-preparation merge always produces a
  new commit, so a pre-merge approval SHA is never the release SHA.

This is why the reviewer must be a person who did not push the tag, and why
self-review is refused: the deployment approval is the only point at which a
human asserts "these exact bytes, from this exact commit, may be signed."

## When public reverification fails

A published immutable release is never deleted. Deleting it would destroy the
distribution object, complicate forensics, and burn the tag name permanently.
The workflow quarantines instead:

- a release that publishes without immutability is **deleted immediately**,
  because it would otherwise expose rewritable bytes at the exact URL the
  bootstrap trusts; the signed tag is retained and the remedy is a new patch
  version, never a reused tag. A failed deletion is reported as the loudest
  line of the incident, because a mutable release may still be public;
- a release that published immutably is never deleted — see below;
- the run stays failed, so the release is never declared usable;
- the release is never marked `Latest`: publication explicitly sets
  `--latest=false`, and only a clean public reverification promotes it, so a
  failure leaves it published but unpromoted;
- a high-priority release incident is opened automatically;
- no `latest` or bootstrap promotion may reference the version;
- the release and workflow logs are preserved as evidence;
- if the artifacts are invalid, a corrected patch version is published — the
  tag is never reused.

This keeps "publicly uploaded" and "declared usable" as separate states, which
is the distinction the v1 contract draws.

## Outstanding operational gates

### Evidenced on 2026-08-12

The following were confirmed against the AWS account and this repository. The
evidence is non-secret ARNs, policy documents, and ownership assignments, held
outside this repository.

- **Least-privilege signing principals.** Two named roles replace
  administrator-derived access, both scoped to the exact key ARN.
  `ori-runtime-release-signer` is assumable only by a named IAM user with MFA
  for manual ceremonies and may call `kms:DescribeKey`, `kms:GetPublicKey`, and
  `kms:Sign`. `ori-runtime-github-release-signer` is assumable only through
  GitHub OIDC and may call `kms:GetPublicKey` and `kms:Sign`. Signing is
  additionally conditioned on `kms:SigningAlgorithm = ED25519_SHA_512` and
  `kms:MessageType = RAW`; those request-context keys apply to `kms:Sign` and
  not to the inspection calls. Neither role holds `kms:CreateGrant`,
  `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `iam:*`, or `s3:*`.
- **Key-policy enforcement.** Key policy `ori-runtime-release-key-policy-v2`
  explicitly denies `kms:Sign` to every principal outside those two roles, so
  the allowlist is enforced at the key rather than only at the roles.
- **Short-lived federation restricted to protected releases.** The OIDC trust
  is bound to audience `sts.amazonaws.com` and subject
  `repo:ori-platform/ori-runtime:environment:release-signing`, so only the
  protected environment can assume the signing role. Ordinary CI runs with
  `id-token: none`.
- **Proof of possession.** A domain-separated challenge was signed through the
  approved role and verified; a one-byte mutation was rejected.
- **Ownership.** Emergency-disable owner and backup administrator are assigned,
  and the release approver is separate from the signing operator.

### Administrator-attested and code-owner accepted on 2026-08-13

Detailed evidence is retained outside the public repository because it contains
sensitive operational material.

- durable CloudTrail logging of KMS events beyond Event History's limited
  window, with its retention arrangement;
- absence of long-lived AWS credentials in GitHub repository and organisation
  secrets.

### Evidenced by the v2.3.0 release run on 2026-08-13

- protected GitHub OIDC signing succeeded through the `release-signing`
  environment, gated on a required reviewer approving the deployment;
- the workflow built four targets, signed them through the pinned KMS key,
  published the complete asset set, and reverified it from the public origin;
- the published release reported immutability and was promoted to `Latest`;
- the assets were independently reverified afterwards from a separate machine.

### Remaining release-time evidence

- installation evidence on both production tuples against the published
  v2.3.1 release: Raspberry Pi OS Bookworm `aarch64` with stock Python 3.11,
  and Ubuntu 24.04 `x86_64` with stock Python 3.12. Each must cover install,
  service start, reboot persistence, upgrade, rollback, refusal of a tampered
  or unsigned artifact, and absence of live package resolution.

The public key and fingerprint are normatively pinned in
`ori-specs/runtime-release-bundle/v1` by the merged contract amendment in
`ori-specs#63`.

The controls that gate signing are in place, so the protected release path is
enabled. It remains self-limiting: the workflow refuses to run without the
repository protections, refuses to sign without a reviewer approving the
protected deployment, and refuses to promote a release it cannot reverify.

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
