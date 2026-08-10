# Ori Runtime — Unreleased

Changes merged to `main` after `v2.2.0` are collected here until the next
release is cut.

- Added the contract-bound foundation for signed Linux release bundles:
  deterministic offline bundle construction, a purpose-bound Ed25519 key
  registry and signing boundary, fail-closed verification, bounded safe
  extraction, and exact post-extraction manifests. The operator installer and
  protected external-signing release workflow remain in progress under #273.
