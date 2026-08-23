# Ori Runtime Dependency Locks

This directory keeps the repo-level Python dependency inputs and hash-locked
outputs out of the project root.

## Files

| File | Purpose | Edit by hand? |
| --- | --- | --- |
| `runtime.in` | Human-readable runtime constraints | Yes |
| `runtime.txt` | Hash-locked runtime dependencies | No |
| `dev.in` | Human-readable development and CI constraints | Yes |
| `dev.txt` | Hash-locked development and CI dependencies | No |
| `phone.in` | Phone Starter source/build constraints | Yes |
| `phone.txt` | Hash-locked Phone Starter source/build dependencies | No |
| `phone-growatt.in` | Additive Growatt phone profile constraints | Yes |
| `phone-growatt.txt` | Hash-locked Growatt phone profile dependencies | No |
| `phone-victron.in` | Additive Victron phone profile constraints | Yes |
| `phone-victron.txt` | Hash-locked Victron phone profile dependencies | No |
| `pi.in` | Raspberry Pi hardware constraints | Yes |
| `pi.txt` | Hash-locked Raspberry Pi hardware dependencies | No |

## Updating Locks

Use `pip-tools` and keep generated files hash-locked:

```bash
pip-compile requirements/runtime.in --generate-hashes --annotate -o requirements/runtime.txt
pip-compile requirements/dev.in --generate-hashes --annotate --constraint requirements/runtime.txt -o requirements/dev.txt
pip-compile requirements/phone.in --allow-unsafe --generate-hashes -o requirements/phone.txt
pip-compile requirements/phone-growatt.in --allow-unsafe --generate-hashes -o requirements/phone-growatt.txt
pip-compile requirements/phone-victron.in --allow-unsafe --generate-hashes -o requirements/phone-victron.txt
pip-compile requirements/pi.in --allow-unsafe --generate-hashes -o requirements/pi.txt
```

Do not edit `.txt` files manually. If a generated lock changes, the matching
`.in` file or Dependabot PR should explain why.

## One Lock Per Profile, Not Per Interpreter

`runtime.txt` is a single hash-lock compiled under one interpreter and used for
every published target, including the two Python 3.13 targets added for
Raspberry Pi OS Trixie. It carries no environment markers, so the resolution
does not branch on interpreter version.

That is a decision, not an accident, and it holds only while the pinned set
resolves binary-only on every target. It was measured rather than assumed
before 3.13 was added: `pip download --require-hashes --only-binary=:all:` on
`aarch64` under CPython 3.13 resolves the whole of `runtime.txt` from wheels,
with `cp313` builds where a package is version-specific and `abi3` wheels for
`cryptography` and `psutil`. Nothing fell back to a source distribution.

Per-version locks would be the alternative, and they are worse while this
holds: they multiply the files Dependabot maintains, they let two targets drift
onto different resolved versions of the same dependency, and they make the
bundle manifest describe a different dependency set per target. Keep one lock.

**When to revisit.** If a future interpreter or dependency makes the
binary-only resolution fail, do not paper over it by allowing source builds —
a device installs from the wheelhouse with `--no-index --require-hashes` and
cannot compile anything. Re-run the check above, and if it cannot pass, split
the lock per interpreter version and update `scripts/build-wheelhouse.sh`, the
release matrix, and the bundle manifest together.

## Wheelhouse Naming

Source files live under `requirements/`, but device wheelhouses still emit
root-level install files named `requirements.txt`, `requirements-phone.txt`,
and `requirements-pi.txt`. Keep that deployment contract stable because
`scripts/install-phone.sh`, `scripts/install-pi.sh`, and existing offline
operator runbooks depend on it.
