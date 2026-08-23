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

## Wheelhouse Naming

Source files live under `requirements/`, but device wheelhouses still emit
root-level install files named `requirements.txt`, `requirements-phone.txt`,
and `requirements-pi.txt`. Keep that deployment contract stable because
`scripts/install-phone.sh`, `scripts/install-pi.sh`, and existing offline
operator runbooks depend on it.
