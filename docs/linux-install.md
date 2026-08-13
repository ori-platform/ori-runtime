# Installing Ori Runtime on Linux

This guide covers installing a **signed Ori Runtime release** onto a Linux
device as a managed systemd service. Every byte is verified against a release
key whose private half never leaves AWS KMS, and nothing is unpacked or
executed until that verification succeeds.

If you want to run Ori from a source checkout for development, see
[`linux-setup.md`](linux-setup.md) instead. That is a different path with
different guarantees.

---

## Requirements

| Requirement | Why |
| --- | --- |
| Linux on `x86_64` or `aarch64` | The only published targets |
| Python 3.11 or 3.12 | Bundles are built per interpreter version |
| Bash | The bootstrap is a Bash/Python polyglot and refuses other shells |
| OpenSSL 3 or newer | Ed25519 verification needs `pkeyutl -rawin` |
| systemd | The runtime is installed as a managed service |

**Production support is expressed as tested platform tuples**, not one global
interpreter version:

| Platform | Architecture | Python | Status |
| --- | --- | --- | --- |
| Raspberry Pi OS Bookworm | `aarch64` | 3.11 (stock) | Production-supported |
| Ubuntu 24.04 | `x86_64` | 3.12 (stock) | Production-supported |
| Other published bundles | `x86_64`, `aarch64` | 3.11, 3.12 | Community compatibility |

Both production tuples use the interpreter their distribution ships, so no
manual Python installation is required.

**Raspberry Pi OS Bullseye is not supported.** It ships OpenSSL 1.1.1, which
cannot perform the required verification — the installer reports
`crypto_unavailable` rather than pretending otherwise.

**Fedora is deferred.** Current releases ship Python 3.13, for which no bundle
is published, so the bootstrap reports `unsupported_target`.

---

## Install

### Interactive

```sh
curl -fsSL \
  https://github.com/ori-platform/ori-runtime/releases/download/v2.3.1/install-linux.sh \
  | bash -s -- --version 2.3.1 -- --scope user
```

You will be prompted for a device ID, name, location, and an optional operator
contact. Piped installs reopen `/dev/tty` for those prompts; if no terminal is
available the install fails rather than silently choosing defaults.

Use `bash`, not `sh`. Under `dash` — which is `/bin/sh` on Debian and Ubuntu —
the script exits with a message telling you to re-run it with Bash.

### Unattended

Every identity value must be supplied; unattended mode never prompts.

```sh
curl -fsSL \
  https://github.com/ori-platform/ori-runtime/releases/download/v2.3.1/install-linux.sh \
  | bash -s -- --version 2.3.1 -- \
      --scope system \
      --unattended \
      --device-id energy-monitor-ikeja-01 \
      --name "Ikeja Office Energy Monitor" \
      --location "Lagos, Nigeria" \
      --deployment-type pi
```

### High-assurance install

`curl | bash` trusts HTTPS and GitHub release delivery for the bootstrap script
itself — the key embedded in the script cannot authenticate the file containing
it. To remove that residual trust, fetch the script and its checksum from the
immutable tag, verify, inspect, then run it locally:

```sh
base=https://github.com/ori-platform/ori-runtime/releases/download/v2.3.1
curl -fsSLO "${base}/install-linux.sh"
curl -fsSLO "${base}/install-linux.sh.sha256"
sha256sum -c install-linux.sh.sha256
less install-linux.sh
bash install-linux.sh --version 2.3.1 -- --scope system --unattended ...
```

Everything after the bootstrap is already covered by the KMS signature.

---

## Scope: user or system

| | `--scope user` | `--scope system` |
| --- | --- | --- |
| Runs as | Your login account | An unprivileged service account |
| Install root | `~/.local/ori` | `/opt/ori` |
| Unit file | `~/.config/systemd/user/ori-runtime.service` | `/etc/systemd/system/ori-runtime.service` |
| Environment file | `~/.config/ori/runtime.env` | `/etc/ori/runtime.env` |
| Requires root | No — and refuses to run as root | Yes |
| Starts at boot | Only if lingering is enabled | Yes |

System scope defaults to the service user `ori-runtime`; override with
`--service-user`. That account must already exist. Under system scope the
installed code stays root-owned and read-only to the service: the runtime can
read its config and create its health socket, but cannot modify the code it
executes.

Choose **system** for devices in the field. Choose **user** for a workstation
or a trial where you do not want a root-owned install.

---

## What the installer does

1. Verifies the bundle signature, digest, size, version, and target before any
   archive is opened.
2. Builds an isolated environment from the bundle's hash-locked wheelhouse with
   no package-index access — no live PyPI resolution, ever.
3. Generates and validates a minimal config through the runtime's own
   validator. Credentials are never collected here; secrets belong in the
   environment file.
4. Installs the systemd unit and activates the new release atomically.
5. Restarts the service and waits for the runtime's health socket to report
   healthy for the configured device.
6. Only then enables the service for boot.

If any step fails, the previous release is restored along with its config and
unit, and the service is restarted against them. A first install that fails
leaves nothing behind.

On success the installer prints a JSON summary:

```json
{"boot_persistence":true,"changed":true,"device_id":"energy-monitor-ikeja-01",
 "scope":"system","status":"healthy","version":"2.3.1"}
```

---

## Boot persistence

System installs are enabled for boot and the installer fails if that cannot be
confirmed.

User installs depend on lingering, which is off by default — without it the
service stops when you log out. The installer reports this honestly rather than
implying persistence you do not have. If `boot_persistence` is `false`:

```sh
sudo loginctl enable-linger "$USER"
```

---

## Upgrading

Run the same install command with the new version. The installer verifies the
new bundle, prepares it alongside the current release, and only switches over
once the new one is healthy.

Downgrades are refused unless you pass `--allow-downgrade`, so a stale command
cannot quietly roll a fleet backwards.

Re-running the same version is safe: it re-verifies, re-applies config and
permissions, and reports `"changed": false`.

---

## Rollback

Rollback is automatic. There is no manual rollback command because there is no
window in which you need one: if the new release fails to start or fails its
health check, the installer restores the previous release, its config, and its
unit, restarts the service, and confirms the previous release is healthy before
reporting failure.

The failure is reported as `post_install_health_failed`. If the rollback itself
fails — which means the device may be running neither release — the code is
`rollback_failed` and the device needs attention.

---

## Uninstall

```sh
sudo ori-install-linux uninstall --scope system
```

This stops and removes the service and deletes the installed releases. **Your
data is kept** — config, database, and logs under the data directory survive.

To remove data as well:

```sh
sudo ori-install-linux uninstall --scope system --remove-data
```

That is irreversible. Take a copy of `ori.yaml` and the state database first if
you may need them.

---

## Diagnostics

### Is it running?

```sh
systemctl status ori-runtime           # system scope
systemctl --user status ori-runtime    # user scope
```

### Logs

```sh
journalctl -u ori-runtime -f           # system scope
journalctl --user -u ori-runtime -f    # user scope
```

### Health

The runtime exposes a local read-only health socket at `<data>/health.sock`:

```sh
sudo /opt/ori/current/venv/bin/python -m ori.cli_bridge health snapshot \
  --socket /opt/ori/data/health.sock --timeout-ms 2000
```

This returns the same snapshot the installer health-gates on: device identity,
uptime, sensor state, capability posture, and whether any subsystem is
critical.

### Config

```sh
sudo /opt/ori/current/venv/bin/python -m ori.cli_bridge config validate \
  --path /opt/ori/data/ori.yaml
```

### Failure codes

Every failure exits `2` and prints `code: detail` to stderr. The codes are
stable and defined by `ori-specs/runtime-release-bundle/v1`.

| Code | Meaning |
| --- | --- |
| `unsupported_target` | Not Linux, or an unsupported architecture or Python version |
| `crypto_unavailable` | OpenSSL is missing or older than 3 — not a bad signature |
| `untrusted_release_key` | The bundle names a key that is not the pinned release key |
| `invalid_signature_envelope` | The detached signature is malformed |
| `signature_verification_failed` | The signature did not verify against the pinned key |
| `artifact_integrity_mismatch` | Size or digest mismatch, or a download problem |
| `unsafe_bundle_archive` | The archive contains something unsafe to extract |
| `bundle_manifest_mismatch` | Extracted files do not match the signed manifest |
| `invalid_release_version` | The requested version is malformed |
| `downgrade_forbidden` | Older than what is installed; pass `--allow-downgrade` if intended |
| `unsafe_install_root` | The install root or a path within it is unsafe |
| `offline_install_failed` | The offline environment could not be built from the wheelhouse |
| `config_validation_failed` | Generated config was rejected, or an identity value was invalid |
| `service_start_failed` | The systemd unit or service identity could not be set up |
| `post_install_health_failed` | The new release did not become healthy; it was rolled back |
| `rollback_failed` | Activation failed **and** rollback failed — the device needs attention |

`crypto_unavailable` is worth calling out: it means the host cannot perform the
verification, not that the release is bad. It is the expected result on
OpenSSL 1.1.1 systems such as Raspberry Pi OS Bullseye.

---

## Verifying what you installed

The release key is pinned in this repository and normatively recorded in
`ori-specs/runtime-release-bundle/v1`. Its fingerprint:

```text
Public key   aDlW3MqinQM8y96szEqNske2ytKkxbmMDl87CuLbAQ8=
SHA-256      d4f44308d60fb78a33f709eebc85271f2b8c0d4e59e50bb77bf08f5864918c90
```

See [`RELEASE_SIGNING.md`](RELEASE_SIGNING.md) for the signing authority, its
custody, and the controls around it.
