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

## Missing OS prerequisites

If something the installation needs is absent, the installer tells you what and
why, shows the exact command, and asks. The default answer is **No**:

```text
Some OS packages this installation needs are missing:
  python3-venv             python3-venv  — building the offline runtime

On Raspberry Pi OS Bookworm, this would run exactly:
    apt-get install --no-install-recommends --yes python3-venv
apt may install required OS dependencies and update package-manager state.
No Python packages are downloaded from package indexes.

Install these packages now? [y/N]:
```

Declining leaves the host exactly as it was and stops the install with
`prerequisite_install_failed` and the command to run yourself. So do lacking
administrator privileges, running on a distribution the installer does not know
how to prepare, and cancelling the prompt. "No" means "do not change my
system" — never "continue without something the installation needs".

Package names come from a fixed allowlist and are placed into a fixed argument
array; nothing is passed through a shell, and operating-system components such
as `systemd`, `python3` and `bash` are never candidates. Automatic help is
available on Raspberry Pi OS and Debian Bookworm, and on Ubuntu 24.04.

**Unattended runs never prompt and never modify the host.** They fail with the
same code and the same command, so automation stays reproducible.

This check runs only after the release bundle has been authenticated. An
unsigned or tampered bundle can never reach a package prompt.

---

## Install

### Interactive

```sh
curl -fsSL \
  https://github.com/ori-platform/ori-runtime/releases/download/v2.4.0/install-linux.sh \
  | bash -s -- --version 2.4.0
```

You are asked, in order: the installation scope, a device ID, a device name, a
location, and an optional operator contact. Then the values are read back and
you confirm before anything is written to the host.

Piped installs reopen `/dev/tty` for those prompts; if no terminal is available
the install fails rather than silently choosing defaults. Prompts and progress
go to stderr, so `--json` output stays parseable even during an interactive run.

Scope is asked first, and there is no silent default:

```text
Installation scope:

  1. System — recommended for deployed devices
     Starts during boot without login.
     Runs as dedicated unprivileged user ori-runtime.
     Requires administrator privileges.

  2. User — intended for workstation evaluation
     Runs as your login user.
     Stops after your last session unless lingering is enabled.
     Does not start at boot without lingering.

Choose [1]:
```

Pressing Enter accepts the shown default, but you must submit the prompt —
a non-interactive run never inherits it. Choosing system scope without root
ends the install with the exact command to repeat; the installer will not call
`sudo` for you.

Device ID and name are suggested from this host's name, with the rules and
examples shown:

```text
  1-64 characters: lowercase letters, digits, dots, dashes, underscores.
  Examples: pi-ikeja-01, hvac.roof.3, meter_02
Device ID [pi-ikeja-01]:
```

Enter accepts the suggestion. A stock-image hostname — `raspberrypi`,
`localhost`, `ubuntu` — gets a short random suffix, because otherwise every
device flashed from that image would share an identity.

Location and operator contact are never suggested. The installer cannot know
them, and a plausible-looking location in a fleet report is worse than a blank
one. Operator contact may be left empty.

Rejected input is never echoed back.

Use `bash`, not `sh`. Under `dash` — which is `/bin/sh` on Debian and Ubuntu —
the script exits with a message telling you to re-run it with Bash.

### Unattended

Every identity value must be supplied; unattended mode never prompts.

```sh
curl -fsSL \
  https://github.com/ori-platform/ori-runtime/releases/download/v2.4.0/install-linux.sh \
  | bash -s -- --version 2.4.0 -- \
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
base=https://github.com/ori-platform/ori-runtime/releases/download/v2.4.0
curl -fsSLO "${base}/install-linux.sh"
curl -fsSLO "${base}/install-linux.sh.sha256"
sha256sum -c install-linux.sh.sha256
less install-linux.sh
bash install-linux.sh --version 2.4.0 -- --scope system --unattended ...
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
leaves no Ori installation behind.

One thing is not undone: OS packages you approved earlier in the run. They are
installed by your system's package manager on your explicit instruction, and
removing them automatically could break unrelated software that now depends on
them. If an installation fails after that point, those packages remain, and the
failure message says so.

On success the installer prints a human summary naming the installation and
what happens to it after a reboot:

```text
Ori Runtime installed

  version   2.4.0
  scope     system
  device    energy-monitor-ikeja-01
  root      /opt/ori
  release   /opt/ori/releases/2.4.0
  config    /opt/ori/data/ori.yaml
  data      /opt/ori/data
  socket    /opt/ori/data/health.sock
  unit      /etc/systemd/system/ori-runtime.service
  runs as   ori-runtime

  Starts during boot without anyone logging in.
```

Colour is suppressed when output is not a terminal, when `NO_COLOR` is set, or
when `TERM=dumb`.

Pass `--json` when a program consumes the result. Stdout then carries exactly
one JSON document — on failure as well as success — while prompts and progress
go to stderr:

```json
{"active_release":"/opt/ori/releases/2.4.0",
 "boot_persistence":true,
 "changed":true,
 "config_path":"/opt/ori/data/ori.yaml",
 "data_path":"/opt/ori/data",
 "device_id":"energy-monitor-ikeja-01",
 "diagnostics":[{"name":"install.identity","status":"PASS","mandatory":false,
                 "message":"Ori 2.4.0 installed in system scope at /opt/ori"}],
 "health":{"device_id":"energy-monitor-ikeja-01","critical":false},
 "health_socket":"/opt/ori/data/health.sock",
 "install_root":"/opt/ori",
 "launcher_installed":true,
 "launcher_path":"/usr/local/bin/ori",
 "next_step":"Run `ori doctor` at any time to check this installation.",
 "scope":"system",
 "service_user":"ori-runtime",
 "status":"healthy",
 "unit_path":"/etc/systemd/system/ori-runtime.service",
 "version":"2.4.0",
 "warnings":[]}
```

Every key above is always present on a successful install. `diagnostics`
carries the full doctor report and `health` the runtime snapshot; both are
abridged here for readability.

A failed `--json` run emits a stable error document instead:

```json
{"error":{"code":"unsupported_target","detail":"installer requires Linux"},
 "ok":false,"schema_version":1}
```

---

## The `ori` command

The installer writes a launcher so one command works regardless of which
release is active:

| Scope | Launcher |
| --- | --- |
| `user` | `~/.local/bin/ori` |
| `system` | `/usr/local/bin/ori` |

It resolves the active release when it runs, so upgrades and rollbacks take
effect without rewriting it. Available commands:

```sh
ori doctor              # diagnose this installation
ori status              # where it lives and whether it is running
ori config validate     # check the installed config
ori install             # verify and install a release bundle
ori uninstall --scope   # stop the service and remove the installation
ori --version
```

Every command has `--help` covering examples, scope behaviour, exit-status
meaning, and `--json` where relevant. Exit statuses are consistent: **0**
succeeded, **1** ran and reported a failure, **2** could not run at all — no
installation found, an ambiguous scope, or a refusal on safety grounds.

If the launcher directory is not on your `PATH`, the installer says so and
gives you the exact line rather than claiming the command is ready:

```text
/home/pi/.local/bin is not on your PATH, so the `ori` command will not be
found yet.
Add it for this shell:
    export PATH="/home/pi/.local/bin:$PATH"
To make it permanent, add that line to ~/.profile (or ~/.bashrc, or ~/.zshrc
for zsh).
```

A user-scope launcher refuses to run as root before reaching any release code,
because a user installation is writable by its owner and running it under
`sudo` would execute unprivileged code with full privilege. Re-run it as the
account that owns the installation.

The installer replaces or removes only launchers it wrote. A file you put at
that path yourself is left alone, and the install reports the conflict rather
than failing.

---

## Automatic diagnostics

After the service is enabled, the installer runs the installed `ori doctor` by
its absolute path — never through `PATH`, which could resolve a different
release — bound to the installation it just activated. It checks:

- the config parses and validates through the runtime's own loader;
- the runtime answers on its health socket and reports the expected device;
- the service is active, and whether it is enabled;
- boot persistence, and where it comes from;
- the service account can read its config, execute its interpreter and write
  its data — and **cannot** modify the verified release;
- host prerequisites;
- optional capabilities: sensors, relay, messaging, gateway, local SLM.

Each result is `PASS`, `WARN` or `FAIL`. A **mandatory** failure — invalid or
unreadable config, wrong runtime identity, an inactive service, unsafe
permissions — fails the installation and rolls it back to the previous release.

Warnings do not roll anything back. A user service that will not survive a
reboot is a real warning worth acting on, but it is a working installation.
Deliberately disabled integrations are informational, not faults.

Run it yourself at any time:

```sh
ori doctor                    # the only installation present
ori doctor --scope system     # when both user and system exist
ori doctor --json             # one JSON document on stdout
```

Scope is never inferred from whether you used `sudo`. If both a user and a
system installation exist, `ori doctor` refuses to guess and asks for
`--scope`.

---

## Boot persistence

System installs are enabled for boot and the installer fails if that cannot be
confirmed.

User installs depend on lingering, which is off by default. Without it the
service stops after your **last session ends**, and does not start at boot.
Closing a terminal is not the same thing: a desktop session, or another SSH
connection, keeps the service alive — which is why a user install can appear to
survive logging out and then be gone after a reboot.

Persistence for a user install needs **both** lingering enabled and the unit
enabled; `ori doctor` reports the two states separately and names which one is
missing. The installer reports this rather than implying persistence you do not
have. If `boot_persistence` is `false`:

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

This stops and removes the service, deletes the installed releases, and removes
the `ori` launcher. **Your data is kept** — config, database, and logs under
the data directory survive.

Only a launcher this installer wrote for this installation is removed. A file
you placed at that path, or one belonging to a different Ori installation, is
left alone. `--scope` is required so the wrong installation cannot be removed
by accident.

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
| `prerequisite_install_failed` | A required OS prerequisite is missing and was not installed |
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
