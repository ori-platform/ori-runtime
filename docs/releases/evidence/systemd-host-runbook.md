# Systemd-host pre-publication evidence — runbook

The container harness marks installation and every downstream service claim
BLOCKED, because a container has no systemd session bus. Those are exactly the
claims release candidates have failed on hardware. This runbook proves them on
a real machine, against an artifact built and development-signed from a named
commit.

It is version-agnostic: set the variables in step 0 and every command below is
copy-pasteable verbatim. Nothing here names a release.

## What a passing run establishes

| Phase | Claim |
| --- | --- |
| `install` | The artifact verifies before extraction; a system-scope install completes, reports healthy, writes its config, installs a working launcher, enables and starts the unit under `ori-runtime`, opens its health socket, and diagnoses clean — including `permissions.code` on a real venv |
| `persist` | The unit is still active and enabled after a genuine reboot, and the runtime still reports the release under test |
| `rollback` | A candidate that fails *after* activation restores the previous release and removes itself, leaving the service healthy |
| `uninstall` | The unit and every managed path are removed, the service account is retained, and the empty install root is taken away with `rmdir` so the host can run again |

## What it does not establish

KMS signing custody, the production trust root, GitHub publication,
authenticated download, published asset completeness, and post-publication
reverification. Those belong to the protected release workflow and are proven
only by a real tag. The artifact here is development-signed with an ephemeral
key that is discarded when the build finishes.

The build is not byte-identical to the workflow's. The packaged key registry is
part of the source, so substituting it changes the wheel and the bundle as well
as the signature. What is reproduced is installation behaviour.

## Prerequisites

- systemd is the init system — `test -d /run/systemd/system`
- **No existing Ori installation.** `/opt/ori` absent, no `ori-runtime.service`
  known to systemd, no `/usr/local/bin/ori`. The harness refuses otherwise
  rather than install over one.
- The interpreter the target names, on `PATH` (`python3.11` or `python3.12`),
  plus a `python3` of 3.9 or newer for the harness itself
- `git`, `tar`, `openssl`, and `sudo`
- A clean checkout of the commit under test — the builder archives from the
  commit, not the working tree, so uncommitted edits are not included
- The ability to reboot the host

## 0. Set the run's identity

```bash
set -o pipefail                     # see the note below — this is not optional
cd /path/to/ori                     # the checkout under test
COMMIT=$(git rev-parse HEAD)        # must be the exact merged commit
VERSION=<the version this commit declares>   # e.g. 2.4.0-rc.5
TARGET=linux-$(uname -m)-python3.12          # or python3.11
OUT=$HOME/ori-evidence
mkdir -p "$OUT"
```

Every command below pipes into `tee` so the run is logged. **Without
`pipefail`, `$?` after such a pipe is `tee`'s status and is always 0** — it
would report success for a failed phase and hide partial coverage entirely.
With it, `$?` is the harness's own status, including the 3 that means BLOCKED.

Each block below sets it again rather than relying on this one. The reboot ends
the shell that ran the install, and a fresh shell pasting a later block would
otherwise read every phase as a pass. `${PIPESTATUS[0]}` is a bash-only
alternative; it silently expands to nothing under zsh, so this runbook does not
use it.

`VERSION` is checked against `pyproject.toml` through the same normalisation the
release workflow uses; a mismatch stops the build before anything is signed.

## 1. Build and development-sign the artifact

```bash
set -o pipefail
./docs/releases/evidence/build-local-artifact.sh \
    "$COMMIT" "$TARGET" "$VERSION" "$OUT" 2>&1 | tee "$OUT/build.log"
echo "build exit $?"
```

Record the summary block it prints — source commit, archive digest, artifact
digest, and the ephemeral key fingerprint.

Then derive the arguments the harness needs:

```bash
BUNDLE="$OUT/ori-runtime-$VERSION-$TARGET.tar.gz"
SIG="$BUNDLE.signature.json"
KEYS="$OUT/release-keys.dev.json"
SHA=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
```

## 2. Install

```bash
set -o pipefail
sudo ./docs/releases/evidence/harness-systemd-host.sh \
    install "$BUNDLE" "$SIG" "$KEYS" "$SHA" "$VERSION" 2>&1 \
    | tee "$OUT/install.log"
echo "install exit $?"
```

Do not proceed unless this is **0**. The boot is recorded only after every
install assertion has passed, so a failed install cannot later be presented as
the provenance of a persistence claim.

## 3. Reboot, then prove persistence

```bash
sudo reboot
```

After the host comes back:

```bash
set -o pipefail
cd /path/to/ori
sudo ./docs/releases/evidence/harness-systemd-host.sh persist "$VERSION" 2>&1 \
    | tee "$OUT/persist.log"
echo "persist exit $?"
```

The phase compares the current boot id against the one recorded at install.
Uptime is not accepted: installing shortly after an ordinary boot and checking
immediately satisfies any uptime bound while nothing has restarted.

## 4. Rollback

Rollback needs a candidate that installs and *then* fails its own post-install
diagnosis. A tampered or mis-signed artifact cannot produce one — verification
refuses it before anything is installed, and recording that refusal as a
rollback would prove nothing while printing PASS.

Without such an artifact the phase records BLOCKED and the run exits **3**:

```bash
set -o pipefail
sudo ./docs/releases/evidence/harness-systemd-host.sh rollback 2>&1 \
    | tee "$OUT/rollback.log"
echo "rollback exit $?"
```

To prove it instead, build a second artifact from a scratch commit that makes a
mandatory health check fail, and pass it the same way as step 2:

```bash
sudo ./docs/releases/evidence/harness-systemd-host.sh \
    rollback "$FAILING_BUNDLE" "$FAILING_SIG" "$KEYS" "$FAILING_SHA" "$FAILING_VERSION"
```

The phase requires the exact `post_install_health_failed` code. "Some nonzero
exit" is satisfied by an argument error or a signature rejection, neither of
which ever activates anything — indistinguishable from a successful rollback
unless the code is checked.

## 5. Uninstall

```bash
set -o pipefail
sudo ./docs/releases/evidence/harness-systemd-host.sh uninstall 2>&1 \
    | tee "$OUT/uninstall.log"
echo "uninstall exit $?"
```

This uninstalls with `--remove-data`, because the evidence installation exists
only for this run. The installer removes its own tree; the phase then checks
that `current`, `releases` and `data` are all gone and finishes with a
non-recursive `rmdir /opt/ori`.

Nothing here removes anything recursively. `rmdir` deletes a directory only
when it is already empty, so it cannot descend into a real deployment, cannot
delete anything the installer chose to keep, and refuses outright on a symlink.
If the install root is not empty, the phase reports what remains and records
BLOCKED rather than forcing it.

Retention under the default flag is the installer's own behaviour and is
covered by the unit suite — asserting it here would mean deleting the retained
data by hand afterwards.

The `ori-runtime` account is retained deliberately: files elsewhere may belong
to it, and a freed uid can be reused by a later account. It does not block a
further run — installation adopts an existing usable account as found. Remove
it only if you want it gone:

```bash
sudo userdel ori-runtime
```

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Every required claim proven |
| 1 | A required claim failed — the run is not evidence |
| 3 | Claims remain BLOCKED by the environment; partial coverage |

A run that exits 3 must be reported as partial. Reading only "it finished" turns
untested claims into apparent passes.

## Recording the run

Write one record per run at `docs/releases/evidence/<version>-systemd-host.md`,
following the layout of the container-run records already in this directory. It
must carry:

- source commit and source-archive SHA-256, with the command to reproduce it
- artifact SHA-256 and the ephemeral key fingerprint
- harness revision (printed in each phase's `=== HOST ===` block)
- host identity: distribution, kernel, architecture, systemd version, and both
  the `python3` and base interpreter paths
- the exit status of every phase, and the attached logs
- the limitations above, restated — evidence that overstates itself is worse
  than none

The harness prints the host block itself, so paste it rather than retyping it.
