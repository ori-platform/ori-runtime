# Raspberry Pi Support

What Ori needs from a Raspberry Pi, and why the interpreter version decides
whether GPIO works at all.

## Supported hardware

| Requirement | Value |
| --- | --- |
| Model | **Raspberry Pi 4 Model B or newer** |
| Architecture | `aarch64` (64-bit) |
| OS | Raspberry Pi OS **Trixie** (Debian 13), 64-bit |
| Python | **3.13**, from the system (`/usr/bin/python3.13`) |

**Pi 4 is the floor for the Python 3.13 target.** Trixie's 64-bit images and the
`aarch64` release bundles assume a BCM2711 or later. Earlier boards are either
32-bit only or run an OS whose Python predates the supported set, and no
`linux-armv7`/`python3.10` bundle is published. A Pi 3 will not install from a
3.13 bundle, and nothing about the failure will make that obvious — so do not
plan a deployment around one.

Reference bench: Pi 4 Model B, BCM2711, 4GB.

## Why the interpreter version is not cosmetic

Ori drives GPIO through `gpiozero`. It never imports `RPi.GPIO` directly.

`gpiozero` declares **no pin factory** of its own — it selects one at import
from whatever is installed. On Trixie that is `LGPIOFactory`, backed by
`python3-lgpio` from apt.

That package ships a compiled extension built **per interpreter version**:

```
/usr/lib/python3/dist-packages/_lgpio.cpython-313-aarch64-linux-gnu.so
```

A runtime on any interpreter other than the one apt built for cannot import it,
and the consequence is worse than a failure.

`gpiozero` does not raise when no real factory is available. It warns and falls
back to `NativeFactory`, its own experimental implementation. Measured on the
bench Pi, installing this lock into an isolated virtual environment gives:

```
PinFactoryFallback: Falling back from pigpio: No module named 'pigpio'
NativePinFactoryFallback: Falling back to the experimental pin factory
NativeFactory because no other pin factory could be loaded.
pin factory: NativeFactory
```

So `from gpiozero import DigitalOutputDevice, OutputDevice` succeeds,
`gpio_backend_importable()` returns true, and the hardened-posture check passes.
The runtime reports GPIO as available and drives Tier D through an experimental
fallback rather than refusing to start.

That is the opposite of failing closed. `relay.py` says as much in its own
docstring -- the import check "proves dependency availability only" -- but
nothing between that check and a Tier D trip asks *which* factory was loaded.

This is why running Ori on a bundled 3.12 interpreter beside a 3.13 system is
not a workaround, and why the check below is on the factory rather than on the
import.

## Why there is no pin factory in `requirements/pi.txt`

Two dead ends, both checked:

- **`RPi.GPIO` publishes sdists only.** The wheelhouse build resolves with
  `--only-binary=:all:`, which reduces its candidate set to nothing. The `pi`
  wheelhouse target could never be built while it was pinned.
- **`lgpio` on PyPI is a placeholder.** The only installable release is
  `0.0.0.2`, whose wheel contains a zero-byte `lgpio.py`. `rpi-lgpio` depends on
  it and inherits the same emptiness. Neither yields a working factory.

So the pin factory comes from the operating system. `requirements/pi.in` carries
`gpiozero` and `smbus2` only, and the image supplies the rest:

```bash
sudo apt install python3-lgpio python3-rpi-lgpio
```

Both are present on a stock Trixie image; the command is for a minimal one.

## The venv must be able to see it

An isolated venv cannot import apt packages, so a Pi install needs the pin
factory reachable from inside it — otherwise `gpiozero` is present but
factory-less, which fails in exactly the silent way described above.

The venv stays isolated and the installer takes the module by name. The two
files apt ships, `lgpio.py` and the extension built for this interpreter's ABI,
are **copied** into the release's own `site-packages`.

Copied rather than linked, for two reasons. The release permission transaction
requires an external symlink target to be executable and apt ships both files
`0644`, so a link is accepted where it is made and refused a seam later.
Copying also freezes the reviewed bytes into the release instead of leaving
live code attached to whatever a future apt upgrade puts at that path.

Creating the venv with `--system-site-packages` would have been simpler and is
the wrong trade. It puts every apt package on the runtime's import path, where
an unpinned optional import — a transport, a hardware backend — could activate
a capability from a package no release reviewed. It also lets pip treat a pinned
dependency whose version matches a system one as already satisfied, leaving the
runtime importing unhashed code.

Before anything is copied, the source is checked: discovery runs the interpreter
in isolated mode so no environment variable or working directory can steer it,
the answer must land in an admitted system package directory, and each file must
be a regular file, root-owned, and not writable beyond its owner. The extension
is named from the interpreter's own `EXT_SUFFIX` rather than matched by pattern,
so an extension left behind for another ABI cannot be taken.

**Only Pi hardware stages it, and there it is required.** An install that
cannot stage both halves fails with `prerequisite_install_failed` rather than
finishing without the capability the bundle exists to deliver. On Linux that is
not a Pi the same `aarch64` bundle installs without asking: nothing is copied
even where the apt package happens to be present, because that host has no pins
to drive and system code in a release that will never use it is exposure bought
for nothing. `/proc/device-tree/model` is what decides.

To check what a deployed venv can reach beyond its own tree:

```bash
sudo /opt/ori/current/venv/bin/python -c \
  "import importlib.util as u; \
   print([m for m in ('yaml','cryptography','requests','RPi','aiocoap') \
          if (s := u.find_spec(m)) and 'dist-packages' in (s.origin or '')])"
```

An empty list is the expected answer. Anything else means the venv is reading
the system path for something other than the pin factory.

Check a deployed install:

```bash
sudo /opt/ori/current/venv/bin/python -c \
  "from gpiozero import Device; Device.ensure_pin_factory(); print(type(Device.pin_factory).__name__)"
```

`LGPIOFactory` means GPIO is live. **`NativeFactory` means it is not** -- the
import succeeded, every availability check passes, and the pins are driven by an
experimental fallback. Treat that result as a failed check, not a partial pass.

## Upgrading off a hand-placed interpreter

Upgrade first, then remove the old interpreter. A superseded release that
nothing is using no longer blocks anything: an install inspects only the
candidate and the release `current` points at, so inert history is left alone.

```bash
# 1. Install the new release while the old interpreter is still present.
sudo bash install-linux.sh --version <version> -- --unattended --scope system

# 2. Confirm the new venv is on the system interpreter.
sudo readlink -f /opt/ori/current/venv/bin/python   # expect /usr/bin/python3.13

# 3. Remove the hand-placed interpreter and its symlink.
sudo rm -rf /usr/local/ori-python /usr/local/bin/python3.12
```

Step 2 before step 3. A release whose venv still resolves through `/usr/local`
will stop working the moment step 3 runs.

**Never remove the interpreter the active release is built on.** That release
is what an upgrade rolls back to, so removing its interpreter leaves the
installation with a rollback target that cannot start. An install refuses
before interrupting the service rather than discovering it mid-rollback, so the
symptom is a blocked upgrade rather than a failed one.

That is why step 2 is a confirmation and not a formality. Once the new release
is active, the old one is inert: nothing inspects it, and it does not block
anything.

### When retirement is useful

Retirement is optional. It applies when you want to deliberately give up
rollback and downgrade to an inactive release — not as a step in removing an
interpreter, which the order above already handles.

```bash
sudo ori-install-linux release list --scope system
sudo ori-install-linux release retire <version> --scope system
```

The active release cannot be retired, and the command refuses it. If the
release you want to retire is still active, activate a different healthy
release first.

`release list` reports `has_interpreter` per release. It is named for what it
checks — whether a file is there. Whether a release *starts* is only answered
by starting it, which the installer does for the rollback candidate at install
time. `has_interpreter` does not identify releases that block upgrades; only
the active rollback candidate is load-bearing.

Retiring moves a release into `/opt/ori/retired/` rather than deleting it, so
it is reversible; deletion is a separate act.

## Verifying a Pi before you rely on it

Run these on the device, not on a laptop. Simulation mode makes a developer
machine look identical to a working Pi, which is the point of it and also the
trap.

```bash
# 1. The platform is what you think it is.
grep VERSION_CODENAME /etc/os-release && uname -m && python3 -V

# 2. The pin factory resolves under the system interpreter.
python3 -c "from gpiozero import Device; Device.ensure_pin_factory(); \
  print(type(Device.pin_factory).__module__)"

# 3. The runtime's own venv resolves it too.
sudo /opt/ori/current/venv/bin/python -c \
  "from gpiozero import Device; Device.ensure_pin_factory(); \
   print(type(Device.pin_factory).__name__)"

# 4. The interpreter the service actually runs.
systemctl cat ori-runtime.service | grep ExecStart
```

Step 3 is the one that matters, and read the name it prints rather than its
exit code: it succeeds for any factory at all, including the experimental
fallback. Steps 1 and 2 can pass on a device whose Ori install still cannot
drive a pin.

## Before a demo

Anything that must physically actuate has to be proven on the device, under a
profile that refuses to pretend:

1. Install from a release bundle carrying a `linux-aarch64-python3.13` target.
2. Confirm step 3 above prints `LGPIOFactory`.
3. Wire the relay to **normally closed** terminals and declare its `gpio_pin`.
4. Move `deployment_profile` off `development`. A hardened profile fails
   startup when a configured GPIO path has no `gpiozero` behind it, which is
   the behaviour you want — it turns a silent simulation into a refusal.
5. Trip a Tier D condition and confirm the relay physically opens.

Step 4 is what converts every preceding assumption into something the runtime
will refuse to fake.
