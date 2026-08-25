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

A runtime on any interpreter other than the one apt built for cannot import it.
The consequence is quiet rather than loud: `gpiozero` finds no usable factory,
the HAL guards catch the ImportError, and the adapter enters simulation mode. A
relay configured under `deployment_profile: development` then reports healthy
while no pin is ever driven.

This is why running Ori on a bundled 3.12 interpreter beside a 3.13 system is
not a workaround. It produces a runtime that cannot actuate and does not say so.

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

The installer creates an isolated virtual environment. An isolated venv cannot
import apt packages, so a Pi install needs the system site directory visible for
the GPIO layer — otherwise `gpiozero` is present but factory-less, which fails
in exactly the silent way described above.

Check a deployed install:

```bash
sudo /opt/ori/current/venv/bin/python -c \
  "from gpiozero import Device; Device.ensure_pin_factory(); print(type(Device.pin_factory).__name__)"
```

`LGPIOFactory` means GPIO is live. `ModuleNotFoundError` or a factory error
means the runtime will simulate every relay operation.

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
  "from gpiozero import Device; Device.ensure_pin_factory(); print('ok')"

# 4. The interpreter the service actually runs.
systemctl cat ori-runtime.service | grep ExecStart
```

Step 3 is the one that matters. Steps 1 and 2 can pass on a device whose Ori
install still cannot drive a pin.

## Before a demo

Anything that must physically actuate has to be proven on the device, under a
profile that refuses to pretend:

1. Install from a release bundle carrying a `linux-aarch64-python3.13` target.
2. Confirm step 3 above returns `ok`.
3. Wire the relay to **normally closed** terminals and declare its `gpio_pin`.
4. Move `deployment_profile` off `development`. A hardened profile fails
   startup when a configured GPIO path has no `gpiozero` behind it, which is
   the behaviour you want — it turns a silent simulation into a refusal.
5. Trip a Tier D condition and confirm the relay physically opens.

Step 4 is what converts every preceding assumption into something the runtime
will refuse to fake.
