# staging the blinka platform library into an isolated release venv

**Result: `lgpio`, `RPi.GPIO`, `board` and `busio` all import from an isolated
venv after staging, the resolved GPIO backend is `LGPIOFactory` and it claims
its line through the kernel, and an ADS1115 reads over the resulting bus.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie, stock Python
3.13.5, on 2026-09-03.

## Why this was needed

adafruit-blinka builds `board` for a Pi through an RPi.GPIO-compatible module.
Without one, `import board` raises `RuntimeError` — a crash on the supported Pi
and nothing at all on a host with no blinka, which is why it passed every
developer machine and every CI job while the i2c adapter could not open an
ADS1115 on the only platform it exists for.

It cannot be carried in the wheelhouse. `rpi-lgpio` publishes a pure
`py3-none-any` wheel, but requires `lgpio>=0.1.0.1`, and no `lgpio` release
publishes a wheel for the supported interpreter: `0.2.2.0` ships cp39 through
cp312 and no cp313, `0.1.0.0` ships eggs pip cannot install, and the
requirement excludes the zero-byte `0.0.0.2` placeholder. One lock serves every
target, so a resolution that cannot satisfy the supported Trixie tuple fails the
wheelhouse build, and apt's build is wanted regardless — matched to this
interpreter's ABI and to the system liblgpio. Pinning the placeholder is a hard
resolver conflict. Raspberry Pi OS ships the shim prebuilt as
`python3-rpi-lgpio`, so it is staged the way the pin factory already is —
best effort, because a Pi that staged the pin factory but has no shim installs
today, and the classic `python3-rpi.gpio` can occupy the same import name with
a layout this manifest does not carry.

## What was verified

The pinned Pi requirement set installs on the target with hashes required and
pulls neither module, which is what makes staging necessary rather than
convenient:

```
$ pip install --require-hashes -r requirements/pi.txt     exit 0
   Adafruit-Blinka: 9.2.0
   adafruit-circuitpython-ads1x15: 3.0.5
   lgpio: not installed
   rpi-lgpio: not installed
   sysv-ipc: 1.2.0
```

The four manifest members were then copied into that venv's `purelib` exactly
as `_stage_system_modules` copies them, from
`/usr/lib/python3/dist-packages`, `0644`, preserving package layout:

```
lgpio.py
_lgpio.cpython-313-aarch64-linux-gnu.so
RPi/__init__.py
RPi/GPIO/__init__.py
```

Nothing else came with them — the `RPi` tree in the release holds those two
files and no `egg-info`.

```
   isolated venv (no dist-packages on path): True
   lgpio, RPi.GPIO, board, busio: all import
   pin factory: LGPIOFactory | arbitrated: True
   ADS1115 at 0x48, A0 tied to GND: -0.00063 V
```

`arbitrated: True` is the property that matters beyond importing: the backend
holds its line through the kernel rather than driving `/dev/gpiomem` without
claiming it, so a second writer is refused. The reading is the expected one for
a grounded input on a channel wired to a header ground pin.

## Bookworm 3.11, measured rather than assumed

Run in an `arm64` Bookworm container answering as Pi hardware, against the
installer's own staging code. Bookworm packages neither `python3-lgpio` nor
`python3-rpi-lgpio`.

```
no pin factory:
  refused -> prerequisite_install_failed: this device needs the system lgpio
             pin factory and lgpio is not installed; install python3-lgpio
  notes: []                       <- the shim block never ran

pin factory present, shim absent:
  install proceeds
  notes: ['adafruit-blinka has no platform library in this release
           (RPi is not installed (python3-rpi-lgpio)); i2c sensors will
           report their driver unavailable']
  staged: lgpio.py, _lgpio.cpython-311-aarch64-linux-gnu.so
```

So a Pi with no pin factory refuses today and still refuses, unchanged by this
work; the configuration the best-effort shim protects is the second one. An
earlier draft of this record claimed the first case installed today. It does
not.

## What this does not establish

The venv was built and populated by hand rather than by an installed release
bundle, because the change is not in a published candidate yet. It proves the
staged file set is sufficient and the resulting backend is the intended one; it
does not exercise the installer's own transaction, permissions, or rollback
around that staging. A published candidate carrying this change still needs the
systemd-host runbook on this tuple.

The relay was not actuated. The pin factory was resolved and its chip handle
observed; nothing was driven.
