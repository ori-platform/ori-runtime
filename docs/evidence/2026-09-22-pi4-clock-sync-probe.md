# The host-clock synchronization probe, on the bench Pi

**Result: `host_clock_synchronized()` reports the kernel's own state on the
target. It returned `True` on a clock that NTP had synchronized, and `False`
once the clock had been restated with NTP off. In both states it agreed with
`timedatectl`.**

The run used the bench Raspberry Pi 4 Model B on Raspberry Pi OS Trixie,
2026-09-22, with the bench virtual environment's Python 3.13. The module under
test was the working tree's `ori/utils/time_utils.py`, copied to a scratch
directory on the Pi. The installed release was not modified, and `ori-runtime`
stayed active throughout.

| Step | `timedatectl` `NTPSynchronized` | `host_clock_synchronized()` |
| --- | --- | --- |
| After boot, NTP synchronized | yes | `True` |
| `timedatectl set-ntp false`, then `date -s` to the current time | no | `False` |
| `timedatectl set-ntp true`, re-synchronized | yes | `True` |

Setting the time clears the kernel's synchronized flag (`STA_UNSYNC`), and
`adjtimex` then returns `TIME_ERROR`, which is the state the probe reads. The
clock step was below one second.

## What this does not establish

- **The x86_64 target was not run.** The probe relies on the kernel ABI's
  zero-`modes` read, and the code handles both 64-bit targets the same way.
- **The compaction and reader changes were not exercised on the Pi.** They are
  host-tested.
- **An offline device that never synchronizes was not observed over time.**
