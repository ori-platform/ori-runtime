# Controller-loss behaviour of a local GPIO output — bench record, 2026-09-01

What a commanded GPIO output does when the controller is lost, measured per
mode on one platform. This is the record the claims in `docs/COMMISSIONING.md`
and `ori/actions/relay.py` rest on. It is evidence about this platform and
wiring; a different platform, kernel, or GPIO driver must be observed, not
assumed.

## Platform

| | |
|---|---|
| Board | Raspberry Pi 4 Model B Rev 1.5 (BCM2711) |
| OS / kernel | Debian GNU/Linux 13 (trixie), `6.18.34+rpt-rpi-v8` |
| GPIO stack | gpiozero 2.0.1 over lgpio 0.2.2.0 (`LGPIOFactory`), Linux GPIO character device |
| Pin | BCM GPIO 26 (physical pin 37) |
| Watchdog | `/sys/class/watchdog/watchdog0/state: active`, held by systemd (`RuntimeWatchdogUSec=1min`); the runtime service itself has `WatchdogUSec=0` |

## Wiring

SRD-05VDC 4-channel opto-isolated relay board, trigger selector S1 on Com–High
(high-level trigger, established by direct rail test). Relay contacts unwired.
The board is powered independently of the Pi, so removing the Pi's power leaves
the board running — without this, the power-loss observation is confounded:

```
MB102 supply, 5 V rail ── DC+          (selector cap on the 5 V pair)
MB102 − rail           ── DC−
Pi pin 39 (GND)        ── MB102 − rail (same rail half as DC−)
Pi pin 37 (GPIO 26)    ── IN1
```

Coil state is observed through the channel LED (LED1) and the armature click.
The LED indicates the driven coil circuit, not the contact position.

## Method

The coil is held energised through the runtime's own acquisition path
(`RelayAction.acquire_at(26, True, coil_state="energised")`, the same call the
commissioning proof operation uses), by a holder process that then sleeps.
Each mode is then induced and the coil observed.

## Observations

### 1. Orderly exit (SIGINT)

Holder started interactively, then interrupted. Cleanup ran; the line was
released. LED1 extinguished. `pinctrl get 26` afterwards: `ip pn | lo`.

### 2. Abrupt process loss (SIGKILL by exact PID)

```
  holder pid:        1988
  is it alive:       yes
  pin while held:    26: op -- pn | hi // GPIO26 = output
  killed. alive now: dead
  pin 0.2s after:    26: op -- pn | hi // GPIO26 = output
  pin 2s after:      26: op -- pn | hi // GPIO26 = output
```

The process was confirmed dead and the pad remained an output driving high.
**LED1 stayed on indefinitely.** A first attempt at this test using `pkill -f`
was discarded as ambiguous — the pattern can match its own wrapper — and the
recorded run kills by exact PID.

A follow-up run established what the run above did not record: that the
kernel freed the line request even though the pad kept driving. The checks, in
order, after an identical exact-PID `kill -9`:

```
pinctrl get 26                                        # pad state
ls -l /proc/[0-9]*/fd | grep -c gpiochip              # open gpiochip descriptors
python3 - <<'EOF'                                     # is the line claimable?
import lgpio
h = lgpio.gpiochip_open(0)
lgpio.gpio_claim_input(h, 26, lgpio.SET_PULL_DOWN)    # raises if held
lgpio.gpio_free(h, 26)
lgpio.gpiochip_close(h)
EOF
pinctrl get 26                                        # pad state after reclaim
```

No process held a gpiochip descriptor, and the fresh claim succeeded — while
the pad was still `op -- pn | hi`:

```
  killed; alive now:   dead
  pin after kill:      26: op -- pn | hi // GPIO26 = output
  gpiochip consumers:  0
  claim as input:      SUCCEEDED — the line request was free
  pin after reclaim:   26: ip    pd | lo // GPIO26 = input
```

**Reclaiming the freed line as an input cleared the driving pad.** That is
direct evidence that a supervising process can recover from application-process
loss by claiming the dead process's line as an input — an act that derives
nothing from the zone's asserted polarity — and it is the distinction between
application-process loss, where the kernel and a supervisor remain available,
and a kernel failure, where nothing does.

### 3. Loss of the Pi's power (board independently powered)

Holder running, LED1 on; the Pi's supply was removed. **LED1 extinguished.**
The board remained powered throughout, so the change is attributable to the
Pi's output ceasing to drive. On reboot the pin reported the boot default
`ip pd | lo`.

### 4. Reset (`sysrq-b`, twice)

Holder running, LED1 on; `echo b > /proc/sysrq-trigger` (immediate reboot, no
shutdown path). **LED1 extinguished at the reset and stayed out**, both runs.

## What this establishes, and what it does not

- On this platform, **abrupt process loss is the only tested mode that left
  the coil commanded.** Orderly release, power loss, and one reset class
  de-energised. Kernel failure was not induced and is untested.
- No software cleanup can cover abrupt process loss, since it is defined by
  the process's code not running. That much is logic, not measurement; that
  the pad then *keeps driving* is this platform's measured property.
- `sysrq-b` demonstrates that a reset clears the pad. It does **not**
  demonstrate the hardware-watchdog timeout path: on BCM2711 the restart
  handler is expected to traverse the same SoC reset, but a genuine watchdog
  expiry was not induced.
- The state database (SQLite, WAL) reported `integrity_check: ok` after the
  power removal and both resets.
- One platform, one board, one wiring. The coil was observed via its channel
  LED and click; the protected-circuit contacts were unwired throughout.
