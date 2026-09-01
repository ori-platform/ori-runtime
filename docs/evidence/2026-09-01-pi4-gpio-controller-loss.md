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

**Reclaiming the freed line as an input cleared the driving pad — but this run
claimed with `SET_PULL_DOWN`, an explicitly chosen bias** that on this
high-trigger wiring happens to oppose the trigger level. It demonstrates that
the line is recoverable after process loss; it does not demonstrate a neutral
mechanism. The neutral variant was demonstrated separately, below.

### Neutral reclamation, observer-paced (same day, later run)

The reclaim was repeated with `lgpio.SET_PULL_NONE` — no bias selected — and
paced by the observer: each phase halted on an Enter press until LED1 had been
judged, because an earlier self-pacing script moved faster than a person can
attribute an LED change to a phase. (Three same-day fast runs produced
identical pad traces but unattributable LED timing, and one further run was
performed with the relay board unpowered and is void for any coil claim; both
are recorded here as discarded, like the `pkill` attempt above.)

The holder commands the coil through `RelayAction.acquire_at`, the GPIO
acquisition primitive invoked beneath `CommissionedActuator.acquire_commanding`.
This isolates process-loss behaviour after acquisition; it does not test
binding verification or commissioned outcome resolution. As run —
`/home/ori/bench/hold_energised.py`, with `PYTHONPATH` pointing at this
repository's source tree:

```python
"""Hold the coil energised through the real seam, then wait to be killed.

Uses `acquire_at`, the same path the commissioning proof uses, so what is
observed on controller loss is what that path leaves behind.
"""
import asyncio, os, signal, sys, time
from ori.actions.relay import RelayAction

async def main() -> None:
    relay = RelayAction()
    await relay.acquire_at(26, True, coil_state="energised")
    print(f"  coil commanded ENERGISED, pid {os.getpid()}", flush=True)
    print("  LED1 should be ON now. Confirm, then this will be killed.", flush=True)
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

# No handlers: SIGKILL cannot be caught anyway, and the point is what the
# kernel leaves when the process simply stops existing.
asyncio.run(main())
```

The pacing script starts the holder, kills it by exact PID, claims and frees
the line, and blocks on the observer between phases —
`/home/ori/bench/gate1d.py`:

```python
"""Neutral-reclaim observation, paced by the observer.

Nothing advances until Enter is pressed, so every LED judgement has an
unambiguous owner phase.
"""
import os, signal, subprocess, time

def pin() -> str:
    return subprocess.run(["pinctrl", "get", "26"], capture_output=True, text=True).stdout.strip()

def pause(msg: str) -> None:
    input(f"\n>>> {msg}\n>>> press Enter when you have judged LED1... ")

env = dict(os.environ, PYTHONPATH="/home/ori/bench/src")
holder = subprocess.Popen(
    ["./venv/bin/python", "hold_energised.py"],
    cwd="/home/ori/bench", env=env, start_new_session=True,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(3)
print(f"PHASE 1 — coil commanded ENERGISED (holder pid {holder.pid})")
print(f"  pin: {pin()}")
pause("LED1 should be ON now. Confirm it.")

os.kill(holder.pid, signal.SIGKILL)
holder.wait()
time.sleep(0.5)
print(f"\nPHASE 2 — holder SIGKILLed (confirmed dead: {holder.returncode is not None})")
print(f"  pin: {pin()}")
pause("Per the standing evidence LED1 should have STAYED ON. Did it?")

import lgpio
h = lgpio.gpiochip_open(0)
lgpio.gpio_claim_input(h, 26, lgpio.SET_PULL_NONE)
time.sleep(0.3)
print(f"\nPHASE 3 — line claimed as input, NO pull (nothing chosen)")
print(f"  pin: {pin()}")
pause("THE QUESTION: did LED1 go OUT at this claim, and stay out?")

lgpio.gpio_free(h, 26)
lgpio.gpiochip_close(h)
time.sleep(0.3)
print(f"\nPHASE 4 — claim freed")
print(f"  pin: {pin()}")
pause("LED1 should still be out. Confirm, then done.")
print("\nReport the four phase judgements.")
```

Invoked as `ssh -t ori-pi '~/bench/gate1d.sh'`, where `gate1d.sh` is
`cd /home/ori/bench && exec ./venv/bin/python gate1d.py`. Captured output:

```
❯ ssh -t ori-pi '~/bench/gate1d.sh'
PHASE 1 — coil commanded ENERGISED (holder pid 1937)
  pin: 26: op -- pn | hi // GPIO26 = output

>>> LED1 should be ON now. Confirm it.
>>> press Enter when you have judged LED1...

PHASE 2 — holder SIGKILLed (confirmed dead: True)
  pin: 26: op -- pn | hi // GPIO26 = output

>>> Per the standing evidence LED1 should have STAYED ON. Did it?
>>> press Enter when you have judged LED1...

PHASE 3 — line claimed as input, NO pull (nothing chosen)
  pin: 26: ip    pn | lo // GPIO26 = input

>>> THE QUESTION: did LED1 go OUT at this claim, and stay out?
>>> press Enter when you have judged LED1...

PHASE 4 — claim freed
  pin: 26: ip    pn | lo // GPIO26 = input

>>> LED1 should still be out. Confirm, then done.
>>> press Enter when you have judged LED1...

Report the four phase judgements.
Connection to 192.168.0.104 closed.
```

The observer's judgement at each pause: phase 1, LED1 on; phase 2, LED1
stayed on; phase 3, LED1 out by the time the prompt printed — the only event
between the phase-2 judgement and that prompt was the input claim — and it
stayed out; phase 4, still out.

```
PHASE 1 — coil commanded ENERGISED     pin: 26: op -- pn | hi   LED1: ON
PHASE 2 — holder SIGKILLed (dead)      pin: 26: op -- pn | hi   LED1: STAYED ON
PHASE 3 — claimed input, NO pull       pin: 26: ip    pn | lo   LED1: WENT OUT, stayed out
PHASE 4 — claim freed                  pin: 26: ip    pn | lo   LED1: still out
```

**A neutral no-pull input claim cleared the driving pad and de-energised the
coil on this platform and wiring.** That is the supervisor mechanism
demonstrated end to end with nothing derived from the zone's asserted polarity
— and it is the distinction between application-process loss, where the kernel
and a supervisor remain available, and a kernel failure, where nothing does.
Whether neutral reclamation clears the pad on another platform is a
qualification question, not an assumption.

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
