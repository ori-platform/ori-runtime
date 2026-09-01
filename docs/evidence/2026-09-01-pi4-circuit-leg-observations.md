# 2026-09-01 — Pi 4 protected-circuit observations: five modes at the load

Same bench, same day, and a continuation of
`2026-09-01-pi4-gpio-controller-loss.md`: every observation there was made at
the coil (LED1, the relay board's channel indicator). This record adds a wired
load — a 5 V DC fan through the channel-1 contacts — and repeats or extends
the observations at the protected circuit itself, which is what
commissioned-safety claims are ultimately about.

Scope, stated up front: the coil is commanded through `RelayAction.acquire_at`,
the GPIO acquisition primitive invoked beneath
`CommissionedActuator.acquire_commanding` — process-loss and release behaviour
after acquisition, not binding verification or commissioned outcome
resolution. All LED and fan states are human-judged, observer-paced (each
phase halts on an Enter press until judged). One pin (GPIO26), one platform
(this Pi 4); portability is a qualification question.

## The load circuit

Added to the standing control-side wiring (GPIO26 → IN1, high-trigger,
`active_high: true`):

- supply → COM1, NO1 → fan red, fan black → ground; the fan's third
  (PWM/tach) wire taped, unconnected; NC1 empty
- the fan is polarised; the contact pair is a switch and its order is not

The supply arrangement changed twice during the day, and one of those changes
is itself a finding (the battery post-mortem below). Final topology: relay
DC+ → Pi pin 2 (5 V), contact feed COM1 → Pi pin 4 (5 V), DC− and fan return
on the bench ground rail, continuous to Pi pin 39. Powering coil and load
from the Pi's 5 V header is a bench-only topology, as the first record notes.

## 1. Process loss and neutral reclamation, at the circuit

`/home/ori/bench/circuit_gate1.py` — the first record's four phases, judged at
LED1 and the fan separately:

```python
"""First circuit-leg observation: gate1d's four phases, judged at the load.

LED1 shows the coil; the FAN is the protected circuit through COM1/NO1.
Nothing advances until Enter is pressed, so every judgement has an
unambiguous owner phase.
"""
import os, signal, subprocess, time

def pin() -> str:
    return subprocess.run(["pinctrl", "get", "26"], capture_output=True, text=True).stdout.strip()

def pause(msg: str) -> None:
    input(f"\n>>> {msg}\n>>> judge BOTH LED1 and the FAN, then press Enter... ")

env = dict(os.environ, PYTHONPATH="/home/ori/bench/src")
holder = subprocess.Popen(
    ["./venv/bin/python", "hold_energised.py"],
    cwd="/home/ori/bench", env=env, start_new_session=True,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(3)
print(f"PHASE 1 — coil commanded ENERGISED (holder pid {holder.pid})")
print(f"  pin: {pin()}")
pause("Expected: LED1 ON and the FAN SPINNING. Is the circuit live?")

os.kill(holder.pid, signal.SIGKILL)
holder.wait()
time.sleep(0.5)
print(f"\nPHASE 2 — holder SIGKILLed (confirmed dead: {holder.returncode is not None})")
print(f"  pin: {pin()}")
pause("Per the coil evidence both should have STAYED as they were. Did the fan keep spinning?")

import lgpio
h = lgpio.gpiochip_open(0)
lgpio.gpio_claim_input(h, 26, lgpio.SET_PULL_NONE)
time.sleep(0.3)
print(f"\nPHASE 3 — line claimed as input, NO pull (nothing chosen)")
print(f"  pin: {pin()}")
pause("THE QUESTION: did the FAN STOP at this claim, with LED1 out, and stay stopped?")

lgpio.gpio_free(h, 26)
lgpio.gpiochip_close(h)
time.sleep(0.3)
print(f"\nPHASE 4 — claim freed")
print(f"  pin: {pin()}")
pause("Both should still be off/stopped. Confirm, then done.")
print("\nReport the four phase judgements, LED1 and fan separately.")
```

Run as `ssh -t ori-pi '~/bench/circuit_gate1.sh'` (`cd /home/ori/bench && exec
./venv/bin/python circuit_gate1.py`). Captured output:

```
PHASE 1 — coil commanded ENERGISED (holder pid 1581)
  pin: 26: op -- pn | hi // GPIO26 = output
PHASE 2 — holder SIGKILLed (confirmed dead: True)
  pin: 26: op -- pn | hi // GPIO26 = output
PHASE 3 — line claimed as input, NO pull (nothing chosen)
  pin: 26: ip    pn | lo // GPIO26 = input
PHASE 4 — claim freed
  pin: 26: ip    pn | lo // GPIO26 = input
```

Judgements, per pause: phase 1, LED1 on and fan spinning; phase 2, both
stayed exactly as they were — **the dead process's load kept running on the
retained pad**; phase 3, LED1 out and fan stopped at the neutral no-pull
claim; phase 4, both still off.

That is the controller-loss finding and its recovery, both now observed at
the load. (The session paste also contained a coil-only `gate1d` run — stale
terminal scrollback from the earlier process, not a run of this session.)

## 2. Orderly release, at the circuit

`/home/ori/bench/circuit_gate2.py` — the runtime's own shutdown sequence,
in-process: `release()` drives the coil de-energised with the pin still an
output; `disconnect()` then surrenders the line to an undriven input.

```python
"""Orderly release observed at the circuit: the runtime's own shutdown path.

release() drives the coil de-energised with the pin still an output;
disconnect() then surrenders the line to an undriven input. Contrast case to
circuit_gate1's SIGKILL, where neither ran and the fan kept spinning.
"""
import asyncio, subprocess

def pin() -> str:
    return subprocess.run(["pinctrl", "get", "26"], capture_output=True, text=True).stdout.strip()

def pause(msg: str) -> None:
    input(f"\n>>> {msg}\n>>> judge BOTH LED1 and the FAN, then press Enter... ")

async def main() -> None:
    from ori.actions.relay import RelayAction
    relay = RelayAction()
    await relay.acquire_at(26, True, coil_state="energised")
    print(f"PHASE 1 — coil commanded ENERGISED, in this process")
    print(f"  pin: {pin()}")
    pause("Expected: LED1 ON and the FAN SPINNING.")

    ok = await relay.release()
    print(f"\nPHASE 2 — release() ran (returned {ok}): coil driven de-energised, pin still an output")
    print(f"  pin: {pin()}")
    pause("Expected: LED1 OUT and the FAN STOPPED, at the release.")

    await relay.disconnect()
    print(f"\nPHASE 3 — disconnect() ran: line surrendered to an undriven input")
    print(f"  pin: {pin()}")
    pause("Expected: both still off/stopped.")
    print("\nReport the three phase judgements, LED1 and fan separately.")

asyncio.run(main())
```

Captured output:

```
PHASE 1 — coil commanded ENERGISED, in this process
  pin: 26: op -- pn | hi // GPIO26 = output
PHASE 2 — release() ran (returned True): coil driven de-energised, pin still an output
  pin: 26: op -- pn | lo // GPIO26 = output
PHASE 3 — disconnect() ran: line surrendered to an undriven input
  pin: 26: ip    pn | lo // GPIO26 = input
```

Judgements: phase 1, LED1 on and fan spinning; phase 2, LED1 out and the fan
stopped at the release, with the pad a driven-low output exactly as the code
documents; phase 3, both still off after the surrender. The contrast with
section 1 is the point: the same process ending by its own release path stops
the load; ending by SIGKILL does not.

## 3. Startup, at the circuit — a platform observation, not a runtime one

With the load wired, a full `sudo reboot`: the fan never ran and never
twitched — not at power-on, not during kernel GPIO initialisation, not during
userspace bring-up. Repeated implicitly at every power-up of the day,
including cold boots with the bench supply switched on first: no twitch was
ever observed.

This is a whole-boot observation of the platform and installation. No runtime
revision, service status, binding state, GPIO acquisition or post-boot health
was recorded, so which layer is responsible for the quiet pad is unresolved,
and nothing here is evidence about the commissioned runtime's startup
command. The runtime-attributed startup observation remains to be made, with
that evidence captured alongside it.

## 4. Loss of coil power, at the circuit — observed once, then contaminated

For this mode the load's supply must survive the coil's loss, so the contact
feed was moved to Pi pin 2 while the coil stayed on the bench supply (an
MB102 breadboard module). `/home/ori/bench/circuit_gate3.py`:

```python
"""Loss of coil power, observed at the circuit — and what power restoration does.

The fan is now Pi-fed; the coil stays MB102-fed. Switching the MB102 off is
the loss-of-coil-power condition with the load's supply surviving it.
"""
import asyncio, subprocess

def pin() -> str:
    return subprocess.run(["pinctrl", "get", "26"], capture_output=True, text=True).stdout.strip()

def pause(msg: str) -> None:
    input(f"\n>>> {msg}\n>>> press Enter when you have judged... ")

async def main() -> None:
    from ori.actions.relay import RelayAction
    relay = RelayAction()
    await relay.acquire_at(26, True, coil_state="energised")
    print(f"PHASE 1 — coil commanded ENERGISED")
    print(f"  pin: {pin()}")
    pause("Expected: LED1 ON and the FAN SPINNING. Judge both.")

    pause("PHASE 2 — switch the MB102 OFF now, watching the fan AS you switch. "
          "Expected: fan stops and LED1 dies the moment coil power is lost. Judge both.")
    print(f"  pin after MB102 off: {pin()}")

    pause("PHASE 3 — switch the MB102 back ON now, watching the fan AS power returns. "
          "THE QUESTION: does the fan RESTART on its own, with no new command? Judge both.")
    print(f"  pin after MB102 on: {pin()}")

    ok = await relay.release()
    await relay.disconnect()
    print(f"\nPHASE 4 — release() (returned {ok}) then disconnect()")
    print(f"  pin: {pin()}")
    pause("Expected: both off/stopped. Confirm, then done.")
    print("\nReport the four phase judgements, LED1 and fan separately.")

asyncio.run(main())
```

**Run 1, phases 1–2 (valid in themselves).** Captured output:

```
PHASE 1 — coil commanded ENERGISED
  pin: 26: op -- pn | hi // GPIO26 = output
  pin after MB102 off: 26: op -- pn | hi // GPIO26 = output
  pin after MB102 on: 26: op -- pn | hi // GPIO26 = output
PHASE 4 — release() (returned True) then disconnect()
  pin: 26: ip    pn | lo // GPIO26 = input
```

(The script prints each phase's pin reading after the operator's Enter; the
phase-2 and phase-3 lines above are those post-judgement readings.)
Judgements: phase 1, LED1 on and fan spinning; phase 2, the bench supply
switched off — LED1 and the fan died at the switch, with the fan's own supply
alive and the pad still driving (`op -- pn | hi` above). Loss of coil power
opened the protected circuit.

**Everything after that is contaminated and discarded.** The operator
restored supply power out of phase order; from that moment the coil never
audibly pulled in again for the rest of the session, across two further full
runs and multiple power cycles, while LED1 kept lighting. The restoration
question — whether restored coil power re-closes the circuit against a
still-driving pad — was therefore not answered. One further run was aborted
by Ctrl-C at phase 1; the interpreter's cleanup released the line
(`ip pn | lo` afterwards), an orderly-release exit, not a pad-retention case.

## 5. The battery post-mortem

The failure in section 4 was diagnosed to the bench supply's source: a
Hi-Watt 6F22 carbon-zinc 9 V battery (a transistor-radio type, built for
tens of milliamps). Diagnostic ladder, in order:

- energise with the suspect supply: **LED1 lit with no click** — the channel
  indicator draws milliamps and lights on a sagging rail; only the click
  proves the coil pulled in. LED1 is not evidence of coil state.
- the fan connected straight to the supply rail: it spun, and the relay
  board's power LED visibly dimmed — the rail sagging under a ~0.2 A load.
- the same dimming appeared under coil load alone (~70 mA) during energise,
  recovering to full brightness on release.

With coil and contact feed both moved to the Pi's 5 V header pins and the
battery-fed supply idle, the full orderly-release run repeated cleanly —
click, LED1, fan spinning, all stopping at release. That A/B result
vindicates the relay, contacts, fan and wiring, and establishes that the
battery-fed MB102 supply path had become inadequate under load. The battery
is the leading cause — the sag was visible under both fan and coil loads,
and a carbon-zinc 6F22 is a tens-of-milliamps part — but battery, regulator
and their wiring left service together, so the battery alone was not
isolated. The clean rerun of section 4, and its restoration question, wait
on a supply that can actually deliver the coil current and is not the Pi's
own rail.

## 6. Reset from an energised coil, at the circuit

The first record's two `sysrq-b` resets also began with the holder running
and LED1 on; what this run adds is the wired load, not the starting coil
state. Both supplies sat on the Pi's 5 V header, which was expected to remain
powered across a `sysrq-b` (the SoC resets; the board's 5 V rail is not
switched by it) — expected from topology, not measured: no rail measurement
or continuous power-indicator observation was recorded during the reset.

```
❯ ssh ori-pi '~/bench/hold_detached.sh'
holder started, pid 1557
26: op -- pn | hi // GPIO26 = output
❯ ssh ori-pi 'echo b | sudo tee /proc/sysrq-trigger'
b
Read from remote host 192.168.0.104: Connection reset by peer
❯ ssh ori-pi 'pinctrl get 26'
26: ip    pd | lo // GPIO26 = input
```

(`hold_detached.sh` runs `hold_energised.py` under `setsid nohup` so the
holder survives the ssh session; the sysrq mask on this system is 438, which
permits the reset.)

Judgement: LED1 and the fan were on before the trigger; both stopped **at the
instant of reset** and stayed stopped through the entire boot. Post-boot pad:
the boot-default undriven input. On the topology argument above, the pad
resetting is the supported explanation for the de-energisation; it is not
independently isolated proof, since supply continuity through the reset was
inferred rather than observed.

## What this record does and does not establish

Observed at the protected circuit on this platform and wiring:
energise/normal, application-process loss (retention and neutral
reclamation), orderly release (both stages), startup (as a whole-boot
platform observation), and one reset class from an energised coil (with
supply continuity inferred from topology, not observed). Loss of coil power was observed once at the circuit
and needs a clean repetition; the power-restoration behaviour against a
driving pad is unobserved. Threshold crossing, latched trip and manual reset
are runtime trip-path behaviours and are not bench-observable until that path
drives this rig. Kernel failure and genuine watchdog expiry remain untested,
as in the first record.
