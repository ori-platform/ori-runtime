# Ori Phone Termux Path

This document defines the phone-first product provisioning wedge. The phone path is a
low-friction deployment profile for early African SME sites, not the final
hardware architecture for physical actuation.

## Product Boundary

The phone path turns a spare Android phone into an Ori edge runtime for Tier A
energy intelligence:

- read a USB serial energy meter through Android USB OTG;
- build a site-local baseline for power draw;
- detect sustained overdraw, sudden spikes, and unstable draw;
- send operator alerts and dashboard logs;
- export consented telemetry to the product provisioning backend for fleet
  intelligence and Gemini-powered reports.

The phone path does not provide certified relay control. Tier B/C physical
switching, load separation, generator/grid transfer, and equipment cutoffs
require a certified Ori Edge Node installation. Tier D safety semantics remain
inviolable, but a phone-only deployment has no direct relay authority unless a
separate certified actuator path is installed.

## Onboarding Kit

The basic phone onboarding kit contains:

- an Android phone with Termux installed, supplied by the customer or bundled by
  Ori;
- a PZEM-004T or equivalent USB/Modbus energy meter;
- a USB OTG adapter cable;
- a short setup card with the Ori install command and support contact.

The USB energy meter is the small sensor device. It measures voltage, current,
power, energy, frequency, and power factor in hardware. Termux does not install
software onto the meter; Termux runs the Ori runtime, and the runtime's
`usb_serial` HAL reads a serial stream exposed from the phone's USB port.

Customer-facing copy should say that the meter "connects to your phone's USB
port using a small adapter cable." Do not imply that the phone's charging port
directly senses the building's mains supply.

## Runtime Shape

Choose the phone profile that matches the site:

- `ori.yaml.phone.example` for USB/PZEM meter deployments;
- `ori.yaml.phone.growatt.example` for qualified Growatt SolarmanV5 WiFi/LAN
  inverter deployments;
- `ori.yaml.phone.victron.example` for Victron VenusOS MQTT deployments.

Use `ori.yaml.phone.example` as the USB starter profile:

- `device.deployment_type: phone`;
- `sensors[].protocol: usb_serial`;
- `sensors[].type: usb_power` for a single plug-level phone starter sensor;
- `sensors[].device_path: /dev/ttyUSB0` or `/dev/ttyACM0` for direct tty
  devices, or `socket://127.0.0.1:PORT` for an approved Android USB-serial
  bridge;
- `actions.relay.enabled: false`;
- `gateway.enabled: false` unless the phone is explicitly bridged to a local
  gateway.
- `telemetry_export.enabled: true` only after the phone has been registered and
  `ORI_ENERGY_DEVICE_API_KEY` has been provisioned in Termux.

Use the inverter profiles when the customer already has supported WiFi/LAN
inverter telemetry:

- Growatt SolarmanV5 requires `sensors[].protocol: growatt`, a local `host`,
  and the inverter dongle `serial`;
- Victron VenusOS requires `sensors[].protocol: victron`, a local MQTT
  `broker_host`, and `portal_id`;
- the Android phone must be on the same local network as the inverter or MQTT
  broker;
- no USB/PZEM meter is needed for these profiles, but the phone still remains
  non-actuating unless a certified actuator path exists.

SolarmanV5 is a transport, not a universal register map. Deye, Sunsynk,
Felicity, Solis, Sofar, GoodWe, Huawei, Sungrow, Axpert/Voltronic, and other
inverter families must pass model-specific qualification before Ori calls them
supported. A profile is not qualified until Ori has verified the local
transport, register addresses, signedness, scaling, units, and polling behavior
against the inverter's own display, official monitoring app, or an independent
PZEM/clamp reference. Run `ori-inverter-profile-doctor --vendor-targets` to see
the current target catalog without treating candidates as live support claims.

The `energy-anomaly-detector` skill accepts `usb_power`, `usb_current`, and
`usb_voltage`. For `usb_power`, the hook treats the reading as watts and uses it
directly for cost projection. It does not reinterpret watts as amps.

Follow [android-phone-install.md](android-phone-install.md) for the install and
USB readiness checklist.

Set `health_socket.path` to a Termux-writable path such as
`/data/data/com.termux/files/home/.ori/health.sock`. The Linux default
`/run/ori/health.sock` is not writable inside the Android app sandbox.

Phone wheelhouses are built from profile-specific lockfiles, not the broad
runtime lockfile. The base `phone` target keeps gateway MQTT, industrial
protocols, Pi GPIO packages, and PC process-control dependencies out of USB/PZEM
Android installs while preserving USB serial, telemetry export, runtime crypto,
and direct alert transports. Use `ORI_WHEELHOUSE_TARGET=phone-growatt` or
`ORI_WHEELHOUSE_TARGET=phone-victron` only when the site needs that inverter
profile. Build production phone wheelhouses on Termux or a compatible trusted
Android builder because Python wheels are platform-specific. The phone targets
build platform-local wheels from hash-locked inputs instead of forcing
binary-only downloads, since native dependencies may not publish
Android-compatible PyPI wheels. Inside the finished wheelhouse,
`requirements-phone.txt` records the base source/build lockfile,
`requirements-phone-growatt.txt` or `requirements-phone-victron.txt` records the
optional profile lockfile, and `requirements.txt` is generated from the actual
built wheels so offline phone installs can still use `--require-hashes`.

`termux-usb -l` is a readiness signal, not a runtime transport by itself. It can
show that Android sees the USB meter, but the runtime still needs the meter to
be presented as a serial stream through a tty path or approved local bridge.

The Android phone smoke has also validated the local bridge shape with a PZEM
socket simulator: `ori-runtime` connected to `socket://127.0.0.1:7000`, loaded
the phone profile, stayed alive, and issued repeated PZEM Modbus reads for the
`usb_power` register. This proves the Android runtime can consume an approved
local serial bridge. It does not replace a physical USB meter validation before activation.

Run this for phone readiness:

```sh
ori-phone-doctor --config ori.yaml
```

The doctor validates Termux command availability, USB readiness, phone-mode
config, relay disablement, signed-config posture, telemetry API-key presence
when enabled, and operator contact setup without starting the runtime loop.
For private APK/provisioned phones, `config.config_signature` should pass before
activation; an unsigned-config warning is only acceptable for assisted Termux
pilots.

Run this on the actual Android phone for end-to-end install readiness:

```sh
bash scripts/termux-phone-smoke.sh --config ori.yaml
```

Use `--install-wheelhouse` to validate the offline signed wheelhouse install
path, and `--runtime-startup-seconds 10` to confirm the runtime stays alive
briefly without leaving it running forever. The smoke script wraps the doctor
and adds Termux package, wheelhouse, import, USB snapshot, and optional runtime
startup checks.

## PWA Role

The PWA is an operator and commercial surface, not the sensing runtime. It can
show onboarding status, live site health, alerts, invoices, subscription state,
reports, and upgrade prompts from any modern phone, including iPhone.

The Android Termux runtime remains the edge execution path because browsers and
PWAs cannot reliably read USB serial meters, run offline background loops, or
enforce Ori's runtime safety model.

## Private Android APK Path

The private APK is the client-facing packaging layer for Phone Starter. It
does not change Ori's safety model; it wraps the same runtime capability behind
normal Android install and permission screens.

The APK must:

- be signed and distributed from the authenticated product provisioning flow
  after trial or Paystack activation;
- accept a short-lived provisioning token from the product backend;
- request USB Host permission for the approved meter or bridge;
- run as a foreground service with a persistent status notification;
- request wake-lock and battery-optimization exemptions explicitly;
- store runtime credentials in Android-protected app storage, not in a public
  config file or the APK bundle;
- keep `deployment_type: phone`, `gateway.enabled: false`, and relay
  entitlements disabled unless a separate certified actuator path exists;
- export telemetry through the existing HTTPS/HMAC runtime telemetry path;
- send alerts to `actions.operator_contact`, which is the client's normal
  operator phone, not necessarily the unattended Android gateway device.

The APK must not:

- enable Tier B/C relay actuation on a phone-only deployment;
- call Gemini, cloud LLMs, or any product backend in the Tier D safety path;
- silently bypass Android USB, notification, background, or battery prompts;
- embed long-lived client API keys or provisioning secrets in the APK;
- treat the client PWA phone as the same device as the unattended runtime
  phone.

The current Termux path is therefore the engineering and assisted-pilot proof.
The APK is the self-serve commercial installer that removes terminal setup
while preserving the runtime's actuation-trust boundaries.

Production provisioning should use one generic Ori Android Agent APK plus a
backend-generated runtime profile. The product provisioning flow asks what the
site has: USB/PZEM meter, Growatt SolarmanV5, Victron VenusOS, or an
unqualified inverter. After payment or trial activation, the backend issues a
short-lived provisioning token; the APK downloads the signed config for that
site instead of embedding customer-specific `ori.yaml` in the APK. The same
profile-generation service should later provision Pi and certified Ori Edge
Node deployments.

The runtime verifies backend-generated configs before loading them. Signed
configs carry a top-level `config_signature` block with
`schema: ori.config_signature.v1`, `signer_id`, `signed_at_ms`, and an
`ed25519:<base64>` signature. The signature covers the unexpanded YAML body, so
placeholders such as `${ORI_ENERGY_DEVICE_API_KEY}` can remain placeholders
until the APK/Termux environment supplies their values. The verification public
key must be provisioned outside the YAML through
`ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64` (or a trusted env name selected by the
launcher); do not put the public key itself in the config file. Private APK and
production launchers should set `ORI_CONFIG_REQUIRE_SIGNED=true` so a tampered
config cannot opt out by changing itself back to a development profile.

The runtime package also ships `ori-config-install` for APK and assisted
Termux provisioning. The APK may download the generated config itself and pass a
local file, or ask the installer to fetch an HTTPS config endpoint with a
short-lived bearer token from an environment variable:

```sh
export ORI_PROVISIONING_TOKEN="short-lived-token"
ori-config-install \
  --source https://api.ori.energy/runtime/config \
  --bearer-token-env ORI_PROVISIONING_TOKEN \
  --destination ori.yaml
```

`ori-config-install` uses the runtime's normal `Config.load()` path, requires a
verified `config_signature`, rejects non-HTTPS remote sources except explicit
loopback development, writes the destination atomically with `0600`
permissions, and does not persist the provisioning token. The product provisioning backend still owns
account creation, payment, token issuance, profile selection, and config
generation; this tool is only the runtime-side install boundary.

## Inverter Profile Qualification

This is the gate for adding hot Nigerian and sub-Saharan African inverter
brands without weakening runtime trust.

An inverter brand/model may be listed as a candidate when one of these is true:

- it exposes a local WiFi/LAN logger that can be scanned from the phone's local
  network;
- it exposes Modbus RTU/TCP, SolarmanV5, MQTT, or a documented local API;
- it can be read by an installer-supported bridge without cloud credentials.

It becomes an Ori-supported profile only after qualification:

1. Capture brand, model, firmware, logger type, logger serial, and wiring or
   LAN topology.
2. Prove local reachability from Android/Termux with `ping`, socket connection,
   MQTT subscription, Modbus scan, or the relevant adapter scan utility.
3. Read the smallest useful register/topic set: PV power, grid/import power,
   load power, battery SOC, battery voltage, and inverter status where
   available.
4. Compare every reading against the inverter screen, the vendor app, or an
   installer meter at the same timestamp.
5. Record register address/topic, register count, signedness, byte order,
   scale, unit, valid range, and unavailable/error behavior.
6. Add adapter fixtures and tests that prove decoding, unit mapping, and
   missing-data behavior.
7. Add a profile-specific `ori.yaml.phone.<brand>.example`, doctor dependency
   check, and wheelhouse target only after the above evidence exists.

Candidate priority for Nigeria and sub-Saharan Africa:

| Candidate | Likely integration route | Status |
| :-- | :-- | :-- |
| Growatt | SolarmanV5/logger path with Growatt register map | Bundled community-derived profile |
| Victron | VenusOS local MQTT | Dedicated local telemetry adapter path |
| Deye | SolarmanV5 or native Modbus with Deye register map | Bundled community-derived profile |
| Sunsynk/Sol-Ark | Likely Deye/Solarman-family path, model-dependent | Deye-family validation target |
| Felicity | Brand/model-specific logger or Modbus path | Needs qualification |
| Solis/Sofar/GoodWe/Huawei/Sungrow | Vendor-specific local API, logger, or Modbus path | Needs qualification |
| Axpert/Voltronic-style off-grid units | Serial/USB or RS485 protocol bridge | Needs qualification |

Until a candidate passes this checklist, the fallback deployable Phone Starter
path remains USB/PZEM metering because it gives Ori an independent measurement
surface that does not depend on inverter-brand support.

Use the offline profile doctor to inspect bundled maps or verify a captured raw
register sample before adding field evidence:

```sh
ori-inverter-profile-doctor --list
ori-inverter-profile-doctor --vendor-targets
ori-inverter-profile-doctor --profile deye_hybrid
ori-inverter-profile-doctor --profile deye_hybrid --decode deye_grid_power --raw 65136
```

This tool never opens a network connection and never writes inverter registers.

For future inverter commands, follow
[INVERTER_CONTROL_LADDER.md](INVERTER_CONTROL_LADDER.md). Current Phone Starter
profiles remain read/advisory only.
It only exercises the same decode path used by the runtime.

## Android Background Runtime

Android can stop unattended background work aggressively, especially on low-cost
devices with vendor battery managers. Early phone deployments must configure the
phone as a dedicated runtime device:

- run `termux-wake-lock` before starting Ori;
- disable battery optimization for Termux in Android settings;
- keep Termux's persistent notification enabled;
- use Termux:Boot or a support-run startup shortcut for restart recovery;
- keep the phone powered from a stable adapter or inverter-backed socket.

This is acceptable for Phone Starter monitoring and Tier A alerts. It is not the
durability boundary for certified actuation; physical control remains an Ori
Edge Node responsibility.

## Device Policy On Phone

The phone runtime uses the same DevicePolicy concept as Pi deployments:

- active trial or paid Starter Phone tier permits Tier A intelligence and
  telemetry export;
- expired subscription restricts non-safety business features such as premium
  reports, cloud sync, and advanced reasoning;
- Tier D safety behavior is never disabled by subscription state;
- relay entitlements are always false for phone-only deployments.

Phone deployments need a stable device identity from the cloud registration
flow. Reinstalling Termux must not silently create a fresh paid trial for the
same site. ori-cloud should bind the phone runtime to a site, account, and
hardware fingerprint where available, while still allowing support-led recovery
when a phone is replaced.

## Telemetry And Data Moat

The phone should keep local readings available offline, but consented telemetry
must not remain trapped on the handset. When `telemetry_export.enabled` is true,
the runtime posts HMAC-signed `runtime.telemetry.v1` batches over HTTPS to the
configured product backend endpoint. The runtime should export:

- normalized sensor readings at a cloud-controlled sampling rate;
- alert and action logs;
- baseline summaries and derived anomaly features;
- device health and sync status.

The first runtime implementation exports real `sensor.reading` events. Alert,
baseline, and health sync remain product-backend follow-up work. Telemetry
export is observational only; failed uploads must not affect local trigger
evaluation, Tier D semantics, or operator alerts.

Sensitive historical exports must follow the runtime-gateway/product security
posture: authenticated envelopes, replay protection, and encryption for
business/audit history when gateway encryption is enabled.

## Alerts On Phone

Phone Starter should keep direct SMS or WhatsApp alerts available as a local
runtime path. Product push notifications can be added through the PWA/backend,
but they depend on account sync, browser notification permissions, and internet
delivery. Direct runtime alerts remain the fallback when the product backend is
unavailable.

The Android device running Ori should be treated as a dedicated edge node. It
may sit near the meter, inverter, or distribution board and should not be
assumed to be the phone the owner carries. Customer messages go to
`actions.operator_contact` and optional secondary contacts.

For early deployments, configure at least one of:

- SMS via IP provider credentials when mobile data is reliable;
- WhatsApp via Twilio where approved;
- GSM modem path only for Edge Node or a supported Android USB modem setup.

## Product Backend Requirements

For early customer validation, the product provisioning backend (`ori-energy`
`apps/api`) is the real backend for phone deployments. `[Ori Cloud](https://github.com/ori-platform/ori-cloud)`
eventually absorbs these responsibilities, but the phone path should
not point to `apps/demo-api`.

The product backend needs explicit support for phone deployments:

- a `phone_starter` or equivalent subscription tier mapped to Tier A energy
  intelligence, no relay entitlement, and limited local/cloud reasoning;
- device registration that issues runtime credentials, records deployment type
  `phone`, and binds the runtime to account, site, and subscription;
- DevicePolicy generation for phone runtimes, including trial expiry,
  subscription status, telemetry allowance, report allowance, and relay
  prohibition;
- telemetry ingestion endpoints for phone runtime exports with consent, rate
  limits, idempotency, and offline backfill handling;
- a PWA dashboard that reads cloud state instead of talking directly to the USB
  meter;
- Gemini weekly report generation from real persisted telemetry;
- upgrade flow from Phone Starter to Certified Edge Node without losing the
  site's historical baseline.

`apps/demo-api` should remain a clearly marked scenario/demo backend for
development only. The frontend's committed default API base URL for the
phone path should target `apps/api`.
