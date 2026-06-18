# Ori Phone Termux Path

This document defines the phone-first Ori Energy wedge. The phone path is a
low-friction deployment profile for early African SME sites, not the final
hardware architecture for physical actuation.

## Product Boundary

The phone path turns a spare Android phone into an Ori edge runtime for Tier A
energy intelligence:

- read a USB serial energy meter through Android USB OTG;
- build a site-local baseline for power draw;
- detect sustained overdraw, sudden spikes, and unstable draw;
- send operator alerts and dashboard logs;
- export consented telemetry to ori-cloud for fleet intelligence.

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
`usb_serial` HAL reads the meter over the phone's USB port.

Customer-facing copy should say that the meter "connects to your phone's USB
port using a small adapter cable." Do not imply that the phone's charging port
directly senses the building's mains supply.

## Runtime Shape

Use `ori.yaml.phone.example` as the starting profile:

- `device.deployment_type: phone`;
- `sensors[].protocol: usb_serial`;
- `sensors[].type: usb_power` for a single plug-level phone starter sensor;
- `actions.relay.enabled: false`;
- `gateway.enabled: false` unless the phone is explicitly bridged to a local
  gateway.

The `energy-anomaly-detector` skill accepts `usb_power`, `usb_current`, and
`usb_voltage`. For `usb_power`, the hook treats the reading as watts and uses it
directly for cost projection. It does not reinterpret watts as amps.

## PWA Role

The PWA is an operator and commercial surface, not the sensing runtime. It can
show onboarding status, live site health, alerts, invoices, subscription state,
reports, and upgrade prompts from any modern phone, including iPhone.

The Android Termux runtime remains the edge execution path because browsers and
PWAs cannot reliably read USB serial meters, run offline background loops, or
enforce Ori's runtime safety model.

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
must not remain trapped on the handset. The runtime should export:

- normalized sensor readings at a cloud-controlled sampling rate;
- alert and action logs;
- baseline summaries and derived anomaly features;
- device health and sync status.

Sensitive historical exports must follow the runtime-gateway/cloud security
posture: authenticated envelopes, replay protection, and encryption for
business/audit history when gateway encryption is enabled.

## ori-cloud Requirements

ori-cloud needs explicit support for phone deployments:

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
- upgrade flow from Phone Starter to Certified Edge Node without losing the
  site's historical baseline.

The `/Users/adegneus/Ori-Platform/ori-energy` demo should be treated as the
product proxy for this flow: waitlist, onboarding, site health, alerts,
subscription state, and the Edge Node upgrade path.
