# Android Phone Install Guide

This guide is for early Phone Starter testing on a dedicated Android phone.
It is not the certified Edge Node path for physical actuation.

## Hardware

- Android phone with USB OTG support
- USB OTG adapter
- PZEM-004T or equivalent USB/Modbus energy meter
- Stable charger or inverter-backed power socket for the phone
- Optional: second phone or laptop for SSH/support access

## Android Setup

Install Termux and optional add-ons from the same source:

- Termux
- Termux:API
- Termux:Boot, if restart recovery is needed

Do not mix Termux from one app store with add-ons from another. Android treats
them as different app identities and the add-ons may not work.

Then configure the phone as a dedicated runtime device:

```sh
pkg update
pkg install -y termux-api python git openssh
termux-wake-lock
```

In Android settings:

- disable battery optimization for Termux;
- allow Termux to run in the background;
- keep Termux's persistent notification enabled;
- enable auto-start for Termux on vendors that expose that setting.

## USB Readiness Gate

The current runtime `usb_serial` adapter expects a serial device path such as
`/dev/ttyUSB0`. Some rooted or permissive Android builds expose USB serial
meters this way. Many stock Android builds do not.

Check before trying to run Ori against the meter:

```sh
ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true
termux-usb -l
```

If `/dev/ttyUSB0` or `/dev/ttyACM0` appears and Termux can read it, configure
`ori.yaml` with that `device_path`.

If only `termux-usb -l` sees the meter, the phone is detecting the hardware but
the current runtime still needs a Termux USB Host adapter before direct meter
reads will work on that handset. Do not present that phone as a working USB
runtime until the adapter path is implemented and tested.

## Development Install From Source

Use this for your own early testing. Customer installs should use the signed
wheelhouse path below.

```sh
cd ~
git clone https://github.com/ori-platform/ori-runtime.git ori
cd ori
python -m pip install --upgrade pip
python -m pip install -e ".[runtime]"
cp ori.yaml.phone.example ori.yaml
```

Edit `ori.yaml`:

- set `device.id` to a stable phone/site identifier;
- set `actions.operator_contact`;
- set `sensors[0].device_path` to the actual serial path;
- keep `actions.relay.enabled: false`;
- keep `gateway.enabled: false` for phone-only testing.

After registering the device with the product backend, enable telemetry:

```sh
export ORI_ENERGY_DEVICE_API_KEY="device-api-key-from-apps-api"
```

Then set:

```yaml
telemetry_export:
  enabled: true
  endpoint: "https://api.ori.energy/runtime/telemetry"
  api_key_env: ORI_ENERGY_DEVICE_API_KEY
```

Start the runtime:

```sh
termux-wake-lock
ori-runtime --config ori.yaml
```

## Customer Install From Signed Wheelhouse

Production phone installs must not resolve dependencies live from public package
registries. Build and transfer a signed wheelhouse, then run:

```sh
export ORI_WHEELHOUSE_DIR="$HOME/ori-wheelhouse"
bash scripts/install-phone.sh
cp ori.yaml.phone.example ori.yaml
```

Edit the same site/device fields as the development install, then start:

```sh
termux-wake-lock
ori-runtime --config ori.yaml
```

## Termux:Boot Startup

Create a boot script only after manual runtime startup works.

```sh
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-ori.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd "$HOME/ori"
export ORI_ENERGY_DEVICE_API_KEY="set-this-through-support-provisioning"
ori-runtime --config ori.yaml >> "$HOME/ori-runtime.log" 2>&1
EOF
chmod +x ~/.termux/boot/start-ori.sh
```

For customer devices, provision secrets through the support/install flow rather
than typing them into a reusable script.

## Verification

Run these checks before calling a phone deployment usable:

```sh
python -c "import ori; print('imports ok')"
ori-runtime --config ori.yaml
```

In the runtime logs, confirm:

- `deployment_type=phone` is active;
- relay initialization is skipped;
- the `usb_serial` adapter connects;
- `sensor.reading` events appear for `usb_power`;
- telemetry export logs show successful POSTs when enabled;
- Tier A alerts still work if telemetry export is disabled or the backend is
  unreachable.

## Current Limitation

The runtime is ready for phones that expose the USB meter as a serial device
path. Stock Android devices that only expose the meter through Android's USB
Host permission flow need a dedicated Termux USB Host adapter before they can
read the meter directly. Treat this as the next hardware compatibility task for
the phone path.
