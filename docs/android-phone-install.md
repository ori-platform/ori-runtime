# Android Phone Install Guide

This guide is for early Phone Starter testing on a dedicated Android phone.
It is not the certified Edge Node path for physical actuation.

## Hardware

- Android phone dedicated to the runtime
- Stable charger or inverter-backed power socket for the phone
- Optional: second phone or laptop for SSH/support access

For USB/PZEM mode:

- Android phone with USB OTG support
- USB OTG adapter
- PZEM-004T or equivalent USB/Modbus energy meter

For WiFi inverter mode:

- qualified Growatt SolarmanV5 inverter dongle reachable on the local network,
  or
  Victron VenusOS MQTT reachable on the local network
- inverter connection details from the installer or owner

Deye, Sunsynk, Felicity, Solis, Sofar, and other inverter brands are product
targets, but they are not automatically covered by the Growatt example. Each
brand/model needs a verified local transport and register/topic map before it
is provisioned for a customer.

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

The runtime `usb_serial` adapter needs a serial byte stream. It supports direct
tty paths such as `/dev/ttyUSB0` or `/dev/ttyACM0`, and pyserial URLs such as
`socket://127.0.0.1:7000` when an approved Android USB-serial bridge exposes
the meter as a local TCP serial stream.

Check before trying to run Ori against the meter:

```sh
ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true
termux-usb -l
```

If `/dev/ttyUSB0` or `/dev/ttyACM0` appears and Termux can read it, configure
`ori.yaml` with that `device_path`.

If only `termux-usb -l` sees the meter, the phone is detecting the hardware but
Android is not exposing a serial tty. `termux-usb` gives access to a raw USB
device handle, not a serial stream the runtime can read directly. Use an
approved USB-serial bridge that exposes the meter on localhost and configure
`device_path` with its `socket://` URL. Do not present that phone as a working
USB runtime until one of these serial stream paths is confirmed.

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

Use the profile that matches the site:

```sh
cp ori.yaml.phone.example ori.yaml          # USB/PZEM
cp ori.yaml.phone.growatt.example ori.yaml  # qualified Growatt SolarmanV5
cp ori.yaml.phone.victron.example ori.yaml  # Victron VenusOS MQTT
```

Edit `ori.yaml`:

- set `device.id` to a stable phone/site identifier;
- set `actions.operator_contact`;
- for USB/PZEM, set `sensors[0].device_path` to the actual serial path, or to a
  pyserial URL such as `socket://127.0.0.1:7000`;
- for Growatt, set each inverter sensor `host` and `serial`;
- for Victron, set each inverter sensor `broker_host` and `portal_id`;
- keep `health_socket.path` under `/data/data/com.termux/files/home/.ori/`;
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

Run the doctor before starting the runtime:

```sh
ori-phone-doctor --config ori.yaml
```

For a fuller phone diagnostic on the Android device:

```sh
bash scripts/termux-phone-smoke.sh --config ori.yaml
```

Start the runtime:

```sh
termux-wake-lock
ori-runtime --config ori.yaml
```

## Customer Install From Signed Wheelhouse

Production phone installs must not resolve dependencies live from public package
registries. Build and transfer a signed phone wheelhouse:

```sh
ORI_WHEELHOUSE_TARGET=phone bash scripts/build-wheelhouse.sh          # USB/PZEM
ORI_WHEELHOUSE_TARGET=phone-growatt bash scripts/build-wheelhouse.sh  # Growatt
ORI_WHEELHOUSE_TARGET=phone-victron bash scripts/build-wheelhouse.sh  # Victron
```

The wheelhouse is platform-specific. A macOS or generic Linux build can prove
the script works, but do not ship that wheelhouse to an Android phone. Build the
production phone wheelhouse on Termux or a compatible trusted Android builder,
then sign and transfer it to the customer phone.

On a Termux builder, install build tooling before creating the wheelhouse:

```sh
pkg install -y python clang make pkg-config rust openssl libffi
python -m pip install --upgrade pip pip-tools wheel setuptools
ORI_WHEELHOUSE_TARGET=phone bash scripts/build-wheelhouse.sh
```

Use the matching `ORI_WHEELHOUSE_TARGET` for Growatt or Victron sites.

The phone target builds dependency wheels from hash-locked inputs instead of
forcing `--only-binary`, because several native packages may not publish
Android-compatible PyPI wheels. The wheelhouse will contain both:

- `requirements-phone.txt`, the source/build lockfile used to build the wheels;
- `requirements.txt`, the install lockfile generated from the actual wheel
  files in that wheelhouse.

On the phone:

```sh
export ORI_WHEELHOUSE_DIR="$HOME/ori-wheelhouse"
bash scripts/install-phone.sh
cp ori.yaml.phone.example ori.yaml
```

Edit the same site/device fields as the development install, then start:

```sh
bash scripts/termux-phone-smoke.sh --config ori.yaml
termux-wake-lock
ori-runtime --config ori.yaml
```

To validate the offline wheelhouse installation itself on a test phone, run:

```sh
export ORI_WHEELHOUSE_DIR="$HOME/ori-wheelhouse"
bash scripts/termux-phone-smoke.sh --install-wheelhouse --config ori.yaml
```

To prove the runtime can stay alive briefly without taking over the terminal
forever:

```sh
bash scripts/termux-phone-smoke.sh --config ori.yaml --runtime-startup-seconds 10
```

## Socket Bridge Simulator

If a physical USB energy meter is not available yet, validate the Android
runtime and socket bridge shape with the bundled PZEM simulator:

```sh
cd ~/ori
python scripts/pzem_socket_sim.py --port 7000 --power 850 > ~/pzem-sim.log 2>&1 &
echo $! > ~/pzem-sim.pid
```

Set the phone sensor path in `ori.yaml`:

```yaml
device_path: socket://127.0.0.1:7000
```

Then run:

```sh
bash scripts/termux-phone-smoke.sh --config ori.yaml --runtime-startup-seconds 10
cat ~/pzem-sim.log
```

The simulator log should show repeated requests for register `0x0012` when the
configured sensor type is `usb_power`. Stop it with:

```sh
kill "$(cat ~/pzem-sim.pid)"
```

This proves the Android phone can run Ori through the same `socket://` serial
bridge shape used by an approved USB-serial bridge. It does not prove physical
meter wiring, OTG compatibility, or deployment readiness by itself.

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
ori-phone-doctor --config ori.yaml
bash scripts/termux-phone-smoke.sh --config ori.yaml
ori-runtime --config ori.yaml
```

In the doctor output and runtime logs, confirm:

- `deployment_type=phone` is active;
- relay is disabled;
- USB readiness is either direct serial or an approved local serial bridge;
- telemetry API key environment variable is present if telemetry export is
  enabled;
- relay initialization is skipped;
- the `usb_serial` adapter connects;
- the `usb_serial` adapter logs either `transport=serial` for `/dev/ttyUSB*`
  and `/dev/ttyACM*`, or `transport=socket` for a local serial bridge;
- `sensor.reading` events appear for `usb_power`;
- telemetry export logs show successful POSTs when enabled;
- Tier A alerts still work if telemetry export is disabled or the backend is
  unreachable.

## Inverter Qualification Check

Before provisioning a WiFi inverter site, confirm the exact profile:

- brand and model, for example Growatt, Deye, Sunsynk, Felicity, Victron;
- firmware/logger type and logger serial;
- local network address or broker address;
- whether readings come from SolarmanV5, MQTT, Modbus TCP, Modbus RTU, or
  another local API;
- PV power, grid/import power, load power, battery SOC, and inverter status
  readings cross-checked against the vendor app or inverter display.

If the site uses Deye/Sunsynk/Felicity or another unqualified profile, do not
rename the Growatt profile and ship it. Use USB/PZEM mode for deployment, or
create a separate qualification branch with fixture captures and adapter tests.

## Unsupported USB Shape

The runtime cannot treat a raw `termux-usb` device handle as a serial meter by
itself. A raw Android USB Host handle still needs a USB-serial driver layer for
CDC ACM, CH340, CP210x, FTDI, or the adapter chipset in the onboarding kit. Use
a direct tty device or an approved bridge that presents a serial stream.
