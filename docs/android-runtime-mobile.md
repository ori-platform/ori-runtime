# Android Runtime Mobile Payload

`ori-runtime-mobile` is the native Phone Starter substrate used by APK
provisioning. It is not the Ori Edge Node control runtime and it must not be
described as one.

The payload is a real Android ELF executable built per ABI:

- `arm64-v8a/libori_runtime_exec.so`
- `armeabi-v7a/libori_runtime_exec.so`
- `x86_64/libori_runtime_exec.so`

The `.so` filename is intentional. Android extracts native library entries into
the app's read-only `nativeLibraryDir`, which lets the APK launch the payload
without executing files from the writable app data directory.

## Authority Boundary

The mobile payload only accepts `device.deployment_type: phone`.

It can:

- verify the backend-generated signed runtime config;
- read PZEM-style USB meter data from an approved Android bridge;
- publish HMAC-signed `runtime.telemetry.v1` batches to the provisioning
  endpoint configured in `telemetry_export.endpoint`;
- report operational failure through process exit and stderr.

It must not:

- execute Tier C or Tier D physical actions;
- open Android USB devices directly;
- treat raw `termux-usb` handles as serial streams;
- hardcode provisioning URLs or device API keys.

## USB Bridge Contract

Android owns USB permission. The Java/Kotlin APK layer validates the bound USB
meter identity, opens the device, and exposes a local serial stream. The mobile
payload consumes that stream through a `socket://host:port` sensor path in the
signed config.

Example:

```yaml
device:
  deployment_type: phone

sensors:
  - id: phone-main-power
    type: usb_power
    protocol: usb_serial
    device_path: socket://127.0.0.1:7000
    poll_interval_ms: 2000

telemetry_export:
  enabled: true
  endpoint: "https://provisioning.example.invalid/runtime/telemetry"
  api_key_env: ORI_ENERGY_DEVICE_API_KEY
```

Direct `/dev/ttyUSB*` access remains a Termux/development path. The APK
provisioning path uses the bridge so Android's USB permission model stays
explicit.

## Build

Install Rust, Android NDK, and `cargo-ndk`, then run:

```sh
bash scripts/build-android-runtime-mobile.sh
```

The script writes payloads under `dist/android-runtime-payloads/` and prints the
environment variables expected by the Android release build.

The build uses Cargo's checked-in lockfile through `--locked`. Run
`python3 scripts/check_rust_supply_chain.py` before publishing payloads.
