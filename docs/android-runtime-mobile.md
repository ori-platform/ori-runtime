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
  endpoint configured in `telemetry_export.endpoint`, under
  `runtime-telemetry/v2`;
- report what it observed of each meter on the sensor-status route;
- report its export state on stderr, and exit only when start-up is refused
  (exit code 2). A failed upload is retained and retried; it never ends the
  process.

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
  api_key_env: ORI_DEVICE_API_KEY
```

## Sensor Status

A meter that stops answering produces no readings, and from outside the phone
silence cannot be told from a quiet meter or a dead network. So the payload
posts a signed `runtime.sensor_status.v1` snapshot of every declared sensor to
`telemetry_export.endpoint` with `/sensor-status` appended: whether its most
recent read succeeded, why not if it did not, when one last did, and how many
have failed since. A declared sensor this payload does not read is reported as
`never_read` with reason `not_configured`.

The first snapshot goes out after the first poll of every meter, then once per
`telemetry_export.flush_interval_s`, and when any sensor's state or reason
changes, but for a change no sooner than five seconds after the previous
snapshot and only if the receiver accepted that one. A meter that answers every
other poll therefore costs one snapshot per five seconds, and a receiver that
has not implemented the route one request per interval.

A snapshot is the state when it is taken, not a history. A stop that persists is
reported within five seconds of an accepted snapshot, or within one flush
interval of a discarded one; a stop shorter than that is not reported. For the
same reason, a meter that answers every other poll is usually reported as
`failing` by an interval snapshot, because a failed read lasts the whole timeout
and the snapshot tends to fall inside one; its `last_success_ms` shows that it
is still answering.

A read is bounded by `timeout_ms` for the answer itself; connecting to the
bridge and sending the request each have their own `timeout_ms` as well. A
bridge that holds a late answer and delivers it on the next connection would be
read as that request's answer: Modbus RTU carries no transaction id, and whether
the hosting application's bridge buffers that way is not yet measured.

Each failed read is classified by what the payload observed on the bridge
socket, never from an error message:

| What the payload observed | `reason` |
|---|---|
| The connection was refused, reset, or closed before any byte of an answer | `interface_absent` |
| The socket reported a permission error | `interface_denied` |
| No byte of an answer within the sensor's `timeout_ms` | `no_response` |
| Part of an answer by the timeout, a Modbus exception, or the wrong function, byte count or slave | `malformed_response` |
| A complete frame whose CRC does not match | `integrity_failed` |
| The target does not resolve | `not_configured` |

`timeout_ms` bounds the whole answer, not each byte of it, so a bridge trickling
bytes cannot hold the poll loop and every upload behind it for more than that.

Which physical fault produces which observation depends on how the hosting
application's bridge behaves, and that is not yet measured on a handset. The
expected mapping is that a meter without mains or at the wrong slave id is
`no_response`, an unplugged adapter is `interface_absent`, and a wrong baud rate
is `malformed_response` or `no_response` depending on whether noise arrives.
It holds only if the bridge keeps a silent meter's connection open until the
payload's timeout and stops listening when the adapter is detached. A USB
permission refusal inside the hosting application reaches the payload as
whatever the bridge then does with its socket, typically `interface_absent`;
`interface_denied` arises only from the socket itself.

Every snapshot also carries `export`: the readings the payload has delivered
(and of those, duplicates), declined, abandoned as unconfirmed, dropped and
refused since it started, and the readings it is holding now, queued and
retained. What a phone dropped or is still sitting on is therefore visible to
the receiver, not only in the payload's log. A count changing does not make a
snapshot due; the flush interval carries it.

A snapshot carries no error text, device path or key. It is not retained: any
answer other than acceptance discards it, and the next one supersedes it. The
recorded terminal refusal on this route suspends export on both routes.

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
`bash scripts/check_rust_supply_chain.sh` before publishing payloads.

A payload built this way is for development. It carries no signature and no
recorded provenance, and nothing downstream can establish which commit produced
it, so it must not be packaged into an application that reaches a customer.

## Obtaining a signed payload

A tagged release publishes each payload as separate assets beside the Linux and
Pi bundles, per `runtime-mobile/v2` in ori-specs:

```text
ori-runtime-<version>-android-arm64-v8a-api21.so
ori-runtime-<version>-android-armeabi-v7a-api21.so
ori-runtime-<version>-android-x86_64-api21.so
```

each with a `.signature.json` envelope and a `.sha256` checksum. The release
workflow builds them from the tagged commit with a pinned Rust toolchain,
`cargo-ndk` and NDK, strips them, and signs them in the one job that holds the
release signing credential and builds nothing. Every target is signed and
verified before the release is created, and a release that cannot build all
three fails rather than publishing a partial set.

Fetch and verify payloads from a tagged release in one step, naming the
release you selected and each ABI slot you are filling. Neither is read from the
envelope; they are what the envelope is checked against:

```sh
python3 scripts/verify_published_release.py \
  --version 2.5.0 \
  --android-target android-arm64-v8a-api21 \
  --workspace "$PWD/payloads"
```

It downloads each payload, its checksum and its envelope from the release
origin into the workspace, and runs the nine consumer checks against the
registry shipped in `ori/installer/android-payload-keys.json`. Exit status 0
means the files left in the workspace may be packaged; any refusal exits 2 and
names what refused. A payload already on disk is verified with
`scripts/verify-android-runtime-payload.py`, which takes the artifact, the
envelope, the version, the target and the registry.

Keep a downloaded file under its published name until verification has passed:
the name is part of what is checked, and `libori_runtime_exec.so` carries no
identity. A consumer that cannot verify a payload must fail its build rather
than package it with a warning, and must never substitute a stub or a previously
staged file for a missing one.

The payload registry pins the release signing key under its own key id and
purpose, `android_runtime_payload`. The same key signs the Linux bundles under a
different purpose, and a signature from one protocol never verifies under the
other. A registry holding a key whose seed the conformance corpus publishes is
refused at load.

The envelope's `stripped` is measured from the payload's section headers, not
taken from the build setting, and a release refuses to sign a payload that is
not stripped or whose Android note records an API level other than its target's.

Panic locations embed the absolute source path of every file they come from, and
stripping keeps them, so the build script remaps two prefixes and refuses to run
with `RUSTFLAGS` of the caller's:

- the Cargo registry, to `/cargo`;
- the toolchain sysroot's copy of the standard library, to `/rustc/<commit>` —
  the prefix rustc itself uses when `rust-src` is not installed. Without that,
  a machine with `rust-src` embeds its own home directory where a machine
  without it embeds rustc's canonical prefix, and the two digests could never
  agree for a reason that has nothing to do with the sources.

Each stripped payload is then checked for any remaining path under the build
machine's home directory, and a payload carrying one fails the build.

With that, the three payloads reproduce byte for byte across different source
directories, target directories and Cargo homes, and between a toolchain with
`rust-src` installed and one without, on one host. Every release rebuilds each
payload from a fresh copy of the tagged commit before staging anything and
fails if a digest does not reproduce, so a published digest has been produced
twice on the runner image that published it.

**Across host operating systems the digests differ, and pinning the toolchain
does not change that.** Measured on 2026-09-16 between macOS arm64 and the
release runner image (Ubuntu 24.04 x86_64), with the same pinned Rust
toolchain, `cargo-ndk` and NDK, every payload differed. The difference is not
arbitrary: the section inventory is identical and every section produced from
the crate's own data matches in size — `.rodata`, `.dynsym`, `.dynstr`, the
relocations, `.data` — while `.text` and the unwind tables (`.eh_frame`,
`.gcc_except_table`, and on 32-bit ARM `.ARM.exidx` and `.ARM.extab`) differ by
between 8 bytes and 2.3 KiB. That is where code from the NDK's prebuilt static
runtime libraries lands, and those prebuilts ship inside the host-specific NDK
download rather than being built from the pinned sources. Which build produced
a payload is therefore a property of the host operating system as well as of
the pinned versions.

What a digest means here follows from that: it identifies the bytes a release
published and reproduces on that runner image, and it is not a value another
machine can expect to arrive at independently. Verify a payload by its
signature and its published digest, not by rebuilding it elsewhere and
comparing.
