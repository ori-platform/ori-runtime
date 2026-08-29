# Runtime-Gateway MQTT Security Hardening

Ori uses MQTT as the LAN transport between the runtime and the site gateway for:

- Tier 3 reasoning requests/responses
- Runtime-owned export requests/responses
- Sensor/adapter integrations that already speak MQTT

This document covers deployment hardening for the broker layer. It complements,
but does not replace, runtime-gateway HMAC envelopes.

## Where the broker runs

The runtime and the gateway normally run on the **same device**. The gateway is
the site coordinator for every Ori deployment at that site; `ori-cloud` is the
fleet coordinator across sites. So a site has one coordinator device, and the
broker runs there.

That produces two client positions with different requirements:

| | Broker reached over | Requirements |
|---|---|---|
| Coordinator device | loopback (`mqtt://127.0.0.1:1883`) | HMAC auth **and** payload encryption |
| Other devices at the site | site LAN | the above, **plus** TLS and a declared `broker_posture` |

Production posture requires `gateway.auth.enabled` and
`gateway.encryption.enabled` for **every** enabled broker, loopback included.
Co-location removes the network attacker, not the local-process one — any
process on the device can reach a loopback listener, so payload protections
still carry the weight. TLS and declared broker posture relax on loopback
because there is no wire to intercept.

**The broker is operator-managed infrastructure.** The runtime does not install,
start, or supervise one, and the installer will not: an MQTT broker is a shared
system component, and installing those is not the installer's authority to take.
A config declaring `gateway.enabled: true` asserts that a broker exists.
`ori doctor` reports whether one actually answers, as a warning rather than a
failure — a broker may legitimately start after the runtime, and gateway
reasoning is discretionary, since Tier D fires from the rule path regardless.

**The shared secret is supplied by the environment, never by the config.**
`gateway.auth.shared_secret_env` names a variable; the value belongs in the
service environment. A config that enables auth without that variable present
fails at runtime startup, so config generation and secret delivery have to land
together.

`ori doctor` reports the *configured variable name* and nothing more. It cannot
establish whether the secret was delivered: a system service reads its
environment from `/etc/ori/runtime.env` and a user service from
`~/.config/ori/runtime.env`, neither of which `ori doctor` inherits, so any
claim about presence would describe the caller rather than the service. Delivery
is enforced where it is observable — at runtime startup.

## Security Model

Use layered controls:

1. **Payload authentication**: enable `gateway.auth` so reasoning/export
   envelopes are HMAC signed and replay-checked. Seen envelope keys are
   persisted to the state database by default
   (`gateway.auth.persistent_replay_cache: true`), so a power cycle — an
   attacker-influenceable event on a physically accessible device — cannot
   reopen the replay window.
2. **Payload encryption**: enable `gateway.encryption` so sensitive runtime
   export responses are AES-GCM encrypted before the broker sees them.
3. **Broker authentication and ACLs**: require MQTT usernames/passwords and
   restrict each client to the smallest topic set it needs.
4. **Network isolation**: keep the broker on the site LAN/VLAN, never exposed to
   the public internet.
5. **TLS where practical**: use MQTT over TLS for deployments where certificate
   provisioning is operationally manageable.

Broker credentials authenticate a client to the broker. HMAC envelopes
authenticate the JSON message content end-to-end between runtime and gateway.
AES-GCM encryption hides sensitive export response bodies from a broker that can
observe routed messages. TLS encrypts the transport pipe. All are separate
controls; TLS is not a substitute for HMAC or payload encryption.

## Runtime Config

Production deployments should enable gateway message authentication:

```yaml
gateway:
  enabled: true
  broker_url: mqtts://ori-runtime:${ORI_RUNTIME_MQTT_PASSWORD}@192.168.1.10:8883
  broker_posture:
    deployment_check: required
    anonymous_access: disabled
    require_credentials: true
    acl_policy: per_device_required
  tls:
    enabled: true
    ca_certfile: /etc/ori/certs/site-ca.crt
    certfile: ""
    keyfile: ""
    keyfile_password_env: ""
  auth:
    enabled: true
    shared_secret_env: GATEWAY_SHARED_SECRET
    previous_shared_secret_env: ""
    max_clock_skew_ms: 300000
    replay_ttl_ms: 300000
  encryption:
    enabled: true
  reasoning:
    enabled: true
    timeout_ms: 10000
```

Store the actual secret in the runtime environment:

```bash
export GATEWAY_SHARED_SECRET='replace-with-site-local-random-secret'
```

Do not reuse remote-command secrets. `GATEWAY_SHARED_SECRET` is for site-local
runtime-gateway MQTT envelopes only.

`gateway.broker_posture` is a production declaration that the deployment has
disabled anonymous clients, requires per-device ACLs, and requires MQTT
credentials. It is not broker introspection; production operators must still
apply the Mosquitto configuration below or equivalent broker-side controls.

For gateway HMAC rotation, set `previous_shared_secret_env` to the old secret's
environment variable while `shared_secret_env` points at the new secret. The
runtime signs new outbound MQTT envelopes with the current secret only, but
accepts inbound envelopes signed with either current or previous. Remove
`previous_shared_secret_env` after the gateway and runtime are both confirmed on
the new secret.

`gateway.encryption.enabled` requires `gateway.auth.enabled`. The runtime derives
a separate AES-GCM key from `GATEWAY_SHARED_SECRET` with HKDF domain separation;
the raw HMAC key is not reused as the encryption key. Encryption currently
applies to sensitive export responses: `sensor_history`, `action_log`,
`reasoning_log`, and `tier_c_decision_log`. Health export responses remain
plaintext so basic operational posture can be inspected without decrypting
historical business/audit data.

## Topic Contract

For a runtime with `device_id=dev-01`, the gateway integration uses:

| Direction | Publisher | Subscriber | Topic |
| --- | --- | --- | --- |
| Reasoning request | runtime | gateway | `ori/dev-01/reasoning/request` |
| Reasoning response | gateway | runtime | `ori/dev-01/reasoning/response` |
| Export request | gateway | runtime | `ori/dev-01/export/request` |
| Export response | runtime | gateway | `ori/dev-01/export/response/+` |
| Gateway heartbeat | gateway | all runtimes | `ori/gateway/health` |
| Runtime node heartbeat | runtime | gateway | `ori/dev-01/runtime/heartbeat` |
| Tier C enrichment request | runtime | gateway | `ori/dev-01/tier_c/enrichment/request` |
| Tier C enrichment response | gateway | runtime | `ori/dev-01/tier_c/enrichment/response` |
| Evidence outbound carriage | runtime | gateway | `ori/dev-01/evidence/outbound` |
| Evidence outbound acknowledgement | gateway | runtime | `ori/dev-01/evidence/outbound/ack` |
| Evidence inbound delivery | gateway | runtime | `ori/dev-01/evidence/inbound` |
| Evidence inbound acknowledgement | runtime | gateway | `ori/dev-01/evidence/inbound/ack` |

`ori/gateway/health` is a site-wide broadcast topic (not device-scoped).  All
runtimes at the site subscribe to it.  The gateway publishes to it every 30 s
(configurable).  When `gateway.auth.enabled: true`, the heartbeat payload must
carry a valid HMAC ``auth`` envelope verified by
``GatewayMessageAuthenticator.verify_broadcast``; unsigned heartbeats are
discarded with a WARNING. Staging/production posture rejects auth-disabled
gateway brokers at config load — loopback included, since local processes can
still reach a loopback broker (development deployments get a WARNING) — so
hardened deployments never accept unsigned heartbeats.

`ori/{device_id}/runtime/heartbeat` is the runtime's device-scoped liveness
signal to the gateway. It is not sensor data and must not be routed through the
runtime EventBus. When `gateway.auth.enabled: true`, the runtime signs the
payload with the regular device-bound HMAC envelope using message type
`runtime.heartbeat`.

The Tier C enrichment topics carry the runtime-gateway HMAC envelope in both
directions when `gateway.auth.enabled: true` (`tier_c_enrichment_request`,
`tier_c_enrichment_response`); the gateway drops an unauthenticated request
before it reaches a provider, and a verified response remains advisory.

The evidence topics are different. The carriage payload on
`evidence/outbound` deliberately carries no HMAC envelope: every artifact in it
is already signed end to end by the device, so a carriage HMAC would prove
nothing a gateway holding that key could not forge. The two acknowledgement
topics and the inbound delivery topic do carry the envelope
(`evidence_outbound_ack`, `evidence_inbound`, `evidence_inbound_ack`), and
both sides use persistent MQTT sessions so a message published during a
restart is not lost. Broker ACLs are defence in depth on these topics, never
the authentication: each artifact is verified under its own key material.

Do not grant normal clients broad `#` wildcard access. Use exact topics where
possible and `+` only where the protocol requires a request ID segment.

## Retained Messages

Runtime-gateway request/response topics must never use retained MQTT messages.
Reasoning and export payloads are request-scoped and timestamped. A retained
`reasoning/response` or `export/response` can deliver stale data to a fresh
subscriber after reconnect and cause confusing or unsafe operator-facing
behavior.

Publishers must set `retain=false` for:

- `ori/{device_id}/reasoning/request`
- `ori/{device_id}/reasoning/response`
- `ori/{device_id}/export/request`
- `ori/{device_id}/export/response/{request_id}`
- `ori/gateway/health`
- `ori/{device_id}/runtime/heartbeat`
- `ori/{device_id}/tier_c/enrichment/request`
- `ori/{device_id}/tier_c/enrichment/response`
- `ori/{device_id}/evidence/outbound`
- `ori/{device_id}/evidence/outbound/ack`
- `ori/{device_id}/evidence/inbound`
- `ori/{device_id}/evidence/inbound/ack`

A retained enrichment response would present stale advisory text against a
later Tier C proposal, and a retained evidence artifact is a statement about a
moment replayed to a reconnecting client as a current one.

A retained `ori/gateway/health` message would make a freshly-connected runtime
believe the gateway is alive based on a stale heartbeat, defeating the TTL-based
liveness window in ``CapabilityPostureTracker``.
A retained runtime node heartbeat would make the gateway believe a runtime node
is alive after it has disconnected.

The runtime already publishes gateway reasoning requests with `retain=false`,
and export responses use the MQTT library default (`retain=false`). Gateway
implementations must do the same. If the broker supports policy plugins that
deny retained publishes on `ori/+/reasoning/#`, `ori/+/export/#`,
`ori/+/tier_c/#` and `ori/+/evidence/#`, enable that policy in production.

## Mosquitto Example

`/etc/mosquitto/conf.d/ori-site.conf`:

```conf
listener 1883 192.168.1.10
allow_anonymous false
password_file /etc/mosquitto/ori.passwd
acl_file /etc/mosquitto/ori.acl
persistence true
log_type error
log_type warning
log_type notice
```

Create separate users:

```bash
sudo mosquitto_passwd -c /etc/mosquitto/ori.passwd ori-runtime-dev-01
sudo mosquitto_passwd /etc/mosquitto/ori.passwd ori-gateway-site-a
sudo systemctl restart mosquitto
```

`/etc/mosquitto/ori.acl`:

```conf
# Runtime for device dev-01.
user ori-runtime-dev-01
topic write ori/dev-01/reasoning/request
topic read  ori/dev-01/reasoning/response
topic read  ori/dev-01/export/request
topic write ori/dev-01/export/response/+
topic read  ori/gateway/health
topic write ori/dev-01/runtime/heartbeat
topic write ori/dev-01/tier_c/enrichment/request
topic read  ori/dev-01/tier_c/enrichment/response
topic write ori/dev-01/evidence/outbound
topic read  ori/dev-01/evidence/outbound/ack
topic read  ori/dev-01/evidence/inbound
topic write ori/dev-01/evidence/inbound/ack

# Gateway for the same site/device.
user ori-gateway-site-a
topic read  ori/dev-01/reasoning/request
topic write ori/dev-01/reasoning/response
topic write ori/dev-01/export/request
topic read  ori/dev-01/export/response/+
topic write ori/gateway/health
topic read  ori/dev-01/runtime/heartbeat
topic read  ori/dev-01/tier_c/enrichment/request
topic write ori/dev-01/tier_c/enrichment/response
topic read  ori/dev-01/evidence/outbound
topic write ori/dev-01/evidence/outbound/ack
topic write ori/dev-01/evidence/inbound
topic read  ori/dev-01/evidence/inbound/ack
```

For a multi-device site, repeat the runtime block for each device and grant the
gateway only the device namespaces it is responsible for. Do not give the
gateway global `ori/#` access unless it is an explicitly trusted integration
environment.

## TLS Option

TLS protects MQTT transport confidentiality and prevents passive LAN sniffing.
It is defense-in-depth over HMAC, not a substitute for HMAC.

Example Mosquitto TLS listener:

```conf
listener 8883 192.168.1.10
allow_anonymous false
password_file /etc/mosquitto/ori.passwd
acl_file /etc/mosquitto/ori.acl
cafile /etc/mosquitto/certs/site-ca.crt
certfile /etc/mosquitto/certs/broker.crt
keyfile /etc/mosquitto/certs/broker.key
require_certificate false
```

Runtime MQTT adapter TLS options are available for sensor adapters. Runtime
gateway reasoning/export transport also supports `mqtts://` broker URLs and the
`gateway.tls` config block shown above.

## Deployment Checklist

- [ ] Broker listens only on the site LAN/VLAN address.
- [ ] `allow_anonymous false`.
- [ ] Runtime and gateway use separate MQTT users.
- [ ] ACLs grant only the exact `ori/{device_id}/...` topics needed.
- [ ] Runtime ACL includes `topic read ori/gateway/health` and
      `topic write ori/{device_id}/runtime/heartbeat`; gateway ACL includes
      `topic write ori/gateway/health` and
      `topic read ori/{device_id}/runtime/heartbeat`.
- [ ] Where Tier C enrichment or evidence is enabled, each side's ACL covers
      exactly its direction on `ori/{device_id}/tier_c/enrichment/*` and
      `ori/{device_id}/evidence/*` as listed above, and nothing wider.
- [ ] Retained publishes are forbidden by client policy or broker policy on
      `ori/{device_id}/reasoning/*`, `ori/{device_id}/export/*`, and
      heartbeat topics.
- [ ] `gateway.auth.enabled: true` for every gateway broker, loopback included.
- [ ] `GATEWAY_SHARED_SECRET` is unique per site and separate from remote-command
      secrets.
- [ ] Broker credentials and HMAC secret are provisioned outside git-tracked
      files.
- [ ] Broker logs are monitored for repeated rejected connections or ACL
      denials.

## Non-Goals

- MQTT messages must not mutate runtime config, policy, update intent, relay
  state, or actuator settings. Those paths remain under authenticated remote
  command handling.
- Tier D safety does not depend on MQTT, broker reachability, gateway reasoning,
  or cloud services.
- mTLS is not required for all deployments. It can be added for enterprise
  deployments with certificate lifecycle tooling, but HMAC + ACLs + network
  isolation are the baseline.
