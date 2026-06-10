# Runtime-Gateway MQTT Security Hardening

Ori uses MQTT as the LAN transport between the runtime and the site gateway for:

- Tier 3 reasoning requests/responses
- Runtime-owned export requests/responses
- Sensor/adapter integrations that already speak MQTT

This document covers deployment hardening for the broker layer. It complements,
but does not replace, runtime-gateway HMAC envelopes.

## Security Model

Use layered controls:

1. **Payload authentication**: enable `gateway.auth` so reasoning/export
   envelopes are HMAC signed and replay-checked.
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
  tls:
    enabled: true
    ca_certfile: /etc/ori/certs/site-ca.crt
    certfile: ""
    keyfile: ""
    keyfile_password_env: ""
  auth:
    enabled: true
    shared_secret_env: GATEWAY_SHARED_SECRET
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

`ori/gateway/health` is a site-wide broadcast topic (not device-scoped).  All
runtimes at the site subscribe to it.  The gateway publishes to it every 30 s
(configurable).  When `gateway.auth.enabled: true`, the heartbeat payload must
carry a valid HMAC ``auth`` envelope verified by
``GatewayMessageAuthenticator.verify_broadcast``; unsigned heartbeats are
discarded with a WARNING.

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

A retained `ori/gateway/health` message would make a freshly-connected runtime
believe the gateway is alive based on a stale heartbeat, defeating the TTL-based
liveness window in ``CapabilityPostureTracker``.

The runtime already publishes gateway reasoning requests with `retain=false`,
and export responses use the MQTT library default (`retain=false`). Gateway
implementations must do the same. If the broker supports policy plugins that
deny retained publishes on `ori/+/reasoning/#` and `ori/+/export/#`, enable that
policy in production.

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

# Gateway for the same site/device.
user ori-gateway-site-a
topic read  ori/dev-01/reasoning/request
topic write ori/dev-01/reasoning/response
topic write ori/dev-01/export/request
topic read  ori/dev-01/export/response/+
topic write ori/gateway/health
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
- [ ] Runtime ACL includes `topic read ori/gateway/health`; gateway ACL includes
      `topic write ori/gateway/health`.
- [ ] Retained publishes are forbidden by client policy or broker policy on
      `ori/{device_id}/reasoning/*`, `ori/{device_id}/export/*`, and
      `ori/gateway/health` topics.
- [ ] `gateway.auth.enabled: true` in production.
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
