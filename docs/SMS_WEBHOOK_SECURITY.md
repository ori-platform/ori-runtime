# SMS Webhook Security

Ori can receive inbound SMS webhooks for Tier C approvals and authenticated
remote commands. This path is security-sensitive because a forged inbound
message can look like an operator reply if deployment controls are weak.

The runtime implements application-layer controls, but it cannot prove carrier
identity or provider network posture by itself. Public webhook deployments must
combine runtime checks with network controls.

## Runtime Controls

The runtime currently enforces these controls before an inbound SMS message can
influence approval or command handling:

- The webhook defaults to `127.0.0.1`, not a public bind address.
- The webhook accepts only `POST` on the configured path.
- Token authentication uses headers only; query-string token fallback is not
  supported.
- Optional HMAC verification signs the raw HTTP body before payload parsing.
- HMAC verification includes timestamp skew and nonce replay protection.
- Optional `allowed_source_cidrs` rejects disallowed peer IPs before auth,
  signature verification, or body parsing.
- Request bodies are capped at 64KB.
- Plain Tier C approval replies are accepted only from configured operator
  numbers (`operator_contact` and `secondary_contact`).
- Structured remote commands use the separate `RemoteCommandVerifier`, including
  HMAC, replay protection, sender allowlisting, and command policy checks.

## What Runtime Code Cannot Prove

Africa's Talking and other SMS providers pass a sender field reported through
carrier infrastructure. Runtime sender allowlisting checks that the inbound
payload claims to be from the configured operator number, but it cannot defeat
carrier-level sender spoofing by itself.

This is not a runtime bug. It is a boundary fact: carrier-origin authenticity is
outside the Python process. Deployments that expose a public webhook must add
network and signing controls before the payload reaches the runtime.

## Recommended Topologies

### 1. Local-Only Webhook

Use this for development and single-device setups where a local process forwards
provider webhooks to the runtime.

```yaml
actions:
  sms:
    incoming_webhook:
      enabled: true
      host: "127.0.0.1"
      token: "${ORI_SMS_WEBHOOK_TOKEN}"
      signature:
        mode: token_only
```

This is acceptable because the listener is loopback-only. Do not expose this
configuration to the public internet.

### 2. Signing Bridge In Front Of Runtime

Use this for production public webhook ingress. The provider calls a small
bridge or reverse proxy. The bridge verifies provider/network constraints, then
forwards the exact body to the runtime with Ori HMAC headers.

```text
Africa's Talking -> signing bridge/reverse proxy -> runtime localhost webhook
```

Runtime config:

```yaml
actions:
  sms:
    incoming_webhook:
      enabled: true
      host: "127.0.0.1"
      token: "${ORI_SMS_WEBHOOK_TOKEN}"
      signature:
        mode: token_and_hmac
        shared_secret: "${ORI_SMS_WEBHOOK_HMAC_SECRET}"
        signature_header: "x-ori-webhook-signature"
        timestamp_header: "x-ori-webhook-timestamp"
        nonce_header: "x-ori-webhook-nonce"
```

The bridge signs the raw body with `ORI_SMS_WEBHOOK_HMAC_SECRET`. The runtime
verifies HMAC before decoding JSON or form data.

### 3. Direct Public Runtime Webhook

Use this only when the upstream caller can generate Ori HMAC headers, for
example a managed API gateway or provider integration that supports raw-body
signing. Raw Africa's Talking webhooks do not provide Ori HMAC headers by
themselves, so the signing-bridge topology above is the normal production path.
Public direct ingress must use both HMAC and source CIDR allowlisting.

```yaml
actions:
  sms:
    incoming_webhook:
      enabled: true
      host: "0.0.0.0"
      allowed_source_cidrs:
        - "203.0.113.0/24"  # provider or reverse-proxy range
      token: "${ORI_SMS_WEBHOOK_TOKEN}"
      signature:
        mode: token_and_hmac
        shared_secret: "${ORI_SMS_WEBHOOK_HMAC_SECRET}"
```

This still does not prove carrier-level sender identity. It only constrains the
network origin and authenticates the HTTP body delivered to the runtime.

## Production Posture

When `device.deployment_profile: staging\|production` or
`security.enforce_production_posture: true` is enabled, non-loopback webhook
hosts must configure:

- `actions.sms.incoming_webhook.allowed_source_cidrs`
- `actions.sms.incoming_webhook.signature.mode: token_and_hmac` or
  `hmac_required`

`token_only` is forbidden for public production webhook ingress.

Outside production posture, the runtime emits startup warnings when a non-loopback
SMS webhook host uses `token_only` or omits source CIDR allowlisting. These are
warnings so development setups are not broken accidentally; they are not a
substitute for production posture.

## Non-Goals

- The runtime does not validate Africa's Talking account configuration.
- The runtime does not prove carrier-origin identity.
- The runtime does not maintain provider IP ranges automatically.
- The runtime does not replace firewall, reverse-proxy, or signing-bridge
  controls.
