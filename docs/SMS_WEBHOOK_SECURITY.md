# SMS Webhook Security

Ori can receive inbound SMS webhooks for Tier C approvals and authenticated
remote commands, and Africa's Talking delivery reports for outbound-message
reconciliation. This path is security-sensitive because a forged inbound
message can look like an operator reply, and a forged report can invent handset
delivery or trigger retry, if deployment controls are weak.

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
- HMAC verification includes timestamp skew and nonce replay protection. A
  nonce is kept for `replay_ttl_seconds` from receipt, and also until its
  signing time plus the skew, whichever is later, since a request is accepted
  until then.
- Optional `allowed_source_cidrs` rejects disallowed peer IPs before auth,
  signature verification, or body parsing.
- Request bodies are capped at 64KB.
- Plain Tier C approval replies are accepted only from configured operator
  numbers (`operator_contact` and `secondary_contact`). With neither
  configured, no reply is accepted from anyone. A staging or production
  deployment, or one with `security.enforce_production_posture: true`, refuses
  to start with SMS or WhatsApp enabled and no `operator_contact`.
- A reply from any other number is refused before anything is stored. An
  accepted reply is at most 480 characters, refused rather than cut. Each
  configured number may leave 10 replies a minute (a burst of 5), and all of
  them together 30 a minute (a burst of 10). A refused sender spends none of
  that, so a sender outside the allowlist cannot use up an operator's turn; a
  spoofed configured number can, since the sender field is only as strong as
  the carrier (see below). Each number keeps at
  most 16 unread replies, the newest, and a reply older than the longest
  approval window plus ten minutes is removed, since no listener can read it.
- Before anything is read, each peer address is limited to 600 requests a
  minute. That protects the process's CPU, not the approval path: through a
  signing bridge every request arrives from one address, so this limit cannot
  tell an operator from a stranger. Per-sender limiting at the bridge
  (ori-gateway#138) is what keeps a flood from many senders off it.
- Structured remote commands use the separate `RemoteCommandVerifier`, including
  HMAC, replay protection, sender allowlisting, and command policy checks. They
  are verified before the approval allowlist, so a command-shaped message from
  any number is recorded as an attempt, may be answered with a rejection SMS,
  which spends SMS credit, and past the rejection limit records an incident and
  alerts the operator. The remote-command throttle bounds that; the approval
  limits below do not.

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

The signature header is `hmac-sha256:` and the lowercase hex HMAC-SHA256,
keyed by the shared secret, over the timestamp header's text, a LF, the nonce
header's text, a LF, and the raw body, each exactly as sent. The timestamp is
the signing time in Unix milliseconds as 1 to 16 ASCII digits, and the nonce,
when present, is 1 to 128 visible ASCII characters with no space. A header
outside that form is refused, never normalised, and each of these headers,
the token, `Authorization`, `Content-Type` and `Content-Length` may appear
once.

Configure Africa's Talking **Incoming Messages** and **Delivery Reports** URLs
to reach this bridge. The bridge must preserve the form or JSON fields and sign
the exact body it forwards. Delivery reports are matched only to a uniquely
accepted SMS by their provider `id`; unknown or ambiguous IDs cannot mutate the
outbox.

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
