# Firmware MQTT Operator Service

The runtime owns firmware MQTT transport-identity issuance. Operator tools
connect to a local Unix socket; they never load the provisioning-authority
seed, client-CA private key, or runtime database.

## Security boundary

- The service is disabled by default.
- The socket has no world permissions and every connection is checked against
  an allowed peer-UID list using kernel-provided Unix peer credentials.
- The authenticated actor written into signed requests is derived by the
  runtime as `uid-<uid>`. A client cannot supply or override it.
- The provisioning-authority seed is loaded from the configured environment
  variable. If firmware command egress is also enabled, startup fails unless
  both features load the same seed.
- The client-CA key must be a regular, non-symlink file owned by root or the
  runtime user, with mode `0o600` or stricter.
- Signed requests and public certificate metadata are retained in
  `ori_state.db`; private key material is never stored in correlation records,
  responses, logs, or service JSON.

## Local contract

Each connection carries one newline-terminated JSON request and receives one
newline-terminated JSON response. The request limit is 32 KiB.

Every request includes:

```json
{
  "contract": "ori.runtime.firmware-mqtt-operator",
  "schema_version": 1,
  "operation": "create_csr"
}
```

Operations and additional fields:

| Operation | Fields |
|---|---|
| `create_csr` | `device_id`, `reason` |
| `prepare_install` | `correlation_id`, `response_b64`, `reason` |
| `verify_install_result` | `correlation_id`, `response_b64` |
| `revoke` | `device_id`, `reason` |
| `verify_revoke_result` | `correlation_id`, `response_b64` |
| `status` | `device_id`, `request_id` |
| `verify_status_response` | `correlation_id`, `response_b64` |

Requests are strict: extra, missing, duplicate, oversized, or incorrectly typed
fields are refused. Binary-exact signed firmware messages use canonical base64.
Success responses return `ok: true` and `result`; failures return `ok: false`
and a typed `error.code`.

Stable boundary errors include `authentication_failed`, `contract_mismatch`,
`version_mismatch`, `invalid_request`, `request_too_large`, `request_timeout`,
`unsupported_operation`, `stale_correlation`, `correlation_mismatch`,
`anchor_unknown`, `device_revoked`, `anchor_not_approved`,
`anchor_not_confirmed`, `anchor_changed`, `anchor_epoch_mismatch`,
`anchor_history_unprovable`, `invalid_device_key`, `device_response_mismatch`,
`malformed_response`, `bad_signature`, `device_response_refused`,
`invalid_certificate_material`,
`sequence_exhausted`, `provisioning_refused`, and `internal_error`.

`prepare_install` returns only a signed install message and public certificate
fingerprint, serial, and validity metadata. A verified install result is
diagnostic: `successful` is true only when its authenticated verdict is exactly
`accepted`.

Correlation records survive runtime restart and are single-use. Unknown,
completed, or wrong-operation handles fail closed. CSR consumption and install
request persistence are one SQLite transaction, so a restart cannot expose a
consumed CSR without its resulting signed install request.

This socket is an operator transport, not physical authority. MQTT client
authentication does not grant Layer 1 evidence trust or Tier B/C/D action
authority.
