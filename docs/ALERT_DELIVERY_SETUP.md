# Alert Delivery Setup

How to provision real SMS and WhatsApp credentials, and how to prove an alert
actually reached a phone.

Ori is an agent that acts. Two of its Tier A actions are "tell a human". Until a
message has landed on a real handset from a real account, that half of the
product is unproven no matter how green the suite is.

---

## Before anything: which account owns this

Register both providers to a **role address on the company domain** — something
like `alerts@` or `ops@` — not to an individual's mailbox.

These accounts hold billing, API keys, and the sender identity customers will
see. An account tied to one person's address cannot be handed over, cannot be
recovered when that person is unavailable, and mixes personal identity into a
production credential. Create the alias first if it does not exist; everything
below assumes it.

Enable multi-factor authentication on both accounts at creation, before any key
exists to steal.

---

## 1. Africa's Talking — SMS, the primary channel for Nigeria

The runtime reads three variables:

| Variable | Meaning | Default |
| --- | --- | --- |
| `AT_API_KEY` | API key from the dashboard | none — required |
| `AT_USERNAME` | Account username | `sandbox` |
| `AT_SENDER_ID` | Alphanumeric sender shown to the recipient | `ORI` |

### Sandbox first (same day)

1. Create the account on the role address and verify it.
2. Use the **sandbox** application. Its username is literally `sandbox`.
3. Generate an API key for the sandbox app.
4. Add the destination handset to the sandbox's allowed test numbers. Sandbox
   will only deliver to numbers you have registered.
5. Set `AT_USERNAME=sandbox`, `AT_API_KEY=<key>`, and leave `AT_SENDER_ID`
   unset — sandbox delivers from a shared shortcode and ignores custom senders.

Sandbox proves the wiring: credentials, SDK initialisation, the send path, and
the runtime's own failover logic. It does **not** prove sender identity or
production deliverability.

### Live (start now — this is the long pole)

1. Create a **live application** in the same account and generate its own API
   key. The live key is not the sandbox key.
2. Top up credit. Nigerian routes are billed per message part; a long reasoned
   alert is several parts.
3. **Register the alphanumeric sender ID.** This is the step with real lead
   time. Nigerian networks require sender IDs to be registered and approved
   before alphanumeric senders are delivered, and unregistered senders are
   commonly dropped or rewritten. Submit `ORI` (or the chosen sender) as early
   as possible and expect the approval to take days to weeks, not hours.
4. Once approved, set `AT_USERNAME` to the live application username and
   `AT_SENDER_ID` to the approved sender.

**Plan the freeze around step 3.** If the sender ID is not approved in time, the
demo can still run on sandbox or on a numeric sender, but the message will not
carry the brand identity. Decide which of those is acceptable rather than
discovering it on the day.

---

## 2. Twilio — WhatsApp

The runtime's WhatsApp backend is Twilio. It reads:

| Variable | Meaning |
| --- | --- |
| `TWILIO_ACCOUNT_SID` | Account SID |
| `TWILIO_AUTH_TOKEN` | Auth token |
| `TWILIO_WHATSAPP_FROM` | Sending address, in the form `whatsapp:+14155238886` |

`TWILIO_WHATSAPP_FROM` **must** start with `whatsapp:+`. The provider logs an
error and disables delivery otherwise, rather than sending to a bare number.

### Sandbox first (same day)

1. Create the Twilio account on the role address and verify it.
2. Open the WhatsApp sandbox. It gives a shared sending number and a join
   phrase.
3. From each recipient handset, send the join phrase to the sandbox number. A
   handset that has not joined will not receive anything.
4. Set the three variables, using the sandbox number as `TWILIO_WHATSAPP_FROM`.

### Approved business templates

Read this before planning any WhatsApp-first demo.

WhatsApp separates **business-initiated** messages from replies inside a
customer-service window. An Ori alert is business-initiated: nobody messaged us
first. Outside a 24-hour window opened by the recipient's own message, a
business-initiated WhatsApp message must use a **pre-approved template** —
fixed wording with variable placeholders, submitted to Meta for review.

The runtime has four closed business-initiated intents. Each always uses an
approved template, even when a provider-side session window may happen to be
open. That window is remote state the runtime cannot safely infer after a
restart, a missed inbound poll, or a second device.

| Intent | Ordered variables and maximum lengths |
| --- | --- |
| `startup` | site (80), connected sensor count (4), active rule count (4) |
| `tier_a_alert` | configured-risk category (64), site (80), timestamp (32) |
| `tier_c_approval` | proposed action (64), site (80), timestamp (32), proposal ID (16), timeout seconds (8) |
| `tier_c_escalation` | proposal ID (16), site (80), timestamp (32), safe-default outcome (16) |

Template wording must be purpose-specific and fixed around those fields. Do not
submit a template such as `ORI ALERT — {{1}}`: carrying arbitrary model output
in one variable recreates the free-form path inside a nominal template. The
detailed reasoning remains in SMS and the audit/dashboard surfaces.

Free-form WhatsApp is restricted to a reply directly caused by an inbound
message that the runtime has recorded, addressed back to that sender, and still
inside the 24-hour window. Such a reply is never placed in the durable outbox;
if the recorded window expires, the runtime refuses it rather than guessing.

### Production WhatsApp (long lead time)

Business verification with Meta, a WhatsApp Business Account, a dedicated sender
number, and four template approvals. Start it now if WhatsApp is meant to be a
launch channel; do not assume it can be compressed.

After approval, configure the provider Content SIDs by intent. All four are
required whenever WhatsApp is enabled, and configuration fails closed if one is
missing or is not an `HX` Content SID:

```yaml
actions:
  whatsapp:
    enabled: true
    to_number: "${OWNER_WHATSAPP_NUMBER}"
    templates:
      startup: "${TWILIO_CONTENT_SID_STARTUP}"
      tier_a_alert: "${TWILIO_CONTENT_SID_TIER_A_ALERT}"
      tier_c_approval: "${TWILIO_CONTENT_SID_TIER_C_APPROVAL}"
      tier_c_escalation: "${TWILIO_CONTENT_SID_TIER_C_ESCALATION}"
```

Content SIDs are deployment configuration, not literals in runtime code. Keep
the actual approved identifiers in the root-owned service environment alongside
the provider credentials.

---

## 3. Where the credentials live on a device

Never in `ori.yaml`. The config carries the *names* of environment variables and
the recipient numbers, not the secrets:

```yaml
actions:
  primary_alert_channel: sms
  sms:
    enabled: true
    to_number: "${OWNER_PHONE_NUMBER}"
  whatsapp:
    enabled: true
    to_number: "${OWNER_WHATSAPP_NUMBER}"
    templates:
      startup: "${TWILIO_CONTENT_SID_STARTUP}"
      tier_a_alert: "${TWILIO_CONTENT_SID_TIER_A_ALERT}"
      tier_c_approval: "${TWILIO_CONTENT_SID_TIER_C_APPROVAL}"
      tier_c_escalation: "${TWILIO_CONTENT_SID_TIER_C_ESCALATION}"
```

Secrets belong in the service environment file, readable only by the runtime
user, alongside the other runtime secrets. Rotate the provider keys on the same
schedule as everything else, and never commit a real key — the bench
configuration lives outside version control for this reason.

---

## 4. Proving it, rather than assuming it

A green suite proves the code calls the provider. It does not prove a message
arrived. The proof is a handset.

**Minimum evidence before v2.5.0 is called ready:**

1. A sandbox SMS lands on a registered handset.
2. Each of the four approved WhatsApp templates lands on a joined handset from
   the real sender; sandbox free-form acceptance does not prove this path.
3. A live SMS lands from the approved sender ID.
4. A Tier C approval message lands, the operator replies `YES-<proposal_id>`,
   and the runtime executes the approved action.
5. The failover path is exercised deliberately: break the primary channel's
   credentials and confirm the secondary carries the alert.
6. For each WhatsApp send, retain the provider message identifier and initial
   acceptance status, then a later `delivered` or `read` observation. Provider
   acceptance alone proves only that Twilio took custody, not that a handset
   received the message.

Item 5 matters more than it looks. `AlertFailoverSender` is the component that
decides an operator hears anything at all when a provider is down, and it has
never been exercised against two real providers failing for real reasons.

Redact recipient numbers and message content from retained evidence. Keep the
intent, provider message identifier, provider status, and observation times so
the acceptance-to-delivery transition remains reproducible.

---

## 5. The startup notification

`_setup_success_message` in `ori/runtime.py` sends a notification once the
runtime has connected sensors, loaded and registered skills, started background
services, completed reconciliation and reached normal health. Failed delivery
is queued in the durable alert outbox, so a provider outage does not block
startup.

The notification is deliberately limited to facts the runtime has established:

> Ori is online at Ikeja Office: 4 sensors connected and 3 rules active. Ori
> will notify you when it detects a configured risk. No safety cutoff is
> commissioned, so Ori can warn but cannot intervene.

"Rules active" means each counted rule belongs to a loaded skill that declares
at least one sensor type with a successfully connected adapter. A rule is
counted once even if several of its declared types are connected. This does not
mean its condition is currently true, that history is available, or that an
actuator exists.

The location is normalised and independently shortened when necessary so the
complete message stays within 320 characters. The fixed no-cutoff disclaimer is
never passed through general tail truncation.

Relay configuration, GPIO library availability and an adapter connection are
not evidence of a commissioned physical safety outcome, so none can strengthen
this wording. A positive intervention claim requires the separately reviewed
safety registry and commissioned actuator posture; until those exist, every
startup notification states that Ori can warn but cannot intervene.

Every boot with setup notifications enabled exercises the configured
exact-channel sender, its credentials and the durable queue-on-failure path.
Automatic channel failover is a separate path and must be tested deliberately.
