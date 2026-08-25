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

### The constraint that shapes the product

Read this before planning any WhatsApp-first demo.

WhatsApp separates **business-initiated** messages from replies inside a
customer-service window. An Ori alert is business-initiated: nobody messaged us
first. Outside a 24-hour window opened by the recipient's own message, a
business-initiated WhatsApp message must use a **pre-approved template** —
fixed wording with variable placeholders, submitted to Meta for review.

Free-form text is exactly what an Ori alert is. The reasoning paragraph the
elevator produces cannot be sent as an arbitrary business-initiated WhatsApp
message.

Three ways to live with it, in order of honesty:

- **Use SMS as the primary channel.** Already the default, and the reason
  `actions.primary_alert_channel` defaults to `sms`. Africa's Talking imposes no
  template constraint, so a reasoned alert sends as written.
- **Approve a template with a free-text variable.** A template such as
  `ORI ALERT — {{1}}` with the reasoning as the variable satisfies review in
  many cases, but the fixed scaffolding is part of the approved content and
  variable length is bounded. Submit early; approval is not instant.
- **Rely on the 24-hour window.** Valid only for a conversation the operator
  started, such as a Tier C approval thread where they replied `YES-<id>`. Not
  usable for the first unsolicited alert.

For the Tier C approval workflow specifically, the operator's `YES`/`NO` reply
opens the window, so follow-up messages in that thread are unconstrained. It is
the *opening* message that needs the template.

### Production WhatsApp (long lead time)

Business verification with Meta, a WhatsApp Business Account, a dedicated sender
number, and template approval. Start it now if WhatsApp is meant to be a launch
channel; do not assume it can be compressed.

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
2. A sandbox WhatsApp message lands on a joined handset.
3. A live SMS lands from the approved sender ID.
4. A Tier C approval message lands, the operator replies `YES-<proposal_id>`,
   and the runtime executes the approved action.
5. The failover path is exercised deliberately: break the primary channel's
   credentials and confirm the secondary carries the alert.

Item 5 matters more than it looks. `AlertFailoverSender` is the component that
decides an operator hears anything at all when a provider is down, and it has
never been exercised against two real providers failing for real reasons.

---

## 5. The startup notification

This already exists. `_setup_success_message` in `ori/runtime.py` sends it once
the runtime has connected sensors, loaded skills, started background services,
completed reconciliation and reached normal health. Failed delivery is queued in
the durable alert outbox, so a provider outage delays nothing.

That makes it the cheapest continuous proof the alert path works: every boot
exercises the real provider, the real credentials and the failover decision.

### It currently claims more than it establishes

The message reads:

> Ori is now watching and protecting your site. {device_id} is monitoring
> {location} in {deployment} mode. Sensors connected: N; skills loaded: M.
> You will receive alerts here when Ori detects risk.

"Watching and protecting" is not supported by what the message counts. It
reports connected sensors and loaded skills. It does not establish that any
trigger is armed, that a relay is wired, or that a Tier D path can actuate.

A device with sensors and skills but no GPIO backend sends that sentence
unchanged. So does a device whose relay is unwired. The operator reads a promise
of intervention from a runtime that can, at most, warn.

A message that reports what actually loaded:

> Ori is online at Ikeja Office: 4 sensors connected, 3 skills loaded. Alert
> delivery is active. Ori will notify you when it detects a configured risk.

"Automatic safety intervention is armed" belongs in that message only when the
runtime has positively established the Tier D registry and a real actuator
posture — not inferred from a relay appearing in configuration, and not from
`gpiozero` importing, which an unarbitrated fallback also satisfies.

Until then the honest claim is notification, which is what the runtime can
actually keep.

