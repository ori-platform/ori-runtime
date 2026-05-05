# Linux Setup Guide

This guide walks you through running Ori on a Linux machine (Ubuntu, Debian, Fedora, or any modern distro). No Raspberry Pi or external hardware is required — Ori's **pc-system-health** skill runs on any laptop using `psutil`.

---

## Prerequisites

- **Python 3.11+** — check with `python3 --version`
- **Git** — check with `git --version`
- **4GB+ RAM** — for running with a local SLM model (optional)
- **A Linux machine** — laptop, desktop, or server

No hardware wiring, no Raspberry Pi, no sensors needed for this setup.

---

## Step 1 — Clone and Install

```bash
# Clone the repository
git clone https://github.com/ori-platform/ori-runtime.git
cd ori-runtime

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip (required for modern editable installs)
pip install --upgrade pip

# One-command bootstrap (dependencies + git hooks + formatting)
bash scripts/bootstrap.sh

# Verify the installation works
pytest tests/ -v
python -c "import ori; print('imports ok')"
```

---

## Step 2 — Create Your Config File

Ori requires a config file named `ori.yaml` to start. This repository provides a minimal Linux-ready example:

```bash
cp ori.linux.yaml.example ori.yaml
```

Then edit `ori.yaml` and replace the placeholders:

| Field                        | What to put                  | Example           |
| ---------------------------- | ---------------------------- | ----------------- |
| `device.id`                  | Unique identifier, no spaces | `my-laptop-01`    |
| `device.name`                | Human-readable device name   | `My Linux Laptop` |
| `device.location`            | Your city and country        | `Lagos, Nigeria`  |
| `device.timezone`            | IANA timezone                | `Africa/Lagos`    |
| `skills[].config.owner_name` | Display name for alerts      | `My Linux Laptop` |

**All other fields have working defaults** — you do not need to change them to get started.

### Required Config Fields Reference

These fields are **required** by the runtime. Missing any of them will cause a `ConfigValidationError`:

| Field                        | Required | Type   | Description                                              |
| ---------------------------- | -------- | ------ | -------------------------------------------------------- |
| `device.id`                  | Yes      | string | Unique device identifier (no spaces)                     |
| `device.name`                | Yes      | string | Human-readable device name                               |
| `device.location`            | Yes      | string | Physical location (city, country)                        |
| `reasoning.default_tier`     | No       | string | Defaults to `rule` (`rule \| local \| gateway \| cloud`) |
| `reasoning.local_model`      | No       | string | GGUF model filename (only needed for `local` tier)       |
| `reasoning.model_path`       | No       | string | Directory containing GGUF models                         |
| `reasoning.offline_fallback` | No       | string | Defaults to `rule`                                       |

Optional but recommended:

| Field                           | Description                                     |
| ------------------------------- | ----------------------------------------------- |
| `actions.operator_contact`      | Phone number for Tier C approval requests       |
| `actions.primary_alert_channel` | `sms` (Africa's Talking) or `whatsapp` (Twilio) |

---

## Step 3 — (Optional) Download a Local SLM Model

For local LLM reasoning (Tier 2), download a GGUF model. The Qwen2.5 0.5B is the recommended starting point:

```bash
# Create models directory
mkdir -p /home/$USER/models

# Download the model
curl -L https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf \
  -o /home/$USER/models/qwen2.5-0.5b-instruct-q4_k_m.gguf
```

Then update your `ori.yaml`:

```yaml
reasoning:
  default_tier: local
  local_model: qwen2.5-0.5b-instruct-q4_k_m
  model_path: /home/$USER/models/
  offline_fallback: rule
```

> **macOS users:** use `/Users/$USER/models/` instead of `/home/$USER/models/`.

Install the llama-cpp-python runtime:

```bash
pip install --no-cache-dir llama-cpp-python
```

---

## Step 4 — Set Up Environment Variables (Optional)

If you want to enable alert channels (WhatsApp via Twilio or SMS via Africa's Talking), create a `.env` file:

```bash
cp .env.example .env
```

Edit `.env` and fill in your credentials:

```bash
# WhatsApp (Twilio)
TWILIO_ACCOUNT_SID=your_sid_here
TWILIO_AUTH_TOKEN=your_token_here
TWILIO_WHATSAPP_FROM=whatsapp:+14155238886

# SMS (Africa's Talking)
AT_API_KEY=your_api_key_here
AT_USERNAME=your_username_here

# Operator phone number
OWNER_PHONE_NUMBER=+234XXXXXXXXXX
```

Then set `ORI_AUTOLOAD_DOTENV=true` before starting Ori so it picks up the `.env` file automatically:

```bash
export ORI_AUTOLOAD_DOTENV=true
```

---

## Step 5 — Start Ori

```bash
# Start the runtime
python -m ori.runtime --config ori.yaml
```

You should see output like:

```bash
[ori] Ori runtime starting...
[ori] Loaded skill: pc-system-health v0.1.0
[ori] Sensor system-cpu polling at 5000ms
[ori] Sensor system-memory polling at 10000ms
[ori] Sensor system-temp polling at 10000ms
[ori] Runtime started. Monitoring active.
```

---

## Platform Notes

### Watchdog Permission Warning

You may see a warning like:

```md
WARNING: cannot open /dev/watchdog — Permission denied
```

This is **non-critical**. Access to `/dev/watchdog` is distro-dependent and usually controlled by the device's owning group:

```bash
# Option 1: Run with sudo (not recommended for development)
sudo python -m ori.runtime --config ori.yaml

# Option 2: Add your user to the watchdog device group (persistent)
WATCHDOG_GROUP="$(stat -c '%G' /dev/watchdog)"
sudo usermod -aG "$WATCHDOG_GROUP" "$USER"
# Then log out and back in

# Option 3: Ignore the warning — it does not affect runtime functionality
```

The default config has `external_watchdog.enabled: false`, so this warning only appears if you explicitly enable it.

### No Hardware Required

The `psutil` adapter reads CPU usage, memory, and temperature from the host OS. It works on every Linux machine — no GPIO, I2C, or serial hardware needed.

### Skipping Tests That Need Hardware

Hardware-dependent tests are automatically skipped on non-Raspberry-Pi platforms. If you want to be explicit:

```bash
pytest tests/ -v -m "not hardware"
```

---

## Troubleshooting

| Problem                                                                                 | Solution                                                                                                                 |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `FileNotFoundError: No such file or directory: 'ori.yaml'`                              | Run `cp ori.linux.yaml.example ori.yaml`                                                                                 |
| `ConfigValidationError: 'device.id' is required but missing`                            | Fill in all `device.*` fields in your `ori.yaml`                                                                         |
| `ConfigValidationError: 'device.name' is required but missing`                          | Add `name:` under `device:` in your `ori.yaml`                                                                           |
| `ConfigValidationError: 'device.location' is required but missing`                      | Add `location:` under `device:` in your `ori.yaml`                                                                       |
| `Environment variable not set: ${...}`                                                  | Set required vars in `.env` and export `ORI_AUTOLOAD_DOTENV=true`, or replace `${VAR}` with literal values in `ori.yaml` |
| `Failed to create llama_context`                                                        | Reinstall llama-cpp-python: `pip install --no-cache-dir --force-reinstall llama-cpp-python`                              |
| `ori-runtime: command not found`                                                        | Install entrypoint: `pip install -e .`, or use `python -m ori.runtime`                                                   |
| `operator_contact is not configured — Tier C approval requests will not reach operator` | This is a **warning**, not an error. Set `actions.operator_contact` in `ori.yaml` if you need Tier C approvals           |

---

## Next Steps

- Read [CONTRIBUTING.md](../CONTRIBUTING.md) to learn how to contribute
- Browse [open issues](https://github.com/ori-platform/ori-runtime/issues) for things to work on
- Explore [AGENTS.md](../AGENTS.md) for the five extension patterns
- Read [PRINCIPLES.md](../PRINCIPLES.md) for the design philosophy
