# Synology NAS Alerts → Telegram

[![build](https://github.com/abgitdev/synology-nas-alerts/actions/workflows/build.yml/badge.svg)](https://github.com/abgitdev/synology-nas-alerts/actions/workflows/build.yml)
![version](https://img.shields.io/badge/version-1.0-blue)
![license](https://img.shields.io/github/license/abgitdev/synology-nas-alerts)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![platform](https://img.shields.io/badge/platform-Synology%20DSM-0b3d91)
![dependencies](https://img.shields.io/badge/dependencies-stdlib--only-success)
![notifications](https://img.shields.io/badge/notify-Telegram-26A5E4?logo=telegram&logoColor=white)
![last commit](https://img.shields.io/github/last-commit/abgitdev/synology-nas-alerts)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

Synology NAS monitoring scripts (tested on **DS124**) that send notifications to **Telegram** only.
No third-party dependencies — pure Python standard library. The only network call is HTTPS to Telegram.

Use this repo as an install base or as a restore backup: copy the files to
`/volume1/scripts/nas-alerts`, create a `.env` with your Telegram settings, and add tasks to the
DSM Task Scheduler.

## What the scripts do

- **`nas-health`** — nightly NAS health digest: CPU/disk temperatures, volume and disk usage,
  RAM/swap, uptime and load, disk SMART/status, local users, login sessions, failed logins over
  24 h (split into LAN vs external), UPS status and Tailscale.
- **`security-alert`** — alerts on new login sessions, SMB connections, and failed SSH attempts from
  **foreign** (external) IPs. Stays silent when there is nothing to report.
- **`ups-alert`** — UPS events: switch to battery, power restored, time on battery, remaining-runtime
  and battery-charge thresholds. Stays silent when there is nothing to report.
- **`notify.py`** — shared Telegram sender used by all three scripts.

## Layout

```
notify.py                 shared sender (imported by every digest.py)
nas-health/    digest.py  run.sh
security-alert/digest.py  run.sh
ups-alert/     digest.py  run.sh
docs/NAS_SETUP.md         short install cheatsheet
.env.example              configuration template
```

Each `digest.py` imports the shared `notify.py` from the parent folder and reads `.env` from the root
(plus an optional per-component `.env`). Telegram settings live in a single root `.env` that is
**never committed**.

## Requirements

- Synology DSM (tested on DS124), SSH access.
- Python 3.8+ (`/usr/bin/python3` on DSM).
- Tasks run **as `root`** — otherwise some system logs, UPS data, and DSM API calls are unavailable.

## Install

```sh
# 1. Copy the files to the NAS
mkdir -p /volume1/scripts/nas-alerts
# (copy notify.py and the nas-health/ security-alert/ ups-alert/ folders here)

# 2. Create .env from the template and fill it in
cp .env.example /volume1/scripts/nas-alerts/.env
chmod 600 /volume1/scripts/nas-alerts/.env
vi /volume1/scripts/nas-alerts/.env
```

> **Install location:** use a **root-owned** directory (e.g. under `/volume1/scripts`), not a
> share-writable folder. The scripts run as root and write `run.log`, `state.json`, and a lock
> directory next to themselves; a directory writable by other local users would expose minor
> symlink/lock races.

## Configuration (`.env`)

| Variable | Default | Script | Purpose |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | — | all | Bot token from @BotFather (**required**) |
| `TELEGRAM_CHAT_ID` | — | all | Recipient chat id (**required**) |
| `NOTIFY_CHANNELS` | `telegram` | all | Delivery channel (only `telegram` is supported) |
| `NOTIFY_TIMEOUT_SECONDS` | `20` | all | Telegram HTTP timeout (3–60) |
| `ALERT_WHITELIST_IPS` | — | security | Extra trusted IPs/machines (comma-separated) |
| `UPS_NAME` | `ups@localhost` | ups | UPS name for `upsc` |
| `UPSC_BIN` | auto-detect | ups | Explicit path to `upsc` |
| `DSM_UPS_STANDBY_MINUTES` | `15` | ups | Minutes until DSM enters safe standby |
| `UPS_OUTAGE_ALERT_MINUTES` | `5,10` | ups | Minutes for interim outage reminders |
| `VERBOSE` | `0` | security/ups | `1` prints `NO_ALERT` when there is no alert |

Additional knobs via the DSM task environment / `run.sh`: `PYTHON_BIN`, `TZ` (defaults to `UTC`),
`*_MAX_SECONDS` (run timeout), `*_BASE_DIR`.

## Schedule (DSM Task Scheduler)

Create the tasks **as user `root`**:

```text
nas-health      daily, 23:00
security-alert  daily, repeat every 5 minutes
ups-alert       daily, repeat every 10 minutes
```

Commands:

```sh
PYTHON_BIN=/usr/bin/python3 /bin/sh /volume1/scripts/nas-alerts/nas-health/run.sh
PYTHON_BIN=/usr/bin/python3 /bin/sh /volume1/scripts/nas-alerts/security-alert/run.sh
PYTHON_BIN=/usr/bin/python3 /bin/sh /volume1/scripts/nas-alerts/ups-alert/run.sh
```

## Checking it works

`nas-health` always sends a digest. `security-alert` and `ups-alert` stay silent without an alert —
use `--test-notify` to verify Telegram delivery:

```sh
/bin/sh /volume1/scripts/nas-alerts/security-alert/run.sh --test-notify
/bin/sh /volume1/scripts/nas-alerts/ups-alert/run.sh --test-notify
```

`--dry-run` prints the digest to stdout and sends **nothing** to Telegram (handy for debugging).

## Logs

Each script writes its own `run.log` next to itself (size-capped, rotated every 7 days).
`run.log`, `state.json`, and lock files are **never committed** — they are in `.gitignore`.

## Known limitations

- **Synology DSM only.** The scripts rely on Synology-specific tools and paths (`synowebapi`,
  `/usr/syno/...`, `smbstatus`, `upsc`, the DSM Log Center DB). On non-Synology systems they will run
  but most collectors return no data.
- **Run as `root`.** Without root, some system logs, the DSM API, and UPS data are unavailable.
- **Best-effort monitoring, not a security control.** These scripts *notify* you of events; they are
  not a replacement for a firewall, fail2ban, or antivirus.
- **Install into a root-owned directory** (not a share-writable folder) — see [Install](#install).
- **Detection edge cases in `security-alert`:**
  - Failed SSH attempts from IPv6 sources may be under-counted when mixed with trusted IPv4 failures
    in the same window (the IP matcher is IPv4-only).
  - A `who` / reverse-DNS hostname that embeds a private IPv4 (e.g. `host-10.0.0.1`) can be classified
    as trusted, which may suppress a login alert when `sshd UseDNS` is enabled. Mitigate by keeping
    `UseDNS no` and/or listing known hosts in `ALERT_WHITELIST_IPS`.

## Security

- Secrets (token, chat id) live only in the runtime `.env` (`chmod 600`), never in code.
- Python standard library only; the sole outbound call is HTTPS to `api.telegram.org` with
  certificate verification and a timeout.
- `subprocess` is always invoked with an argument list (no shell); the DSM Log Center DB query is
  parameterized and opened strictly read-only.

## License

[MIT](LICENSE).
