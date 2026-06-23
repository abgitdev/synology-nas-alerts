# Synology DS124 Telegram Alerts — quick setup

All three scripts send notifications to Telegram only, via a shared file:

```sh
/volume1/scripts/nas-alerts/.env
```

It must contain:

```sh
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
NOTIFY_TIMEOUT_SECONDS=20
```

## DSM Task Scheduler

Tasks must run as `root`, otherwise some Synology system logs and UPS data are unavailable.

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

`nas-health` always sends a digest on each run.

`security-alert` and `ups-alert` stay silent when there is no alert. To test Telegram manually:

```sh
PYTHON_BIN=/usr/bin/python3 /bin/sh /volume1/scripts/nas-alerts/security-alert/run.sh --test-notify
PYTHON_BIN=/usr/bin/python3 /bin/sh /volume1/scripts/nas-alerts/ups-alert/run.sh --test-notify
```

## Logs

Each script writes its own log:

```text
/volume1/scripts/nas-alerts/nas-health/run.log
/volume1/scripts/nas-alerts/security-alert/run.log
/volume1/scripts/nas-alerts/ups-alert/run.log
```

`run.log` is size-capped. Old rotated logs are cleaned every 7 days on a normal run.

## UPS

`ups-alert` only reports UPS events. The safe transition of the NAS into Standby Mode is handled by
Synology DSM itself in:

```text
Control Panel > Hardware & Power > UPS
```
