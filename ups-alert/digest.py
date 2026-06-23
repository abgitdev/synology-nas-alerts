#!/usr/bin/env python3
"""Synology UPS event and threshold notifier."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "state.json"
LOG_FILE = BASE_DIR / "run.log"
THRESHOLDS = [90, 60, 15, 5]
CHARGE_THRESHOLDS = [50, 25, 10, 5]
MAX_RUN_LOG_BYTES = 512 * 1024


class CollectError(RuntimeError):
    pass


sys.dont_write_bytecode = True
sys.path.insert(0, str(BASE_DIR.parent))
from notify import NotifyError, load_env_file, send_messages  # noqa: E402

load_env_file(BASE_DIR.parent / ".env")
load_env_file(BASE_DIR / ".env")


def parse_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        log("ERROR", f"{name} must be a positive integer, using {default}")
        return default
    if value <= 0:
        log("ERROR", f"{name} must be greater than zero, using {default}")
        return default
    return value


def parse_int_list_env(name: str, default: str) -> list[int]:
    raw = os.environ.get(name, default).strip()
    values: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            value = int(item)
        except ValueError:
            log("ERROR", f"{name} contains invalid value {item!r}, skipping it")
            continue
        if value > 0:
            values.add(value)
    return sorted(values)


def dsm_standby_minutes() -> int:
    return parse_positive_int_env("DSM_UPS_STANDBY_MINUTES", 15)


def outage_alert_minutes() -> list[int]:
    configured = parse_int_list_env("UPS_OUTAGE_ALERT_MINUTES", "5,10")
    standby = dsm_standby_minutes()
    return [minute for minute in configured if minute < standby]


def log(level: str, message: str) -> None:
    from datetime import datetime

    line = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f" {level} {message}\n"
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_RUN_LOG_BYTES:
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.1"))
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line)
        LOG_FILE.chmod(0o660)
    except Exception:
        print(line, file=sys.stderr, end="", flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description="Synology UPS CLI monitor")
    parser.add_argument("--dry-run", action="store_true", help="Print only; do not notify or update state")
    parser.add_argument("--test-notify", action="store_true", help="Send a Telegram test message")
    return parser.parse_args()


def run(cmd: list[str], timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectError(f"timeout: {' '.join(cmd)}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise CollectError(f"command failed: {' '.join(cmd)} :: {stderr or exc.returncode}") from exc
    except OSError as exc:
        raise CollectError(f"command failed: {' '.join(cmd)} :: {exc}") from exc
    return result.stdout.strip()


def parse_key_value(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            out[key.strip()] = value.strip()
    return out


def upsc_commands() -> list[list[str]]:
    ups_name = os.environ.get("UPS_NAME", "ups@localhost").strip() or "ups@localhost"
    configured = os.environ.get("UPSC_BIN", "").strip()
    candidates = [configured] if configured else ["/usr/bin/upsc", "/bin/upsc", "/usr/local/bin/upsc"]
    found: list[str] = []
    for candidate in candidates:
        if candidate and Path(candidate).exists() and candidate not in found:
            found.append(candidate)
    path_candidate = shutil.which("upsc")
    if path_candidate and path_candidate not in found:
        found.append(path_candidate)
    return [[candidate, ups_name] for candidate in found]


def upsc_output() -> str:
    errors: list[str] = []
    commands = upsc_commands()
    if not commands:
        raise CollectError("upsc command not found")
    for cmd in commands:
        try:
            return run(cmd, timeout=10)
        except CollectError as exc:
            errors.append(str(exc))
    raise CollectError("; ".join(errors))


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {
            "last_mode": "unknown",
            "notified_thresholds": [],
            "notified_charge_thresholds": [],
            "battery_started_at": None,
            "notified_outage_minutes": [],
        }
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log("ERROR", f"state.json is invalid, starting fresh: {exc}")
        return {"last_mode": "unknown", "notified_thresholds": [], "notified_charge_thresholds": []}
    if not isinstance(data, dict):
        log("ERROR", "state.json must contain an object, starting fresh")
        return {"last_mode": "unknown", "notified_thresholds": [], "notified_charge_thresholds": []}
    data.setdefault("last_mode", "unknown")
    data.setdefault("notified_thresholds", [])
    data.setdefault("notified_charge_thresholds", [])
    data.setdefault("battery_started_at", None)
    data.setdefault("notified_outage_minutes", [])
    return data


def save_state(state: dict) -> None:
    temp_file = STATE_FILE.with_suffix(".json.tmp")
    temp_file.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temp_file.chmod(0o660)
    temp_file.replace(STATE_FILE)


def ensure_writable_base() -> None:
    probe = BASE_DIR / ".write-test"
    try:
        probe.write_text("ok\n", encoding="utf-8")
        probe.unlink()
    except Exception as exc:
        raise CollectError(f"script directory is not writable; run the DSM task as root: {exc}") from exc


def current_ups() -> dict[str, str]:
    raw = upsc_output()
    return parse_key_value(raw)


def parse_runtime_minutes(data: dict[str, str]) -> int | None:
    raw = data.get("battery.runtime")
    if not raw or not raw.isdigit():
        return None
    return int(raw) // 60


def parse_battery_charge(data: dict[str, str]) -> int | None:
    raw = data.get("battery.charge")
    if not raw or not raw.isdigit():
        return None
    return int(raw)


def ups_status_tokens(data: dict[str, str]) -> set[str]:
    return {token.strip().upper() for token in data.get("ups.status", "").split() if token.strip()}


def is_on_battery(data: dict[str, str]) -> bool:
    tokens = ups_status_tokens(data)
    return bool(tokens & {"OB", "LB", "FSD"})


def is_on_mains(data: dict[str, str]) -> bool:
    tokens = ups_status_tokens(data)
    return "OL" in tokens and not (tokens & {"OB", "LB", "FSD"})


def fmt_common(data: dict[str, str]) -> list[str]:
    battery = data.get("battery.charge", "?")
    runtime = parse_runtime_minutes(data)
    input_voltage = data.get("input.voltage", "?")
    model = data.get("ups.model") or data.get("device.model") or "UPS"
    status = data.get("ups.status", "unknown")

    lines = [f"UPS: {model}", f"UPS status: {status}", f"Charge: {battery}%"]
    if runtime is not None:
        lines.append(f"Approx. remaining: {runtime} min")
    if input_voltage not in {"", "?"}:
        lines.append(f"Input voltage: {input_voltage}V")
    return lines


def fmt_dsm_plan() -> list[str]:
    standby = dsm_standby_minutes()
    return [
        f"DSM plan: safe standby {standby} min after a power loss.",
        "The UPS battery estimate can lie, so the DSM timer matters more.",
    ]


def crossed_thresholds(runtime: int | None) -> list[int]:
    if runtime is None:
        return []
    return [threshold for threshold in THRESHOLDS if runtime <= threshold]


def crossed_charge_thresholds(charge: int | None) -> list[int]:
    if charge is None:
        return []
    return [threshold for threshold in CHARGE_THRESHOLDS if charge <= threshold]


def build_threshold_alert(data: dict[str, str], threshold: int, crossed: list[int] | None = None) -> str:
    runtime = parse_runtime_minutes(data)
    runtime_text = f"{runtime} min" if runtime is not None else "n/a"
    if crossed and len(crossed) > 1:
        crossed_text = ", ".join(str(item) for item in crossed)
        lines = [f"Warning: UPS crossed the {crossed_text} min thresholds."]
    else:
        lines = [f"Warning: UPS crossed the {threshold} min threshold."]
    lines.extend(fmt_common(data))
    lines.append(f"Actual runtime now: {runtime_text}")
    return "\n".join(lines)


def build_charge_alert(data: dict[str, str], threshold: int, crossed: list[int] | None = None) -> str:
    charge = parse_battery_charge(data)
    charge_text = f"{charge}%" if charge is not None else "n/a"
    if crossed and len(crossed) > 1:
        crossed_text = ", ".join(str(item) for item in crossed)
        lines = [f"Warning: UPS charge crossed the {crossed_text}% thresholds."]
    else:
        lines = [f"Warning: UPS charge dropped to the {threshold}% threshold."]
    lines.extend(fmt_common(data))
    lines.append(f"Actual charge now: {charge_text}")
    return "\n".join(lines)


def build_battery_alert(data: dict[str, str]) -> str:
    lines = ["Warning: Synology switched to UPS battery power."]
    lines.extend(fmt_dsm_plan())
    lines.extend(fmt_common(data))
    return "\n".join(lines)


def build_recovery_alert(data: dict[str, str]) -> str:
    lines = ["Power restored: Synology is running on mains again."]
    lines.extend(fmt_common(data))
    return "\n".join(lines)


def build_outage_elapsed_alert(data: dict[str, str], elapsed_minutes: int) -> str:
    standby = dsm_standby_minutes()
    remaining = max(standby - elapsed_minutes, 0)
    lines = [
        f"Power has been out for ~{elapsed_minutes} min.",
        f"DSM should enter safe standby {standby} min after a power loss.",
        f"Approx. {remaining} min left until standby.",
    ]
    lines.extend(fmt_common(data))
    return "\n".join(lines)


def build_messages(state: dict, data: dict[str, str]) -> tuple[list[str], dict]:
    battery_mode = is_on_battery(data)
    mains_mode = is_on_mains(data)
    runtime = parse_runtime_minutes(data)
    charge = parse_battery_charge(data)
    notified = set(int(item) for item in state.get("notified_thresholds", []) if str(item).isdigit())
    notified_charge = set(
        int(item) for item in state.get("notified_charge_thresholds", []) if str(item).isdigit()
    )
    notified_outage = set(
        int(item) for item in state.get("notified_outage_minutes", []) if str(item).isdigit()
    )

    messages: list[str] = []
    next_state = {
        "last_mode": state.get("last_mode", "unknown"),
        "notified_thresholds": sorted(notified, reverse=True),
        "notified_charge_thresholds": sorted(notified_charge, reverse=True),
        "battery_started_at": state.get("battery_started_at"),
        "notified_outage_minutes": sorted(notified_outage),
    }

    if battery_mode:
        first_seen_battery = state.get("last_mode") != "battery"
        now = int(time.time())
        started_at = state.get("battery_started_at")
        if not isinstance(started_at, int) or started_at <= 0 or first_seen_battery:
            started_at = now
        if first_seen_battery:
            messages.append(build_battery_alert(data))
            notified = set()
            notified_charge = set()
            notified_outage = set()
        elapsed_minutes = max((now - started_at) // 60, 0)
        new_outage_marks = [
            minute for minute in outage_alert_minutes()
            if elapsed_minutes >= minute and minute not in notified_outage
        ]
        if new_outage_marks:
            messages.append(build_outage_elapsed_alert(data, new_outage_marks[-1]))
            notified_outage.update(new_outage_marks)
        new_runtime_thresholds = [item for item in crossed_thresholds(runtime) if item not in notified]
        if new_runtime_thresholds:
            messages.append(
                build_threshold_alert(data, new_runtime_thresholds[-1], new_runtime_thresholds)
            )
            notified.update(new_runtime_thresholds)
        new_charge_thresholds = [item for item in crossed_charge_thresholds(charge) if item not in notified_charge]
        if new_charge_thresholds:
            messages.append(build_charge_alert(data, new_charge_thresholds[-1], new_charge_thresholds))
            notified_charge.update(new_charge_thresholds)

        next_state["last_mode"] = "battery"
        next_state["notified_thresholds"] = sorted(notified, reverse=True)
        next_state["notified_charge_thresholds"] = sorted(notified_charge, reverse=True)
        next_state["battery_started_at"] = started_at
        next_state["notified_outage_minutes"] = sorted(notified_outage)
        return messages, next_state

    if mains_mode:
        if state.get("last_mode") == "battery":
            messages.append(build_recovery_alert(data))
        next_state["last_mode"] = "mains"
        next_state["notified_thresholds"] = []
        next_state["notified_charge_thresholds"] = []
        next_state["battery_started_at"] = None
        next_state["notified_outage_minutes"] = []
        return messages, next_state

    if state.get("last_mode") == "battery":
        next_state["last_mode"] = "battery"
    else:
        next_state["last_mode"] = "unknown"
    next_state["notified_thresholds"] = sorted(notified, reverse=True)
    next_state["notified_charge_thresholds"] = sorted(notified_charge, reverse=True)
    next_state["notified_outage_minutes"] = sorted(notified_outage)
    return messages, next_state


def message_severity(messages: list[str], data: dict[str, str]) -> str:
    if is_on_battery(data):
        return "critical"
    if messages:
        return "warning"
    return "info"


def main() -> int:
    args = parse_args()
    try:
        if not args.dry_run:
            ensure_writable_base()
        if args.test_notify:
            log("INFO", "start notify_mode=telegram test_notify=true")
            send_messages(
                ["Telegram check for ups-alert. This is a test, not a real alert."],
                title="NAS: UPS alert test",
                severity="info",
                source="ups-alert",
                dry_run=args.dry_run,
            )
            log("OK", "test notification complete")
            return 0

        state = load_state()
        data = current_ups()
        messages, next_state = build_messages(state, data)

        log("INFO", f"start notify_mode=telegram alerts={len(messages)}")
        if not messages:
            if args.dry_run or os.environ.get("VERBOSE", "0") == "1":
                print("NO_ALERT")
                log("EMPTY", "no alerts")
            if not args.dry_run:
                save_state(next_state)
            return 0

        send_messages(
            messages,
            title="NAS: UPS power alert",
            severity=message_severity(messages, data),
            source="ups-alert",
            dry_run=args.dry_run,
        )
        if not args.dry_run:
            save_state(next_state)
        log("OK", f"notification complete alerts={len(messages)}")
        return 0

    except NotifyError as exc:
        log("ERROR", f"notify error: {exc}")
        return 1
    except CollectError as exc:
        log("ERROR", f"collect error: {exc}")
        return 1
    except RuntimeError as exc:
        log("ERROR", str(exc))
        return 1
    except OSError as exc:
        log("ERROR", f"os error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
