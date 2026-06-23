#!/usr/bin/env python3
"""Nightly Synology health and security digest."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOCAL_TZ = datetime.now().astimezone().tzinfo  # tz from TZ env (run.sh defaults to UTC); no region baked into source
BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "state.json"
LOG_FILE = BASE_DIR / "run.log"
AUTH_LOG_CANDIDATES = ["/var/log/auth.log", "/var/log/messages"]
CONN_DB = "/var/log/synolog/.SYNOCONNDB"
TAILSCALE_BIN = "/var/packages/Tailscale/target/bin/tailscale"
SYNOPKG_BIN = "/usr/syno/bin/synopkg"
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_RUN_LOG_BYTES = 512 * 1024
MISSED_RUN_HOURS = 25
VOL_WARN_PCT = 85
VOL_CRIT_PCT = 95
COLLECTOR_ERRORS: list[str] = []
FAILED_PATTERNS = (
    "Failed password",
    "authentication failure",
    "Invalid user",
    "Connection closed by authenticating user",
    "Did not receive identification string",
)
IP_REGEX = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


class CollectError(RuntimeError):
    pass


sys.dont_write_bytecode = True
sys.path.insert(0, str(BASE_DIR.parent))
from notify import NotifyError, load_env_file, send_messages  # noqa: E402

load_env_file(BASE_DIR.parent / ".env")
load_env_file(BASE_DIR / ".env")


def log(level: str, message: str) -> None:
    timestamp = datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} {level} {message}\n"
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_RUN_LOG_BYTES:
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.1"))
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line)
        LOG_FILE.chmod(0o660)
    except Exception:
        print(line, file=sys.stderr, end="", flush=True)


def record_collect_error(source: str, exc: object) -> None:
    message = f"collect error source={source}: {exc}"
    COLLECTOR_ERRORS.append(message)
    log("ERROR", message)


def parse_args():
    parser = argparse.ArgumentParser(description="Synology health CLI digest")
    parser.add_argument("--dry-run", action="store_true", help="Print only; do not notify or update state")
    return parser.parse_args()


def run(cmd: list[str], timeout: int = 20) -> str:
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


def read_text(path: str, *, errors: str | None = None) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors=errors or "strict")
    except Exception as exc:
        raise CollectError(f"read failed: {path}: {exc}") from exc


def read_recent_lines(path: Path, max_bytes: int = MAX_LOG_BYTES) -> list[str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(-max_bytes, os.SEEK_END)
                handle.readline()
            data = handle.read()
    except Exception as exc:
        raise CollectError(f"read failed: {path}: {exc}") from exc
    return data.decode("utf-8", errors="ignore").splitlines()


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log("ERROR", f"state.json is invalid, starting fresh: {exc}")
        return {}
    if not isinstance(payload, dict):
        log("ERROR", "state.json must contain an object, starting fresh")
        return {}
    return payload


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


def parse_key_value_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            out[key.strip()] = value.strip()
        elif "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip('"')
    return out


def _is_bad_status(status: object) -> bool:
    """True only for an explicit, non-normal status string.

    Missing data ("no data"/None) is handled via collector errors, so it
    must NOT be treated as a fault here (otherwise we'd cry CRITICAL on a
    failed API call instead of a real disk problem)."""
    if not status:
        return False
    text = str(status).strip().lower()
    return text not in ("normal", "no data", "-", "")


def upsc_output() -> str:
    errors: list[str] = []
    for cmd in (
        ["/bin/upsc", "ups@localhost"],
        ["/usr/bin/upsc", "ups@localhost"],
        ["/usr/local/bin/upsc", "ups@localhost"],
        ["upsc", "ups@localhost"],
    ):
        try:
            return run(cmd, timeout=10)
        except CollectError as exc:
            errors.append(str(exc))
    raise CollectError("; ".join(errors))


def human_bytes(num: int | float | None) -> str:
    if num is None:
        return "n/a"
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(num)} B"


def parse_meminfo() -> dict[str, int]:
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    out: dict[str, int] = {}
    for line in read_text("/proc/meminfo").splitlines():
        key, _, rest = line.partition(":")
        if key not in wanted:
            continue
        match = re.search(r"(\d+)", rest)
        if match:
            out[key] = int(match.group(1)) * 1024
    return out


def parse_loadavg() -> tuple[str, str, str]:
    parts = read_text("/proc/loadavg").split()
    return parts[0], parts[1], parts[2]


def uptime_seconds() -> int:
    return int(float(read_text("/proc/uptime").split()[0]))


def format_uptime(total_seconds: int) -> str:
    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def cpu_temp_c() -> float | None:
    candidates = sorted(Path("/sys/class/thermal").glob("thermal_zone*/temp"))
    values: list[float] = []
    for path in candidates:
        try:
            raw = path.read_text().strip()
            value = int(raw)
            if value > 1000:
                value /= 1000.0
            values.append(float(value))
        except Exception:
            continue
    if not values:
        return None
    return max(values)


def fmt_celsius(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.1f}C"


def disk_usage(mount: str) -> dict[str, int | str | None]:
    output = run(["/usr/bin/df", "-B1", mount])
    lines = output.splitlines()
    if len(lines) < 2:
        raise CollectError(f"unexpected df output for {mount}")
    parts = lines[1].split()
    if len(parts) < 6:
        raise CollectError(f"unexpected df columns for {mount}")
    return {
        "mount": mount,
        "total": int(parts[1]),
        "used": int(parts[2]),
        "avail": int(parts[3]),
        "pct": parts[4],
    }


def format_disk_usage(item: dict[str, int | str | None]) -> str:
    pct = item.get("pct") or "n/a"
    return (
        f"used {human_bytes(item.get('used'))} / free {human_bytes(item.get('avail'))} "
        f"({pct} of {human_bytes(item.get('total'))})"
    )


def pct_to_int(pct: object) -> int | None:
    try:
        return int(str(pct).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def safe_disk_usage(mount: str) -> dict[str, int | str | None]:
    try:
        return disk_usage(mount)
    except CollectError as exc:
        record_collect_error(f"df:{mount}", exc)
        return {"mount": mount, "total": None, "used": None, "avail": None, "pct": None}


def who_lines() -> list[str]:
    try:
        output = run(["/usr/bin/who"])
    except CollectError:
        return []
    return [line for line in output.splitlines() if line.strip()]


def current_login_sessions() -> tuple[int, list[str]]:
    sessions = who_lines()
    ips = []
    for line in sessions:
        match = re.search(r"\(([^)]+)\)", line)
        if match:
            ips.append(match.group(1))
    return len(sessions), sorted(set(ips))


def list_to_text(items: list[str], *, limit: int = 5, empty: str = "none") -> str:
    cleaned = [item for item in items if item]
    if not cleaned:
        return empty
    shown = cleaned[:limit]
    text = ", ".join(shown)
    remaining = len(cleaned) - len(shown)
    if remaining > 0:
        text += f" and {remaining} more"
    return text


def local_dsm_users() -> list[str] | None:
    cmd = [
        "/usr/syno/bin/synowebapi",
        "--exec",
        "api=SYNO.Core.User",
        "method=list",
        "version=1",
        "type=local",
    ]
    try:
        raw = run(cmd, timeout=20)
        data = json.loads(raw)
        users = data.get("data", {}).get("users", [])
        result = sorted(item["name"] for item in users if item.get("name"))
        return result or None
    except Exception as exc:
        record_collect_error("dsm-users", exc)
        fallback: list[str] = []
        try:
            for line in read_text("/etc/passwd", errors="ignore").splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                name = parts[0]
                uid = parts[2]
                shell = parts[6]
                try:
                    uid_value = int(uid)
                except ValueError:
                    continue
                if uid_value < 1000:
                    continue
                if shell.endswith("nologin") or shell.endswith("false"):
                    continue
                fallback.append(name)
        except Exception as fallback_exc:
            record_collect_error("passwd-fallback", fallback_exc)
            return None
        return sorted(set(fallback)) or None


def is_private_ip(ip: str) -> bool:
    """Treat LAN / loopback / link-local / CGNAT (incl. Tailscale 100.64/10)
    as private. Unparseable -> private, so we never over-alarm on garbage."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def parse_iso_or_syslog_datetime(line: str, now: datetime) -> datetime | None:
    iso_match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z))", line)
    if iso_match:
        try:
            return datetime.fromisoformat(iso_match.group(1).replace("Z", "+00:00")).astimezone(LOCAL_TZ)
        except ValueError:
            return None

    syslog_match = re.match(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if syslog_match:
        try:
            parsed = datetime.strptime(syslog_match.group(1), "%b %d %H:%M:%S")
            parsed = parsed.replace(year=now.year, tzinfo=LOCAL_TZ)
            if parsed - now > timedelta(days=1):
                parsed = parsed.replace(year=now.year - 1)
            return parsed
        except ValueError:
            return None
    return None


def parse_failed_ssh_attempts(now: datetime) -> dict[str, object]:
    """Fallback security source: scrape sshd failures from auth.log/messages."""
    cutoff = now - timedelta(hours=24)
    count = 0
    counter: Counter[str] = Counter()

    for path in AUTH_LOG_CANDIDATES:
        file_path = Path(path)
        if not file_path.exists():
            continue
        try:
            lines = read_recent_lines(file_path)
        except Exception as exc:
            record_collect_error(f"ssh-log:{path}", exc)
            continue

        for line in lines:
            lower = line.lower()
            if "sshd" not in lower:
                continue
            if not any(pattern in line for pattern in FAILED_PATTERNS):
                continue
            timestamp = parse_iso_or_syslog_datetime(line, now)
            if timestamp is None:
                continue
            if timestamp < cutoff:
                continue
            count += 1
            for ip in IP_REGEX.findall(line):
                counter[ip] += 1

    ips = sorted(counter.keys())
    top = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {"count": count, "ips": ips, "top": top, "counter": counter}


def failed_logins_logcenter(now: datetime) -> dict[str, object] | None:
    """Primary security source: DSM Log Center connection DB.

    Counts failed sign-ins in the last 24h and splits them into LAN (your own
    typos) vs external/public IPs (real attacks). Opens the live DB strictly
    read-only + immutable so we never lock or write the running database.
    Returns None to signal the caller to fall back to auth.log."""
    cutoff = int(now.timestamp()) - 86400
    try:
        conn = sqlite3.connect(f"file:{CONN_DB}?mode=ro&immutable=1", uri=True, timeout=5)
    except Exception as exc:
        log("INFO", f"logcenter unavailable, fallback to auth.log: {exc}")
        return None
    try:
        rows = conn.execute(
            "SELECT ip, msg FROM logs "
            "WHERE level='warning' AND time>=? AND msg LIKE '%failed%'",
            (cutoff,),
        ).fetchall()
    except Exception as exc:
        log("INFO", f"logcenter query failed, fallback to auth.log: {exc}")
        return None
    finally:
        conn.close()

    counter: Counter[str] = Counter()
    ext_counter: Counter[str] = Counter()
    for ip, msg in rows:
        ip = (ip or "").strip()
        if not ip:
            # Some DSM rows leave the ip column blank; recover it from the
            # message text ("...from [1.2.3.4] failed to sign in...").
            match = IP_REGEX.search(msg or "")
            ip = match.group(1) if match else ""
        if not ip:
            continue
        counter[ip] += 1
        if not is_private_ip(ip):
            ext_counter[ip] += 1

    top = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        # count only attributed rows so it never exceeds the listed IPs
        "count": sum(counter.values()),
        "external_count": sum(ext_counter.values()),
        "ips": sorted(counter.keys()),
        "external_ips": sorted(ext_counter.keys()),
        "top": top,
        "source": "Log Center",
    }


def security_info(now: datetime) -> dict[str, object]:
    primary = failed_logins_logcenter(now)
    if primary is not None:
        return primary
    fallback = parse_failed_ssh_attempts(now)
    fb_counter = fallback.get("counter") or Counter()
    external_count = sum(c for ip, c in fb_counter.items() if not is_private_ip(ip))
    ext_ips = sorted(ip for ip in fb_counter if not is_private_ip(ip))
    return {
        "count": fallback["count"],
        "external_count": external_count,
        "ips": fallback["ips"],
        "external_ips": ext_ips,
        "top": fallback["top"],
        "source": "auth.log",
    }


def storage_info() -> dict[str, object]:
    cmd = [
        "/usr/syno/bin/synowebapi",
        "--exec",
        "api=SYNO.Storage.CGI.Storage",
        "method=load_info",
        "version=1",
    ]
    blank = {
        "disks": [],
        "disk_temp": None,
        "disk_status": "no data",
        "disk_smart": None,
        "disk_unc": None,
        "volume_status": "no data",
        "vol_show_attention": None,
        "vol_show_danger": None,
        "vol_writable": None,
        "vol_inode_full": None,
        "vol_used": None,
        "vol_total": None,
        "raid_type": None,
        "fs_type": None,
    }
    try:
        raw = run(cmd, timeout=20)
        data = json.loads(raw).get("data") or {}
    except Exception as exc:
        record_collect_error("storage", exc)
        return blank

    # Defensive: a transient API can return data=null or non-list disks/volumes;
    # an unguarded AttributeError here would escape main() and kill the digest.
    disks = data.get("disks") or []
    if not isinstance(disks, list):
        disks = []
    volumes = data.get("volumes") or []
    if not isinstance(volumes, list):
        volumes = []

    disks_out: list[dict[str, object]] = []
    temps: list[int] = []
    unc_total = 0
    unc_seen = False
    smart_values: list[str] = []
    status_values: list[str] = []
    for index, disk in enumerate(disks, start=1):
        temp = disk.get("temp") if isinstance(disk.get("temp"), int) else None
        if temp is not None:
            temps.append(temp)
        unc = disk.get("unc") if isinstance(disk.get("unc"), int) else None
        if unc is not None:
            unc_total += unc
            unc_seen = True
        smart = disk.get("smart_status")
        status = disk.get("overview_status") or disk.get("status") or disk.get("drive_status_key")
        if smart:
            smart_values.append(str(smart))
        if status:
            status_values.append(str(status))
        remain = disk.get("remain_life")
        remain_value = remain.get("value") if isinstance(remain, dict) else None
        disks_out.append(
            {
                "name": disk.get("longName") or disk.get("name") or f"Disk {index}",
                "model": disk.get("model"),
                "smart": smart,
                "status": status,
                "temp": temp,
                "unc": unc,
                "remain_life": remain_value,
            }
        )

    def _worst(values: list[str], default: str) -> str:
        bad = sorted({v for v in values if _is_bad_status(v)})
        if bad:
            return ", ".join(bad)
        return ", ".join(sorted(set(values))) if values else default

    disk_status = _worst(status_values, "no data")
    disk_smart = _worst(smart_values, "no data") if smart_values else None

    volume = volumes[0] if volumes else {}
    space = volume.get("space_status") or {}
    size = volume.get("size") or {}

    def _to_int(value: object) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    volume_status = (
        volume.get("status")
        or volume.get("summary_status")
        or space.get("summary_status")
        or "no data"
    )

    return {
        "disks": disks_out,
        "disk_temp": max(temps) if temps else None,
        "disk_status": disk_status,
        "disk_smart": disk_smart,
        "disk_unc": unc_total if unc_seen else None,
        "volume_status": volume_status,
        "vol_show_attention": space.get("show_attention"),
        "vol_show_danger": space.get("show_danger"),
        "vol_writable": volume.get("is_writable"),
        "vol_inode_full": volume.get("is_inode_full"),
        "vol_used": _to_int(size.get("used")),
        "vol_total": _to_int(size.get("total")),
        "raid_type": volume.get("raidType"),
        "fs_type": volume.get("fs_type"),
    }


def power_status() -> dict[str, object]:
    conf_path = Path("/usr/syno/etc/ups/synoups.conf")
    enabled = None
    mode = "unknown"
    safe_shutdown = "unknown"

    if conf_path.exists():
        try:
            conf = parse_key_value_lines(conf_path.read_text(encoding="utf-8", errors="ignore"))
            enabled = conf.get("ups_enabled", "no").lower() == "yes"
            mode = conf.get("ups_mode", "unknown").lower()
            safe_shutdown = conf.get("ups_safeshutdown", "unknown")
        except Exception as exc:
            record_collect_error("ups-conf", exc)

    try:
        live = parse_key_value_lines(upsc_output())
    except Exception as exc:
        # An unreachable UPS is not a "collection error": the USB bus may be
        # intentionally disabled. Log quietly, without WARNING or noise in the digest.
        log("INFO", f"ups offline (upsc unavailable): {exc}")
        live = {}

    result = {
        "configured": enabled,
        "mode": mode,
        "safe_shutdown": safe_shutdown,
        "ups_status": live.get("ups.status"),
        "model": live.get("ups.model") or live.get("device.model"),
        "battery_charge": live.get("battery.charge"),
        "battery_runtime": live.get("battery.runtime"),
        "input_voltage": live.get("input.voltage"),
        "lines": [],
    }

    if enabled is False and not live:
        result["lines"] = [
            "Power: direct from mains",
            "Power signal: mains only, UPS disabled",
        ]
        return result

    if not live and enabled is None:
        result["lines"] = [
            "Power: direct from mains",
            "Power signal: no data on UPS",
        ]
        return result

    if live:
        setup = f"UPS via {mode.upper()}" if mode != "unknown" else "UPS"
        lines = [f"Power: {setup}"]
        ups_status = live.get("ups.status", "unknown")
        if "OB" in ups_status:
            signal = "mains lost, running on battery"
        elif "OL" in ups_status:
            signal = "mains OK, UPS online"
        else:
            signal = ups_status
        if "LB" in ups_status:
            signal += ", low battery"

        if result["model"]:
            lines.append(f"UPS model: {result['model']}")
        lines.append(f"Power signal: {signal}")

        battery = result.get("battery_charge")
        runtime = result.get("battery_runtime")
        if battery:
            battery_line = f"UPS battery: {battery}%"
            if runtime and str(runtime).isdigit():
                battery_line += f", {int(runtime) // 60} min runtime"
            lines.append(battery_line)
        if result.get("input_voltage"):
            lines.append(f"Input voltage: {result['input_voltage']}V")
        if safe_shutdown != "unknown":
            ups_poweroff = "no" if safe_shutdown == "no" else "yes"
            lines.append(f"Power off the UPS itself after standby: {ups_poweroff}")

        result["lines"] = lines
        return result

    # The UPS is configured in DSM but is not responding right now (e.g. the USB bus is disabled).
    # This is a normal situation, not an error — report it clearly and without alarm.
    setup = f"UPS configured ({mode.upper()})" if mode != "unknown" else "UPS configured"
    result["lines"] = [
        f"Power: {setup}",
        "Power signal: UPS is not responding right now (no USB connection) — telemetry unavailable",
    ]
    return result


def _capture_stdout(cmd: list[str], timeout: int = 10) -> str:
    """Run a command and return stdout regardless of exit code. Some Synology
    tools (e.g. `synopkg status` on a stopped package) exit non-zero while
    printing valid JSON to stdout, so run()'s check=True would discard it."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return (result.stdout or "").strip()


def tailscale_line() -> str | None:
    """One-line Tailscale state. None -> package not installed (omit line)."""
    raw = _capture_stdout([SYNOPKG_BIN, "status", "Tailscale"])
    if not raw:
        return None
    try:
        state = str(json.loads(raw).get("status", "")).lower()
    except Exception:
        state = ""
    if state in ("", "stop", "stopping", "stopped", "nonactive", "non_active"):
        return "Tailscale: package stopped"
    try:
        data = json.loads(_capture_stdout([TAILSCALE_BIN, "status", "--json"]))
    except Exception:
        return "Tailscale: running (status unavailable)"
    backend = str(data.get("BackendState", "?"))
    if backend == "Running":
        self_node = data.get("Self") or {}
        name = (self_node.get("DNSName") or "").rstrip(".") or self_node.get("HostName") or ""
        return f"Tailscale: online{(' · ' + name) if name else ''}"
    if backend == "NeedsLogin":
        return "Tailscale: running, login required"
    if backend == "Stopped":
        return "Tailscale: running, connection stopped"
    return f"Tailscale: {backend}"


def system_header(snapshot_extra: dict[str, object]) -> str | None:
    bits: list[str] = []
    try:
        model = read_text("/proc/sys/kernel/syno_hw_version").strip()
        if model:
            bits.append(model)
    except Exception:
        pass
    try:
        version = parse_key_value_lines(read_text("/etc/VERSION"))
        product = version.get("productversion")
        build = version.get("buildnumber")
        if product:
            bits.append(f"DSM {product}" + (f" ({build})" if build else ""))
    except Exception:
        pass
    raid = snapshot_extra.get("raid_type")
    fs = snapshot_extra.get("fs_type")
    if raid or fs:
        bits.append(f"volume {raid or '?'}/{fs or '?'}")
    return " · ".join(bits) or None


def last_run_text(previous: dict | None) -> tuple[str | None, bool]:
    """Return (human last-run string, missed?) from prior captured_at."""
    if not previous:
        return None, False
    raw = str(previous.get("captured_at") or "")
    try:
        prev = datetime.fromisoformat(raw)
    except ValueError:
        return None, False
    now = datetime.now(LOCAL_TZ)
    if prev.tzinfo is None:
        prev = prev.replace(tzinfo=LOCAL_TZ)
    gap = now - prev
    text = prev.astimezone(LOCAL_TZ).strftime("%d.%m %H:%M")
    return text, gap > timedelta(hours=MISSED_RUN_HOURS)


def format_disk_line(disk: dict[str, object]) -> str:
    parts = [str(disk.get("name") or "Disk")]
    if disk.get("model"):
        parts.append(str(disk["model"]))
    if disk.get("smart"):
        parts.append(f"SMART {disk['smart']}")
    if isinstance(disk.get("unc"), int):
        parts.append(f"bad sectors {disk['unc']}")
    remain = disk.get("remain_life")
    if isinstance(remain, int) and remain >= 0:
        parts.append(f"life {remain}%")
    temp = disk.get("temp")
    if isinstance(temp, (int, float)):
        parts.append(f"{float(temp):.0f}C")
    if _is_bad_status(disk.get("status")):
        parts.append(f"STATUS: {disk['status']}")
    return " · ".join(parts)


def build_summary(snapshot: dict[str, object]) -> str:
    issues: list[str] = []

    uptime = int(snapshot.get("uptime_seconds") or 0)
    if uptime and uptime < 12 * 3600:
        issues.append("recent reboot")

    if snapshot.get("missed_run"):
        issues.append("previous run missed")

    if _is_bad_status(snapshot.get("disk_status")) or _is_bad_status(snapshot.get("disk_smart")):
        issues.append("disk problem (SMART/status)")

    if _is_bad_status(snapshot.get("volume_status")) or snapshot.get("vol_show_danger") is True:
        issues.append("volume problem")
    if snapshot.get("vol_writable") is False:
        issues.append("volume not writable")
    if snapshot.get("vol_inode_full") is True:
        issues.append("volume inodes exhausted")

    vol_pct = snapshot.get("vol_pct")
    if isinstance(vol_pct, int):
        if vol_pct >= VOL_CRIT_PCT:
            issues.append(f"volume almost full ({vol_pct}%)")
        elif vol_pct >= VOL_WARN_PCT:
            issues.append(f"volume filling up ({vol_pct}%)")

    unc = snapshot.get("disk_unc")
    if isinstance(unc, int) and unc > 0:
        issues.append(f"bad sectors appeared ({unc})")

    ups_status = str(snapshot.get("ups_status") or "")
    if "LB" in ups_status:
        issues.append("low UPS battery")
    elif "OB" in ups_status:
        issues.append("running on UPS battery")

    external = int(snapshot.get("failed_login_external") or 0)
    if external > 0:
        issues.append(f"external login attempts ({external})")

    cpu_temp = snapshot.get("cpu_temp")
    if isinstance(cpu_temp, (int, float)) and cpu_temp >= 75:
        issues.append("CPU hot")

    disk_temp = snapshot.get("disk_temp")
    if isinstance(disk_temp, (int, float)) and disk_temp >= 50:
        issues.append("disk heating up")

    if snapshot.get("collector_errors"):
        issues.append("some data could not be collected")

    if not issues:
        return "Summary: all quiet."
    return "Summary: " + "; ".join(issues) + "."


def build_changes(snapshot: dict[str, object], previous: dict | None) -> list[str]:
    if not previous:
        return []

    changes: list[str] = []

    prev_uptime = int(previous.get("uptime_seconds") or 0)
    curr_uptime = int(snapshot.get("uptime_seconds") or 0)
    if prev_uptime > 0 and curr_uptime < prev_uptime:
        changes.append("uptime reset: a reboot is likely")

    prev_ram = previous.get("ram_available")
    curr_ram = snapshot.get("ram_available")
    if isinstance(prev_ram, int) and isinstance(curr_ram, int):
        delta = curr_ram - prev_ram
        if abs(delta) >= 200 * 1024 * 1024:
            direction = "more" if delta > 0 else "less"
            changes.append(f"free RAM is {direction} by {human_bytes(abs(delta))}")

    prev_free = previous.get("volume1_avail")
    curr_free = snapshot.get("volume1_avail")
    if isinstance(prev_free, int) and isinstance(curr_free, int):
        delta = curr_free - prev_free
        if abs(delta) >= 500 * 1024 * 1024:
            direction = "grew" if delta > 0 else "dropped"
            changes.append(f"free space on /volume1 {direction} by {human_bytes(abs(delta))}")

    prev_ips = set(previous.get("failed_login_ips") or previous.get("failed_ssh_ips") or [])
    curr_ips = set(snapshot.get("failed_login_ips") or [])
    new_ips = sorted(curr_ips - prev_ips)
    if new_ips:
        changes.append(f"new IPs with failed logins: {list_to_text(new_ips, limit=3)}")

    return changes[:4]


def build_message(snapshot: dict[str, object], previous: dict | None) -> str:
    now = datetime.now(LOCAL_TZ)
    changes = build_changes(snapshot, previous)

    lines: list[str] = ["NAS: nightly digest"]
    header = snapshot.get("header_text")
    if header:
        lines.append(str(header))
    lines.append(now.strftime("%d.%m.%Y %H:%M"))
    lines.append("")
    lines.append(build_summary(snapshot))

    if snapshot.get("missed_run"):
        lines.append(
            f"⚠ It looks like the previous run was missed (last one was {snapshot.get('last_run_text') or 'unknown'})"
        )

    if changes:
        lines.extend(["", "Changes since yesterday", *(f"  {item}" for item in changes)])

    collector_errors = snapshot.get("collector_errors") or []
    if collector_errors:
        lines.extend(["", "Warning: data collection errors"])
        lines.extend(f"  {item}" for item in collector_errors[:5])

    # 💾 Storage
    lines.extend(["", "💾 Storage"])
    lines.append(
        f"  Volume /volume1 ({snapshot.get('raid_type') or '?'}, {snapshot.get('fs_type') or '?'}): "
        f"{snapshot.get('volume1_usage_text')}"
    )
    lines.append(f"  System disk (/): {snapshot.get('root_usage_text')}")
    for disk in snapshot.get("disks") or []:
        lines.append(f"  {format_disk_line(disk)}")
    volume_status = snapshot.get("volume_status")
    if _is_bad_status(volume_status) or snapshot.get("vol_show_danger") or snapshot.get("vol_show_attention"):
        flag = ""
        if snapshot.get("vol_show_danger"):
            flag = " · DANGER"
        elif snapshot.get("vol_show_attention"):
            flag = " · attention"
        lines.append(f"  Volume status: {volume_status}{flag}")

    # 🧠 Memory / load
    lines.extend(["", "🧠 Memory / load"])
    lines.append(
        f"  RAM:  used {human_bytes(snapshot.get('ram_used'))} / "
        f"free {human_bytes(snapshot.get('ram_available'))} / "
        f"total {human_bytes(snapshot.get('ram_total'))}"
    )
    if snapshot.get("swap_total"):
        lines.append(
            f"  Swap: used {human_bytes(snapshot.get('swap_used'))} / total {human_bytes(snapshot.get('swap_total'))}"
        )
    lines.append(
        f"  CPU {fmt_celsius(snapshot.get('cpu_temp'))} · "
        f"uptime {format_uptime(int(snapshot.get('uptime_seconds') or 0))} · "
        f"load {snapshot.get('load1')} / {snapshot.get('load5')} / {snapshot.get('load15')}"
    )
    if snapshot.get("last_run_text"):
        lines.append(f"  Last run: {snapshot.get('last_run_text')}")

    # 🔐 Access
    lines.extend(["", "🔐 Access"])
    lines.append(f"  Accounts {snapshot.get('user_count_text')} · sessions {snapshot.get('login_count')}")
    lines.append(f"  Accounts: {snapshot.get('users_text')}")
    if snapshot.get("login_ips_text") and snapshot.get("login_ips_text") != "none":
        lines.append(f"  IPs in sessions: {snapshot.get('login_ips_text')}")
    source = snapshot.get("security_source")
    src_suffix = f" ({source})" if source else ""
    lines.append(f"  Failed logins in 24h: {snapshot.get('failed_login_count')}{src_suffix}")
    external = int(snapshot.get("failed_login_external") or 0)
    if external > 0:
        lines.append(
            f"  ⚠ from external IPs: {external} → {list_to_text(snapshot.get('failed_login_external_ips') or [], limit=4)}"
        )
    elif int(snapshot.get("failed_login_count") or 0) > 0:
        lines.append(f"  (all from the local network: {list_to_text(snapshot.get('failed_login_ips') or [], limit=4)})")
    top = snapshot.get("failed_login_top") or []
    if top:
        lines.append("  Top IPs: " + list_to_text([f"{ip} ({n})" for ip, n in top], limit=3))

    # 🔌 Power
    lines.extend(["", "🔌 Power"])
    lines.extend(f"  {item}" for item in (snapshot.get("power_lines") or []))

    # 🌐 Network
    tail = snapshot.get("tailscale_line")
    if tail:
        lines.extend(["", "🌐 Network", f"  {tail}"])

    return "\n".join(lines)


def collect_snapshot() -> dict[str, object]:
    COLLECTOR_ERRORS.clear()
    now = datetime.now(LOCAL_TZ)
    mem = parse_meminfo()
    total = mem.get("MemTotal", 0)
    available = mem.get("MemAvailable", 0)
    used = max(total - available, 0)
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)
    load1, load5, load15 = parse_loadavg()
    root_usage = safe_disk_usage("/")
    volume1_usage = safe_disk_usage("/volume1")
    login_count, login_ips = current_login_sessions()
    users = local_dsm_users()
    security = security_info(now)
    power = power_status()
    storage = storage_info()

    try:
        last_text, missed = last_run_text(load_state_for_lastrun())
    except Exception:
        last_text, missed = None, False

    header = system_header(storage)

    snapshot: dict[str, object] = {
        "date": now.strftime("%Y-%m-%d"),
        "captured_at": now.isoformat(),
        "header_text": header,
        "cpu_temp": cpu_temp_c(),
        "disk_temp": storage.get("disk_temp"),
        "disk_status": storage.get("disk_status"),
        "disk_smart": storage.get("disk_smart"),
        "disk_unc": storage.get("disk_unc"),
        "disks": storage.get("disks"),
        "volume_status": storage.get("volume_status"),
        "vol_show_attention": storage.get("vol_show_attention"),
        "vol_show_danger": storage.get("vol_show_danger"),
        "vol_writable": storage.get("vol_writable"),
        "vol_inode_full": storage.get("vol_inode_full"),
        "vol_pct": pct_to_int(volume1_usage.get("pct")),
        "raid_type": storage.get("raid_type"),
        "fs_type": storage.get("fs_type"),
        "uptime_seconds": uptime_seconds(),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "ram_total": total,
        "ram_available": available,
        "ram_used": used,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "root_usage_text": format_disk_usage(root_usage),
        "volume1_usage_text": format_disk_usage(volume1_usage),
        "volume1_avail": volume1_usage.get("avail"),
        "user_count_text": str(len(users)) if users is not None else "n/a",
        "users_text": list_to_text(users or [], limit=5, empty="no data"),
        "login_count": login_count,
        "login_ips_text": list_to_text(login_ips, limit=5),
        "failed_login_count": security["count"],
        "failed_login_external": security["external_count"],
        "failed_login_ips": security["ips"],
        "failed_login_external_ips": security["external_ips"],
        "failed_login_top": security["top"],
        "security_source": security["source"],
        "last_run_text": last_text,
        "missed_run": missed,
        "ups_status": power.get("ups_status"),
        "power_lines": power.get("lines"),
        "tailscale_line": tailscale_line(),
        "collector_errors": list(COLLECTOR_ERRORS),
    }
    return snapshot


# Loaded once in main() and reused so collect_snapshot can compute "last run"
# without a second disk read; falls back to a direct load if unset.
_PREVIOUS_STATE: dict | None = None


def load_state_for_lastrun() -> dict | None:
    if _PREVIOUS_STATE is not None:
        return _PREVIOUS_STATE
    return load_state()


def snapshot_severity(snapshot: dict[str, object]) -> str:
    # --- CRITICAL: real hardware / data-availability faults ---
    if _is_bad_status(snapshot.get("disk_status")) or _is_bad_status(snapshot.get("disk_smart")):
        return "critical"
    if _is_bad_status(snapshot.get("volume_status")) or snapshot.get("vol_show_danger") is True:
        return "critical"
    if snapshot.get("vol_writable") is False or snapshot.get("vol_inode_full") is True:
        return "critical"
    vol_pct = snapshot.get("vol_pct")
    if isinstance(vol_pct, int) and vol_pct >= VOL_CRIT_PCT:
        return "critical"
    if "LB" in str(snapshot.get("ups_status") or ""):
        return "critical"

    # --- WARNING: attention needed but not an emergency ---
    if snapshot.get("collector_errors"):
        return "warning"
    if snapshot.get("vol_show_attention") is True:
        return "warning"
    if isinstance(vol_pct, int) and vol_pct >= VOL_WARN_PCT:
        return "warning"
    if "OB" in str(snapshot.get("ups_status") or ""):
        return "warning"
    cpu_temp = snapshot.get("cpu_temp")
    if isinstance(cpu_temp, (int, float)) and cpu_temp >= 75:
        return "warning"
    disk_temp = snapshot.get("disk_temp")
    if isinstance(disk_temp, (int, float)) and disk_temp >= 50:
        return "warning"
    if int(snapshot.get("failed_login_external") or 0) > 0:
        return "warning"
    unc = snapshot.get("disk_unc")
    if isinstance(unc, int) and unc > 0:
        return "warning"
    if snapshot.get("missed_run"):
        return "warning"
    return "info"


def main() -> int:
    global _PREVIOUS_STATE
    args = parse_args()
    try:
        if not args.dry_run:
            ensure_writable_base()
        log("INFO", "start notify_mode=telegram")
        _PREVIOUS_STATE = load_state()
        previous = _PREVIOUS_STATE
        snapshot = collect_snapshot()
        severity = snapshot_severity(snapshot)
        message = build_message(snapshot, previous)
        if args.dry_run:
            prefix = (
                "[CRITICAL]" if severity == "critical" else "[INFO]" if severity == "info" else "[WARNING]"
            )
            print(f"(severity={severity} → tag {prefix})")
        send_messages(
            [message],
            title="NAS: nightly health digest",
            severity=severity,
            source="nas-health",
            dry_run=args.dry_run,
        )
        if not args.dry_run:
            save_state(snapshot)
        log("OK", "notification complete")
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
