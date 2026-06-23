#!/usr/bin/env python3
"""Synology security monitor for login, SMB, and failed SSH alerts."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
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
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_RUN_LOG_BYTES = 512 * 1024
MAX_FAILED_LOOKBACK = timedelta(hours=6)
COLLECTOR_ERRORS: list[str] = []
FAILED_PATTERNS = (
    "Failed password",
    "Invalid user",
    "authentication failure",
    "Did not receive identification string",
    "Connection closed by authenticating user",
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
    parser = argparse.ArgumentParser(description="Synology security CLI monitor")
    parser.add_argument("--dry-run", action="store_true", help="Print only; do not notify or update state")
    parser.add_argument("--test-notify", action="store_true", help="Send a Telegram test message")
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


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {
            "ssh_sessions": [],
            "smb_sessions": [],
            "last_check": None,
            "last_failed_check": None,
        }
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log("ERROR", f"state.json is invalid, starting fresh: {exc}")
        return {
            "ssh_sessions": [],
            "smb_sessions": [],
            "last_check": None,
            "last_failed_check": None,
        }
    if not isinstance(data, dict):
        log("ERROR", "state.json must contain an object, starting fresh")
        return {
            "ssh_sessions": [],
            "smb_sessions": [],
            "last_check": None,
            "last_failed_check": None,
        }
    data.setdefault("ssh_sessions", [])
    data.setdefault("smb_sessions", [])
    data.setdefault("last_check", None)
    data.setdefault("last_failed_check", data.get("last_check"))
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


def parse_whitelist() -> set[str]:
    raw = os.environ.get("ALERT_WHITELIST_IPS", "").strip()
    return {item.strip() for item in raw.split(",") if item.strip()}


TRUSTED_NETS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918 home LAN
        "127.0.0.0/8",                                      # loopback
        "169.254.0.0/16",                                  # link-local
        "100.64.0.0/10",                                   # CGNAT / Tailscale
        "::1/128",                                         # IPv6 loopback
        "fe80::/10",                                       # IPv6 link-local
        "fc00::/7",                                        # IPv6 ULA (incl. Tailscale fd7a::/48)
    )
]


def is_private_ip(ip: str) -> bool:
    """True ONLY for genuine home LAN / loopback / link-local / CGNAT
    (incl. Tailscale and IPv6 ULA). Uses an explicit allowlist, so bogon /
    TEST-NET ranges that Python's is_private marks True are NOT auto-trusted,
    and IPv4-mapped IPv6 (::ffff:<v4>) is unwrapped first so a mapped PUBLIC
    address is correctly seen as external."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in TRUSTED_NETS)


def is_trusted_source(ip: str, whitelist: set[str]) -> bool:
    """Trusted (no alert): home LAN / Tailscale, explicitly whitelisted IPs,
    or a local session with no network IP (console). Only public/external
    sources raise an alert."""
    ip = (ip or "").strip()
    if not ip:
        return True
    if ip in whitelist:
        return True
    return is_private_ip(ip)


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


def current_login_sessions() -> list[dict[str, str]]:
    try:
        output = run(["/usr/bin/who"])
    except CollectError as exc:
        record_collect_error("who", exc)
        return []

    sessions = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        paren = re.search(r"\(([^)]+)\)", line)
        raw_host = paren.group(1) if paren else ""
        # Prefer a numeric IPv4 embedded in the parenthetical (e.g. "host [1.2.3.4]");
        # otherwise keep the raw host (IPv6 literal or hostname) for classification.
        ip_in_host = IP_REGEX.search(raw_host)
        sessions.append(
            {
                "user": parts[0],
                "tty": parts[1],
                "ip": ip_in_host.group(1) if ip_in_host else raw_host,
            }
        )
    return sessions


def current_smb_sessions() -> list[dict[str, str]]:
    output = ""
    errors: list[str] = []
    for cmd in (["/usr/local/bin/smbstatus"], ["/usr/bin/smbstatus"], ["smbstatus"]):
        try:
            output = run(cmd, timeout=20)
            break
        except CollectError as exc:
            errors.append(str(exc))
    else:
        record_collect_error("smbstatus", "; ".join(errors))
        return []

    sessions = []
    in_service_block = False
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        if line.startswith("Service") and "Connected at" in line:
            in_service_block = True
            continue
        if not in_service_block:
            continue
        if line.startswith("Locked files:"):
            break
        if not line or line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        if parts[0].lower() == "pid":
            break
        machine = parts[2]
        ip_match = IP_REGEX.search(line)
        sessions.append(
            {
                "service": parts[0],
                "pid": parts[1],
                "machine": machine,
                "ip": ip_match.group(1) if ip_match else "",
            }
        )
    return sessions


def parse_log_timestamp(line: str, now: datetime) -> datetime | None:
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


def recent_failed_ssh(since: datetime, now: datetime) -> dict[str, object]:
    count = 0
    ip_counter: Counter[str] = Counter()
    skipped_unparsed = 0

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

            timestamp = parse_log_timestamp(line, now)
            if timestamp is None:
                skipped_unparsed += 1
                continue
            if timestamp < since or timestamp > now:
                continue

            count += 1
            for ip in IP_REGEX.findall(line):
                ip_counter[ip] += 1

    if skipped_unparsed:
        log("ERROR", f"parse error source=failed-ssh skipped_lines={skipped_unparsed}")

    ips = sorted(ip_counter.keys())
    top = sorted(ip_counter.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        "count": count,
        "ips": ips,
        "top": top,
        "counter": dict(ip_counter),
    }


def key_login(item: dict[str, str]) -> str:
    return f"{item.get('user','')}|{item.get('tty','')}|{item.get('ip','')}"


def key_smb(item: dict[str, str]) -> str:
    return f"{item.get('service','')}|{item.get('ip') or item.get('machine','')}"


def is_noise_smb_session(item: dict[str, str], whitelist: set[str]) -> bool:
    machine = (item.get("machine") or "").strip()
    ip = (item.get("ip") or "").strip()
    pid = (item.get("pid") or "").strip()
    service = (item.get("service") or "").strip()
    if machine in {"", "DENY_NONE"}:
        return True
    if machine in whitelist or ip in whitelist:
        return True
    if ip:
        # A dotted IPv4 was parsed from the row: trust LAN / Tailscale / whitelist.
        if is_trusted_source(ip, whitelist):
            return True
    elif is_private_ip(machine):
        # No IPv4 on the row (IPv6 or hostname in the Machine column): trust ONLY
        # if the machine is itself a private/ULA IP. A public IPv6 or an
        # unresolved hostname falls through and ALERTS (whitelist it if benign).
        return True
    if pid in {"", "0"}:
        return True
    if machine.isdigit():
        return True
    if service in {"", "DENY_NONE"}:
        return True
    return False


def build_login_alert(item: dict[str, str], whitelist: set[str]) -> str:
    ip = item.get("ip") or "unknown"
    foreign = ip not in whitelist and ip != "unknown"
    title = "New login session on Synology."
    if foreign:
        title = "Warning: new login session on Synology from a foreign IP."
    return "\n".join(
        [
            title,
            f"User: {item.get('user','?')}",
            f"TTY: {item.get('tty','?')}",
            f"IP: {ip}",
        ]
    )


def build_smb_alert(item: dict[str, str], whitelist: set[str]) -> str:
    machine = item.get("machine") or "unknown"
    ip = item.get("ip") or ""
    client = ip or machine
    foreign = client not in whitelist and client != "unknown"
    title = "New SMB connection to Synology."
    if foreign:
        title = "Warning: SMB connection to Synology from a foreign IP."
    return "\n".join(
        [
            title,
            f"Share: {item.get('service','?')}",
            f"Machine: {machine}",
            f"IP: {ip or 'n/a'}",
            f"PID: {item.get('pid','?')}",
        ]
    )


def build_collector_alert(errors: list[str]) -> str:
    lines = ["Warning: security-alert could not collect some of the data."]
    lines.extend(errors[:5])
    return "\n".join(lines)


def build_failed_ssh_alert(failed: dict[str, object], whitelist: set[str]) -> str:
    # Show ONLY external offenders, not the owner's own LAN password typos.
    counter = failed.get("counter") or {}
    foreign = sorted(
        ((ip, cnt) for ip, cnt in counter.items() if not is_trusted_source(ip, whitelist)),
        key=lambda item: (-item[1], item[0]),
    )
    foreign_ips = [ip for ip, _ in foreign]
    total = int(failed.get("count", 0) or 0)
    attributed = sum(int(cnt) for cnt in counter.values())
    unparsed = max(total - attributed, 0)  # failed lines with no IPv4 (e.g. IPv6 source)
    shown_count = sum(cnt for _, cnt in foreign) + unparsed

    lines = [
        "Warning: failed SSH attempts from foreign IPs.",
        f"Count: {shown_count}",
    ]
    if foreign_ips:
        extra = f" and {len(foreign_ips) - 5} more" if len(foreign_ips) > 5 else ""
        lines.append(f"IP: {', '.join(foreign_ips[:5])}{extra}")
    if unparsed:
        lines.append(f"Without a recognized IPv4 (possibly IPv6): {unparsed}")
    if foreign:
        top_text = ", ".join(f"{ip} ({cnt})" for ip, cnt in foreign[:3])
        lines.append(f"Top IP: {top_text}")
    return "\n".join(lines)


def build_state(login_sessions, smb_sessions, now):
    return {
        "ssh_sessions": [key_login(item) for item in login_sessions],
        "smb_sessions": [key_smb(item) for item in smb_sessions],
        "last_check": now.isoformat(),
        "last_failed_check": now.isoformat(),
    }


def parse_state_time(value: object, now: datetime) -> datetime:
    if not isinstance(value, str) or not value:
        return now - timedelta(minutes=30)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return now - timedelta(minutes=30)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_TZ)
    parsed = parsed.astimezone(LOCAL_TZ)
    if parsed > now:
        return now - timedelta(minutes=30)
    return max(parsed, now - MAX_FAILED_LOOKBACK)


def main() -> int:
    args = parse_args()
    now = datetime.now(LOCAL_TZ)
    whitelist = parse_whitelist()

    try:
        COLLECTOR_ERRORS.clear()
        if not args.dry_run:
            ensure_writable_base()
        if args.test_notify:
            log("INFO", "start notify_mode=telegram test_notify=true")
            send_messages(
                ["Telegram test for security-alert. This is a test, not a real alert."],
                title="NAS: security alert test",
                severity="info",
                source="security-alert",
                dry_run=args.dry_run,
            )
            log("OK", "test notification complete")
            return 0

        state = load_state()
        login_sessions = current_login_sessions()
        smb_sessions = current_smb_sessions()
        old_login = set(state.get("ssh_sessions") or [])
        old_smb = set(state.get("smb_sessions") or [])
        new_login = [
            item
            for item in login_sessions
            if key_login(item) not in old_login
            and not is_trusted_source(item.get("ip", ""), whitelist)
        ]
        new_smb = [
            item
            for item in smb_sessions
            if key_smb(item) not in old_smb and not is_noise_smb_session(item, whitelist)
        ]
        since = parse_state_time(state.get("last_failed_check"), now)
        failed = recent_failed_ssh(since, now)
        next_state = build_state(login_sessions, smb_sessions, now)

        candidate_messages: list[str] = []
        for item in new_login:
            candidate_messages.append(build_login_alert(item, whitelist))
        for item in new_smb:
            candidate_messages.append(build_smb_alert(item, whitelist))
        foreign_failed = [ip for ip in failed.get("ips", []) if not is_trusted_source(ip, whitelist)]
        # Fail closed: failed attempts whose IP could not be parsed (e.g. an IPv6
        # brute-force, since IP_REGEX is IPv4-only) must still raise an alert
        # instead of being silently dropped.
        unclassified = bool(failed.get("count", 0)) and not failed.get("ips")
        if failed.get("count", 0) and (foreign_failed or unclassified):
            candidate_messages.append(build_failed_ssh_alert(failed, whitelist))
        collector_errors = list(COLLECTOR_ERRORS)
        if collector_errors:
            candidate_messages.insert(0, build_collector_alert(collector_errors))

        log("INFO", f"start notify_mode=telegram alerts={len(candidate_messages)}")

        if not candidate_messages:
            if args.dry_run or os.environ.get("VERBOSE", "0") == "1":
                print("NO_ALERT")
                log("EMPTY", "no alerts")
            if not args.dry_run and not collector_errors:
                save_state(next_state)
            return 0

        send_messages(
            candidate_messages,
            title="NAS: security alert",
            severity="warning",
            source="security-alert",
            dry_run=args.dry_run,
        )
        if not args.dry_run and not collector_errors:
            save_state(next_state)
        log("OK", f"notification complete alerts={len(candidate_messages)}")
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
