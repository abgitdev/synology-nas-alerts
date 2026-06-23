#!/usr/bin/env python3
"""Telegram-only notification helper for Synology maintenance scripts."""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class NotifyError(RuntimeError):
    pass


ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_env_file(path: str | os.PathLike[str]) -> None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise NotifyError(f"cannot read env file {path}: {exc}") from exc

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise NotifyError(f"invalid env line {path}:{line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not ENV_KEY_RE.match(key):
            raise NotifyError(f"invalid env key {path}:{line_number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _timeout() -> int:
    raw = _env("NOTIFY_TIMEOUT_SECONDS", "20")
    try:
        value = int(raw)
    except ValueError:
        return 20
    return max(3, min(value, 60))


def _telegram_chunks(text: str, limit: int = 3900) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    current = ""
    for line in text.splitlines():
        candidate = f"{current}\n{line}".strip() if current else line
        if len(candidate) <= limit:
            current = candidate
            continue
        if current:
            chunks.append(current)
            current = ""
        while len(line) > limit:
            chunks.append(line[:limit])
            line = line[limit:]
        current = line
    if current:
        chunks.append(current)
    return chunks


def _send_stdout(title: str, message: str) -> None:
    print(title)
    print(message)
    print("---")


def _send_telegram(title: str, message: str, severity: str) -> None:
    token = _env("TELEGRAM_BOT_TOKEN")
    chat_id = _env("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise NotifyError("telegram requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")

    prefix = "[CRITICAL]" if severity == "critical" else "[WARNING]" if severity != "info" else "[INFO]"
    text = f"{prefix} {title}\n\n{message}".strip()
    chunks = _telegram_chunks(text)
    if not chunks:
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for chunk in chunks:
        data = urlencode(
            {
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=_timeout()) as response:
                body = response.read().decode("utf-8", errors="replace")
                payload = json.loads(body)
        except HTTPError as exc:
            raise NotifyError(f"telegram HTTP {exc.code}") from exc
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            reason_name = type(reason).__name__ if reason is not None else type(exc).__name__
            raise NotifyError(f"telegram network error: {reason_name}") from exc
        except TimeoutError as exc:
            raise NotifyError("telegram network timeout") from exc
        except OSError as exc:
            raise NotifyError(f"telegram transport error: {type(exc).__name__}") from exc
        except json.JSONDecodeError as exc:
            raise NotifyError("telegram returned invalid JSON") from exc

        if not payload.get("ok"):
            description = str(payload.get("description") or "request rejected")
            raise NotifyError(f"telegram rejected message: {description[:120]}")


def send_message(title: str, message: str, *, severity: str = "info", source: str = "") -> None:
    configured = _env("NOTIFY_CHANNELS", "telegram").lower()
    if configured and configured != "telegram":
        raise NotifyError("only telegram channel is supported")
    try:
        _send_telegram(title, message, severity)
    except Exception as exc:
        print(f"WARN telegram notification failed: {exc}", file=sys.stderr, flush=True)
        raise


def send_messages(
    messages: list[str],
    *,
    title: str,
    severity: str = "info",
    source: str = "",
    dry_run: bool = False,
) -> None:
    for index, message in enumerate(messages, start=1):
        item_title = title if len(messages) == 1 else f"{title} ({index}/{len(messages)})"
        if dry_run:
            _send_stdout(item_title, message)
        else:
            send_message(item_title, message, severity=severity, source=source)
