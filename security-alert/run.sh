#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BASE_DIR="${SECURITY_ALERT_BASE_DIR:-$SCRIPT_DIR}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MAX_SECONDS="${SECURITY_ALERT_MAX_SECONDS:-${NAS_ALERT_MAX_SECONDS:-180}}"
LOCK_DIR="$BASE_DIR/.run.lock"
LOCK_PID="$LOCK_DIR/pid"
LOCK_STARTED="$LOCK_DIR/started"
CHILD_PID=""

export TZ="${TZ:-UTC}"
export PYTHONDONTWRITEBYTECODE=1
umask 077

LOG_CLEAN_MARK="$BASE_DIR/.log-cleanup.stamp"
cleanup_old_logs() {
  NOW=$(date +%s 2>/dev/null || echo 0)
  LAST=0
  if [ -f "$LOG_CLEAN_MARK" ]; then
    LAST=$(cat "$LOG_CLEAN_MARK" 2>/dev/null || echo 0)
  fi
  case "$NOW:$LAST" in
    *[!0-9:]*|0:*) return 0 ;;
  esac
  if [ $((NOW - LAST)) -ge 604800 ]; then
    find "$BASE_DIR" -maxdepth 1 -type f -name 'run.log.*' -mtime +7 -exec rm -f {} \; 2>/dev/null || true
    printf '%s\n' "$NOW" > "$LOG_CLEAN_MARK" 2>/dev/null || true
  fi
}
cleanup_old_logs

lock_expired() {
  NOW=$(date +%s 2>/dev/null || echo 0)
  STARTED=0
  if [ -f "$LOCK_STARTED" ]; then
    STARTED=$(cat "$LOCK_STARTED" 2>/dev/null || echo 0)
  fi
  case "$NOW:$STARTED" in
    *[!0-9:]*|0:*|*:0) return 1 ;;
  esac
  [ $((NOW - STARTED)) -ge $((MAX_SECONDS + 60)) ]
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  OLD_PID=""
  if [ -f "$LOCK_PID" ]; then
    OLD_PID=$(cat "$LOCK_PID" 2>/dev/null || true)
  fi
  if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
    rm -f "$LOCK_PID" "$LOCK_STARTED"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    mkdir "$LOCK_DIR" 2>/dev/null || {
      echo "Already running: $BASE_DIR" >&2
      exit 75
    }
  elif lock_expired; then
    rm -f "$LOCK_PID" "$LOCK_STARTED"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    mkdir "$LOCK_DIR" 2>/dev/null || {
      echo "Already running: $BASE_DIR" >&2
      exit 75
    }
  else
    echo "Already running: $BASE_DIR" >&2
    exit 75
  fi
fi
echo "$$" > "$LOCK_PID"
date +%s > "$LOCK_STARTED" 2>/dev/null || true

cleanup() {
  if [ -n "$CHILD_PID" ] && kill -0 "$CHILD_PID" 2>/dev/null; then
    kill "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
  fi
  rm -f "$LOCK_PID"
  rm -f "$LOCK_STARTED"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
terminate() {
  cleanup
  exit 143
}
trap cleanup EXIT
trap terminate HUP INT TERM

/usr/bin/env "$PYTHON_BIN" "$BASE_DIR/digest.py" "$@" &
CHILD_PID=$!
ELAPSED=0
while kill -0 "$CHILD_PID" 2>/dev/null; do
  if [ "$ELAPSED" -ge "$MAX_SECONDS" ]; then
    kill "$CHILD_PID" 2>/dev/null || true
    sleep 2
    kill -KILL "$CHILD_PID" 2>/dev/null || true
    wait "$CHILD_PID" 2>/dev/null || true
    CHILD_PID=""
    echo "Timeout after ${MAX_SECONDS}s: $BASE_DIR" >&2
    exit 124
  fi
  sleep 1
  ELAPSED=$((ELAPSED + 1))
done

set +e
wait "$CHILD_PID"
STATUS=$?
set -e
CHILD_PID=""
exit "$STATUS"
