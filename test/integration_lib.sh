#!/usr/bin/env bash
# Archivos temporales únicos para tests de integración.
# En pampero /tmp es compartido: rutas fijas (/tmp/m1_build.log) fallan si otro
# usuario ya las creó (Permission denied al redirigir stdout).

tpe_mktemp() {
  local dir="${TMPDIR:-/tmp}"
  dir="${dir%/}"
  [ -n "$dir" ] || dir="/tmp"
  mktemp "$dir/tpe_${1}.XXXXXX"
}

tpe_wait_server() {
  local pid="$1" port="$2" log="${3:-}"
  python3 - "$pid" "$port" <<'PY'
import os
import subprocess
import socket
import sys
import time

pid = int(sys.argv[1])
port = int(sys.argv[2])
deadline = time.monotonic() + 3.0
last = None
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except OSError:
        print(f"server pid {pid} exited before port {port} was ready", file=sys.stderr)
        sys.exit(2)
    ps = subprocess.run(["ps", "-p", str(pid), "-o", "stat="],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        text=True)
    if ps.returncode != 0 or "Z" in ps.stdout:
        print(f"server pid {pid} is not running before port {port} was ready",
              file=sys.stderr)
        sys.exit(2)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
        s.close()
        sys.exit(0)
    except OSError as exc:
        last = exc
        time.sleep(0.05)
print(f"server pid {pid} alive but port {port} not ready: {last!r}", file=sys.stderr)
sys.exit(1)
PY
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -n "$log" ]; then
    echo "== server log =="
    cat "$log"
  fi
  return "$rc"
}

tpe_stop_server() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill -TERM "$pid" 2>/dev/null || return 0
  sleep 0.3
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
