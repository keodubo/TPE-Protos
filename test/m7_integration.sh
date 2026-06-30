#!/usr/bin/env bash
# test/m7_integration.sh - smoke M7: listener de management en el mismo server.
set -u
SOCKS_PORT="${1:-11087}"
MGMT_PORT=$((SOCKS_PORT + 1000))
cd "$(dirname "$0")/.."

BUILD_LOG="/tmp/m7_build_${SOCKS_PORT}.log"
SRV_LOG="/tmp/m7_srv_${SOCKS_PORT}.log"

echo "== build server =="
make server >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA"; cat "$BUILD_LOG"; exit 1; }

: >"$SRV_LOG"
./bin/server -p "$SOCKS_PORT" -P "$MGMT_PORT" --admin root:toor -u user:pass >"$SRV_LOG" 2>&1 &
SRV=$!
cleanup() {
    kill -TERM "$SRV" 2>/dev/null
    sleep 0.3
    kill -9 "$SRV" 2>/dev/null
}
trap cleanup EXIT

python3 - "$SOCKS_PORT" "$MGMT_PORT" <<'PY'
import socket
import sys
import time

socks_port = int(sys.argv[1])
mgmt_port = int(sys.argv[2])


def wait_for_port(port, deadline=3.0):
    end = time.monotonic() + deadline
    last = None
    while time.monotonic() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return True, None
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    return False, last


checks = 0
failures = 0


def check(cond, msg, got=None):
    global checks, failures
    checks += 1
    if cond:
        print(f"  ok  - {msg}")
    else:
        failures += 1
        detail = f" ({got!r})" if got is not None else ""
        print(f"  FAIL- {msg}{detail}")


ready, err = wait_for_port(socks_port)
check(ready, "setup: proxy SOCKS acepta conexiones", err)

ready, err = wait_for_port(mgmt_port)
check(ready, "A: listener management acepta conexiones TCP", err)

def recv_line(sock):
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def mgmt_exchange(payload, expected_lines):
    s = socket.create_connection(("127.0.0.1", mgmt_port), timeout=2)
    s.settimeout(2)
    try:
        s.sendall(payload)
        return [recv_line(s) for _ in expected_lines]
    finally:
        s.close()


got = mgmt_exchange(b"HELLO 1\r\nAUTH root toor\r\n",
                    [b"+OK 1\r\n", b"+OK\r\n"])
check(got == [b"+OK 1\r\n", b"+OK\r\n"],
      "B: HELLO 1 + AUTH admin configurado correctos", got)

got = mgmt_exchange(b"HELLO 2\r\n", [b"-ERR unsupported version\r\n"])
check(got == [b"-ERR unsupported version\r\n"],
      "C: version PMC no soportada -> -ERR", got)

got = mgmt_exchange(b"HELLO 1\r\nAUTH admin wrong\r\n",
                    [b"+OK 1\r\n", b"-ERR auth failed\r\n"])
check(got == [b"+OK 1\r\n", b"-ERR auth failed\r\n"],
      "D: AUTH invalido -> -ERR auth failed", got)

got = mgmt_exchange(b"METRICS\r\n", [b"-ERR not authenticated\r\n"])
check(got == [b"-ERR not authenticated\r\n"],
      "E: comando antes de auth -> -ERR not authenticated", got)

print(f"== RESULTADO M7: {checks - failures} ok, {failures} fallas ==")
sys.exit(0 if failures == 0 else 1)
PY
