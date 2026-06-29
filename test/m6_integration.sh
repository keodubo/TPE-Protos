#!/usr/bin/env bash
# test/m6_integration.sh - smoke M6: access-log real del flujo SOCKS5.
set -u
PORT="${1:-11086}"
cd "$(dirname "$0")/.."

LOG="/tmp/m6_srv_${PORT}.log"
BUILD_LOG="/tmp/m6_build_${PORT}.log"

echo "== build server =="
make server >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA"; cat "$BUILD_LOG"; exit 1; }

: >"$LOG"
./bin/server -p "$PORT" -u user:pass >"$LOG" 2>&1 &
SRV=$!
cleanup() {
    kill -TERM "$SRV" 2>/dev/null
    sleep 0.3
    kill -9 "$SRV" 2>/dev/null
}
trap cleanup EXIT

python3 - "$PORT" <<'PY'
import socket
import struct
import sys
import threading
import time

proxy_port = int(sys.argv[1])

HELLO = bytes.fromhex("050102")
AUTH = b"\x01\x04user\x04pass"


def wait_for_proxy(deadline=3.0):
    end = time.monotonic() + deadline
    last = None
    while time.monotonic() < end:
        try:
            s = socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2)
            s.close()
            return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise RuntimeError(f"proxy no acepta conexiones: {last!r}")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def request_ipv4(port):
    return b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port)


def socks_exchange(port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    s.settimeout(2)
    try:
        s.sendall(HELLO)
        assert recv_exact(s, 2) == b"\x05\x02"
        s.sendall(AUTH)
        assert recv_exact(s, 2) == b"\x01\x00"
        s.sendall(request_ipv4(port))
        return recv_exact(s, 10)
    finally:
        s.close()


class Origin:
    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.accepted = threading.Event()

        def accept_once():
            try:
                conn, _ = self.sock.accept()
                self.accepted.set()
                conn.close()
            except OSError:
                pass

        self.thread = threading.Thread(target=accept_once, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.sock.close()
        self.thread.join(timeout=1)


def unused_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


wait_for_proxy()

with Origin() as origin:
    reply = socks_exchange(origin.port)
    assert len(reply) == 10 and reply[1] == 0x00, reply.hex()
    assert origin.accepted.wait(timeout=1)
    print(origin.port)

closed_port = unused_local_port()
reply = socks_exchange(closed_port)
assert len(reply) == 10 and reply[1] != 0x00, reply.hex()
print(closed_port)
PY
PY_STATUS=$?
if [ "$PY_STATUS" -ne 0 ]; then
    echo "TRAFICO FALLA"
    cat "$LOG"
    exit "$PY_STATUS"
fi

# Dar tiempo a que stdout quede flusheado antes de inspeccionar el archivo.
sleep 0.2

if ! grep -Eq $'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\tuser\t127\\.0\\.0\\.1:[0-9]+\t127\\.0\\.0\\.1:[0-9]+\tOK$' "$LOG"; then
    echo "FALTA access-log OK"
    cat "$LOG"
    exit 1
fi

if ! grep -Eq $'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\tuser\t127\\.0\\.0\\.1:[0-9]+\t127\\.0\\.0\\.1:[0-9]+\tFAIL$' "$LOG"; then
    echo "FALTA access-log FAIL"
    cat "$LOG"
    exit 1
fi

echo "== RESULTADO M6: access-log OK y FAIL emitidos =="
