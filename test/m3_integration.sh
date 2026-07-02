#!/usr/bin/env bash
# test/m3_integration.sh - integracion de REQUEST + CONNECT IPv4 (M3, RFC1928).
# Habla SOCKS5 por sockets reales: HELLO, AUTH y REQUEST.
set -u
PORT="${1:-11083}"
MGMT_PORT=$((PORT + 1000))
cd "$(dirname "$0")/.."
# shellcheck source=integration_lib.sh
. "$(dirname "$0")/integration_lib.sh"
BUILD_LOG="$(tpe_mktemp m3_build)"
SRV_LOG="$(tpe_mktemp m3_srv)"
cleanup() {
    kill -TERM "$SRV" 2>/dev/null
    sleep 0.3
    kill -9 "$SRV" 2>/dev/null
    rm -f "$BUILD_LOG" "$SRV_LOG"
}
trap cleanup EXIT

echo "== build server =="
make server >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA"; cat "$BUILD_LOG"; exit 1; }

./bin/server -p "$PORT" -P "$MGMT_PORT" -u user:pass >"$SRV_LOG" 2>&1 &
SRV=$!

python3 - "$PORT" <<'PY'
import socket
import struct
import sys
import threading
import time

proxy_port = int(sys.argv[1])
checks = 0
failures = 0

HELLO = bytes.fromhex("050102")
AUTH = b"\x01\x04user\x04pass"


def wait_for_proxy(deadline=3.0):
    end = time.monotonic() + deadline
    last_error = None
    while time.monotonic() < end:
        try:
            s = socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2)
            s.close()
            return True, None
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    return False, last_error


def unused_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def check(cond, msg, got=None, want=None):
    global checks, failures
    checks += 1
    if cond:
        print(f"  ok  - {msg}")
    else:
        failures += 1
        detail = ""
        if got is not None or want is not None:
            detail = f" (got [{got}] want [{want}])"
        print(f"  FAIL- {msg}{detail}")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def make_request(cmd, atyp, addr=b"\x7f\x00\x00\x01", port=80, fqdn=b"example.com"):
    if atyp == 0x01:
        body = addr
    elif atyp == 0x03:
        body = bytes([len(fqdn)]) + fqdn
    else:
        body = b""
    return b"\x05" + bytes([cmd]) + b"\x00" + bytes([atyp]) + body + struct.pack("!H", port)


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
                conn.settimeout(1)
                try:
                    conn.recv(1)
                except (socket.timeout, OSError):
                    pass
                conn.close()
            except OSError:
                pass

        self.thread = threading.Thread(target=accept_once, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=1)


def connect_proxy():
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    s.settimeout(2)
    return s


def sequential_exchange(request):
    s = connect_proxy()
    try:
        s.sendall(HELLO)
        hello = recv_exact(s, 2)
        s.sendall(AUTH)
        auth = recv_exact(s, 2)
        s.sendall(request)
        reply = recv_exact(s, 10)
        return hello, auth, reply
    finally:
        s.close()


def pipelined_exchange(request, extra=b""):
    s = connect_proxy()
    try:
        s.sendall(HELLO + AUTH + request + extra)
        return recv_exact(s, 14)
    finally:
        s.close()


ready, error = wait_for_proxy()
check(ready, "setup: proxy acepta conexiones", repr(error), "ready")
if not ready:
    print(f"== RESULTADO M3: {checks - failures} ok, {failures} fallas ==")
    sys.exit(1)

with Origin() as origin:
    req = make_request(0x01, 0x01, port=origin.port)
    hello, auth, reply = sequential_exchange(req)
    check(hello == b"\x05\x02", "A: HELLO -> USERPASS", hello.hex(), "0502")
    check(auth == b"\x01\x00", "A: AUTH correcto -> OK", auth.hex(), "0100")
    check(len(reply) == 10 and reply[:4] == b"\x05\x00\x00\x01",
          "A: CONNECT IPv4 local -> REP success", reply.hex(), "05000001 + 6 bytes")
    check(origin.accepted.wait(timeout=1), "A: origin local recibio el connect")

closed_port = unused_local_port()
closed_req = make_request(0x01, 0x01, port=closed_port)
hello, auth, reply = sequential_exchange(closed_req)
check(hello + auth == b"\x05\x02\x01\x00", "B: handshake previo OK", (hello + auth).hex(), "05020100")
check(len(reply) == 10 and reply[1] == 0x05,
      f"B: puerto cerrado 127.0.0.1:{closed_port} -> REP 0x05", reply.hex(), "05 05 00 01 ...")

cmd_req = make_request(0x02, 0x01)
hello, auth, reply = sequential_exchange(cmd_req)
check(hello + auth == b"\x05\x02\x01\x00", "C: handshake previo OK", (hello + auth).hex(), "05020100")
check(len(reply) == 10 and reply[1] == 0x07,
      "C: CMD unsupported -> REP 0x07", reply.hex(), "05 07 00 01 ...")

bad_atyp_req = make_request(0x01, 0x09, port=80)
hello, auth, reply = sequential_exchange(bad_atyp_req)
check(hello + auth == b"\x05\x02\x01\x00", "D: handshake previo OK", (hello + auth).hex(), "05020100")
check(len(reply) == 10 and reply[1] == 0x08,
      "D: ATYP unsupported -> REP 0x08", reply.hex(), "05 08 00 01 ...")

with Origin() as origin:
    req = make_request(0x01, 0x01, port=origin.port)
    # M3 no implementa relay, pero debe tolerar que llegue al menos un byte
    # temprano sin romper el orden de las respuestas. El backpressure de buffers
    # grandes queda cubierto por la lógica del estado y se termina de ejercer en M4.
    got = pipelined_exchange(req, b"x")
    check(got[:4] == b"\x05\x02\x01\x00", "E: HELLO+AUTH+REQUEST pipelined mantiene orden",
          got[:4].hex(), "05020100")
    check(len(got) == 14 and got[4:8] == b"\x05\x00\x00\x01",
          "E: request pipelined con payload temprano -> REP success",
          got.hex(), "0502010005000001 + 6 bytes")
    check(origin.accepted.wait(timeout=1), "E: origin local recibio el connect pipelined")

print(f"== RESULTADO M3: {checks - failures} ok, {failures} fallas ==")
sys.exit(0 if failures == 0 else 1)
PY
