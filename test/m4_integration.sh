#!/usr/bin/env bash
# test/m4_integration.sh - integracion del relay COPY bidireccional.
set -u
PORT="${1:-11084}"
MGMT_PORT=$((PORT + 1000))
cd "$(dirname "$0")/.."

echo "== build server =="
make server >/tmp/m4_build.log 2>&1 || { echo "BUILD FALLA"; cat /tmp/m4_build.log; exit 1; }

./bin/server -p "$PORT" -P "$MGMT_PORT" -u user:pass >/tmp/m4_srv.log 2>&1 &
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
checks = 0
failures = 0

HELLO = b"\x05\x01\x02"
AUTH = b"\x01\x04user\x04pass"


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


def make_request(port):
    return b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", port)


class Origin:
    def __init__(self, expected, response):
        self.expected = expected
        self.response = response
        self.received = b""
        self.done = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(3)
            try:
                self.received = recv_exact(conn, len(self.expected))
                conn.sendall(self.response)
                conn.shutdown(socket.SHUT_WR)
                while conn.recv(4096):
                    pass
            finally:
                conn.close()
        except OSError:
            pass
        finally:
            self.done.set()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=1)


def socks_connect(port, pipeline_payload=b""):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    s.settimeout(3)
    req = make_request(port)
    if pipeline_payload:
        s.sendall(HELLO + AUTH + req + pipeline_payload)
        prefix = recv_exact(s, 14)
        return s, prefix[:2], prefix[2:4], prefix[4:14]
    s.sendall(HELLO)
    hello = recv_exact(s, 2)
    s.sendall(AUTH)
    auth = recv_exact(s, 2)
    s.sendall(req)
    reply = recv_exact(s, 10)
    return s, hello, auth, reply


ready, error = wait_for_proxy()
check(ready, "setup: proxy acepta conexiones", repr(error), "ready")
if not ready:
    sys.exit(1)

upload = bytes((i % 251 for i in range(24000)))
download = bytes(((255 - i) % 251 for i in range(32000)))
origin = Origin(upload, download)
try:
    client, hello, auth, reply = socks_connect(origin.port)
    check(hello == b"\x05\x02", "A: HELLO -> USERPASS", hello.hex(), "0502")
    check(auth == b"\x01\x00", "A: AUTH correcto -> OK", auth.hex(), "0100")
    check(len(reply) == 10 and reply[:4] == b"\x05\x00\x00\x01",
          "A: CONNECT IPv4 local -> REP success", reply.hex(), "05000001 + 6 bytes")
    client.sendall(upload)
    client.shutdown(socket.SHUT_WR)
    received = recv_exact(client, len(download))
    client.close()
    origin.done.wait(timeout=3)
    check(origin.received == upload, "A: client->origin conserva bytes",
          len(origin.received), len(upload))
    check(received == download, "A: origin->client conserva bytes",
          len(received), len(download))
finally:
    origin.close()

early = b"early-payload-" + bytes(range(64))
reply_data = b"reply-after-early-" + bytes(range(200))
origin = Origin(early, reply_data)
try:
    client, hello, auth, reply = socks_connect(origin.port, early)
    check(hello + auth == b"\x05\x02\x01\x00",
          "B: HELLO+AUTH+REQUEST+payload pipelined mantiene orden",
          (hello + auth).hex(), "05020100")
    check(len(reply) == 10 and reply[:4] == b"\x05\x00\x00\x01",
          "B: CONNECT pipelined -> REP success", reply.hex(), "05000001 + 6 bytes")
    client.shutdown(socket.SHUT_WR)
    received = recv_exact(client, len(reply_data))
    client.close()
    origin.done.wait(timeout=3)
    check(origin.received == early, "B: payload temprano llega al origin",
          origin.received.hex(), early.hex())
    check(received == reply_data, "B: respuesta al payload temprano llega al cliente",
          received.hex(), reply_data.hex())
finally:
    origin.close()

# --- Caso C: backpressure observable ---------------------------------------
# El cliente manda un payload >> (buffers del proxy + buffers de socket) hacia
# un origin que NO lee durante un rato. El proxy NO puede bloquear: debe apagar
# OP_READ del cliente cuando su buffer de salida hacia el origin se llena, y
# rehabilitarlo cuando el origin drena. Verificamos que, pese al stall inicial,
# el payload completo llega y el proxy sigue vivo (acepta otra conexión).
class SlowOrigin:
    def __init__(self, total, stall=0.6):
        self.total = total
        self.stall = stall
        self.received = 0
        self.done = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            try:
                time.sleep(self.stall)  # no leer -> fuerza backpressure
                while self.received < self.total:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    self.received += len(chunk)
            finally:
                conn.close()
        except OSError:
            pass
        finally:
            self.done.set()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


big = bytes((i % 251 for i in range(300000)))  # >> IO_BUFFER_SIZE default 8192
origin = SlowOrigin(len(big))
try:
    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    client.settimeout(8)
    client.sendall(HELLO)
    check(recv_exact(client, 2) == b"\x05\x02", "C: HELLO -> USERPASS")
    client.sendall(AUTH)
    check(recv_exact(client, 2) == b"\x01\x00", "C: AUTH correcto -> OK")
    client.sendall(make_request(origin.port))
    reply = recv_exact(client, 10)
    check(len(reply) == 10 and reply[:4] == b"\x05\x00\x00\x01",
          "C: CONNECT -> REP success", reply.hex(), "05000001 + 6 bytes")
    client.sendall(big)  # bloquearía si el proxy no aplicara backpressure NO-bloqueante
    client.shutdown(socket.SHUT_WR)
    origin.done.wait(timeout=8)
    client.close()
    check(origin.received == len(big),
          "C: payload grande con peer lento llega completo (backpressure)",
          origin.received, len(big))
    ready_again, err2 = wait_for_proxy()
    check(ready_again, "C: el proxy sigue vivo tras backpressure", repr(err2), "ready")
finally:
    origin.close()

print(f"== RESULTADO M4: {checks - failures} ok, {failures} fallas ==")
sys.exit(0 if failures == 0 else 1)
PY
