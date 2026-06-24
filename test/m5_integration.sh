#!/usr/bin/env bash
# test/m5_integration.sh - FQDN, IPv6 y retry multi-IP.
set -u
PORT="${1:-11085}"
cd "$(dirname "$0")/.."

echo "== build server =="
make server >/tmp/m5_build.log 2>&1 || { echo "BUILD FALLA"; cat /tmp/m5_build.log; exit 1; }

./bin/server -p "$PORT" -u user:pass >/tmp/m5_srv.log 2>&1 &
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


def recv_all(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


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


def family_host(family):
    return "::1" if family == socket.AF_INET6 else "127.0.0.1"


class Origin:
    def __init__(self, family, body):
        self.family = family
        self.body = body
        self.accepted = threading.Event()
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((family_host(family), 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            self.accepted.set()
            conn.settimeout(3)
            try:
                conn.recv(4096)
                payload = b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(self.body)).encode()
                payload += b"\r\n\r\n" + self.body
                conn.sendall(payload)
            finally:
                conn.close()
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=1)


def request_fqdn(name, port):
    raw = name.encode("ascii")
    return b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)


def request_ipv6_loopback(port):
    return b"\x05\x01\x00\x04" + (b"\x00" * 15) + b"\x01" + struct.pack("!H", port)


def recv_reply(sock):
    head = recv_exact(sock, 4)
    if len(head) != 4:
        return head
    atyp = head[3]
    addr_len = 4 if atyp == 1 else 16 if atyp == 4 else None
    if addr_len is None:
        return head
    return head + recv_exact(sock, addr_len + 2)


def socks_exchange(req, host_header):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    s.settimeout(4)
    s.sendall(HELLO)
    hello = recv_exact(s, 2)
    s.sendall(AUTH)
    auth = recv_exact(s, 2)
    s.sendall(req)
    reply = recv_reply(s)
    if len(reply) >= 2 and reply[1] == 0:
        http = f"GET / HTTP/1.0\r\nHost: {host_header}\r\n\r\n".encode()
        s.sendall(http)
        body = recv_all(s)
    else:
        body = b""
    s.close()
    return hello, auth, reply, body


def distinct_localhost_families(port):
    families = []
    for item in socket.getaddrinfo("localhost", port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        fam = item[0]
        if fam in (socket.AF_INET, socket.AF_INET6) and fam not in families:
            families.append(fam)
    return families


ready, error = wait_for_proxy()
check(ready, "setup: proxy acepta conexiones", repr(error), "ready")
if not ready:
    sys.exit(1)

families = distinct_localhost_families(80)
fqdn_family = families[0] if families else socket.AF_INET
origin = Origin(fqdn_family, b"fqdn-ok")
try:
    hello, auth, reply, body = socks_exchange(request_fqdn("localhost", origin.port), "localhost")
    check(hello + auth == b"\x05\x02\x01\x00", "A: handshake FQDN OK",
          (hello + auth).hex(), "05020100")
    check(len(reply) in (10, 22) and reply[1] == 0x00,
          "A: FQDN localhost -> REP success", reply.hex(), "05 00 ...")
    check(b"fqdn-ok" in body, "A: relay HTTP por FQDN conserva respuesta")
finally:
    origin.close()

if len(families) >= 2:
    retry_family = families[1]
    origin = Origin(retry_family, b"multi-ip-ok")
    try:
        actual = distinct_localhost_families(origin.port)
        forced_retry = actual and actual[0] != retry_family and retry_family in actual[1:]
        hello, auth, reply, body = socks_exchange(request_fqdn("localhost", origin.port), "localhost")
        check(len(reply) in (10, 22) and reply[1] == 0x00,
              "B: FQDN localhost con familia inicial cerrada -> REP success",
              reply.hex(), "05 00 ...")
        check(b"multi-ip-ok" in body,
              "B: retry multi-IP llega a la direccion posterior")
        check(forced_retry,
              "B: entorno ordeno localhost para forzar retry",
              repr([f.name for f in actual]), "primera familia distinta del origin")
    finally:
        origin.close()
else:
    check(True, "B: retry multi-IP no aplicable: localhost no expone dos familias")

try:
    origin = Origin(socket.AF_INET6, b"ipv6-ok")
except OSError as exc:
    check(False, "C: entorno permite bind IPv6 ::1", repr(exc), "IPv6 loopback")
else:
    try:
        hello, auth, reply, body = socks_exchange(request_ipv6_loopback(origin.port), "[::1]")
        check(hello + auth == b"\x05\x02\x01\x00", "C: handshake IPv6 OK",
              (hello + auth).hex(), "05020100")
        check(len(reply) == 22 and reply[:4] == b"\x05\x00\x00\x04",
              "C: IPv6 ::1 -> REP success IPv6", reply.hex(), "05000004 + 18 bytes")
        check(b"ipv6-ok" in body, "C: relay HTTP por IPv6 conserva respuesta")
    finally:
        origin.close()

print(f"== RESULTADO M5: {checks - failures} ok, {failures} fallas ==")
sys.exit(0 if failures == 0 else 1)
PY
