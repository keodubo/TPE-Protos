#!/usr/bin/env bash
# test/m5_integration.sh - FQDN, IPv6 y retry multi-IP.
set -u
PORT="${1:-11085}"
MGMT_PORT=$((PORT + 1000))
cd "$(dirname "$0")/.."
# shellcheck source=integration_lib.sh
. "$(dirname "$0")/integration_lib.sh"
BUILD_LOG="$(tpe_mktemp m5_build)"
SRV_LOG="$(tpe_mktemp m5_srv)"
M5_L_IPV6_LOG="$(tpe_mktemp m5_l_ipv6)"
M5_L_BAD_LOG="$(tpe_mktemp m5_l_bad)"
cleanup() {
    kill -TERM "$SRV" 2>/dev/null
    sleep 0.3
    kill -9 "$SRV" 2>/dev/null
    rm -f "$BUILD_LOG" "$SRV_LOG" "$M5_L_IPV6_LOG" "$M5_L_BAD_LOG"
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
skips = 0

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


def skip(msg):
    # skip explícito: NO cuenta como ok ni como falla.
    global skips
    skips += 1
    print(f"  SKIP- {msg}")


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

# ---------------------------------------------------------------------------
# Caso B: retry multi-IP DETERMINISTICO.
# Resolvemos localhost (debe dar >=2 familias). Levantamos el origin SOLO en la
# familia que getaddrinfo devuelve SEGUNDA y dejamos la PRIMERA direccion sin
# nadie escuchando (connect a ella -> ECONNREFUSED, comprobado en vivo). Asi el
# proxy DEBE: intentar la 1ra direccion, fallar el connect, y reintentar la 2da
# (request_connect_next). Que el body de la 2da llegue prueba el retry real.
def first_addr_refuses(host, port, family):
    # devuelve True si un connect directo a la PRIMERA direccion es rechazado.
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    if not infos:
        return False
    af, socktype, proto, _, sa = infos[0]
    probe = socket.socket(af, socktype, proto)
    probe.settimeout(1.0)
    try:
        probe.connect(sa)
        probe.close()
        return False  # alguien escucha: NO sirve para forzar retry
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    finally:
        try:
            probe.close()
        except OSError:
            pass


if len(families) < 2:
    skip("B: retry multi-IP no aplicable: localhost no expone dos familias")
else:
    first_family = families[0]
    retry_family = families[1]
    origin = Origin(retry_family, b"multi-ip-ok")
    try:
        # reconfirmar el orden con el puerto real del origin y que la PRIMERA
        # direccion (sin listener) rechace el connect.
        actual = distinct_localhost_families(origin.port)
        ordered = actual == families or (actual and actual[0] == first_family)
        refused = first_addr_refuses("localhost", origin.port, socket.AF_UNSPEC)
        if not (ordered and refused):
            skip("B: el entorno no garantiza 1ra direccion cerrada + 2da abierta "
                 f"(orden={[f.name for f in actual]} refused={refused})")
        else:
            hello, auth, reply, body = socks_exchange(
                request_fqdn("localhost", origin.port), "localhost")
            check(len(reply) in (10, 22) and reply[1] == 0x00,
                  "B: FQDN con 1ra direccion cerrada -> REP success (tras retry)",
                  reply.hex(), "05 00 ...")
            check(b"multi-ip-ok" in body,
                  "B: retry multi-IP alcanza la 2da direccion y relayea su body",
                  body[-32:], b"...multi-ip-ok")
            check(origin.accepted.is_set(),
                  "B: el origin de la 2da direccion efectivamente acepto la conexion")
    finally:
        origin.close()

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

print(f"== RESULTADO M5: {checks - failures} ok, {failures} fallas, {skips} skips ==")
sys.exit(0 if failures == 0 else 1)
PY
PY_RC=$?

# ---------------------------------------------------------------------------
# Caso D (f6): bind del socket pasivo según -l.
#   D1) -l ::1  -> el server debe escuchar SOLO en IPv6 loopback, no en 0.0.0.0.
#   D2) -l noEsUnaIP -> literal inválido: el server DEBE fallar (exit != 0) con
#       diagnóstico en stderr, en vez de caer mudo a INADDR_ANY (0.0.0.0).
# Estos casos levantan instancias EFÍMERAS del server, aparte del proxy del
# trap de arriba.
# ---------------------------------------------------------------------------
f6_fail=0
f6_check() {
    # $1: cond (0=ok), $2: msg
    if [ "$1" -eq 0 ]; then
        echo "  ok  - $2"
    else
        echo "  FAIL- $2"
        f6_fail=1
    fi
}

# D1: -l ::1 escucha en IPv6 loopback (y NO en 0.0.0.0 IPv4).
D1_PORT=$((PORT + 1))
D1_MGMT_PORT=$((MGMT_PORT + 1))
./bin/server -l ::1 -p "$D1_PORT" -P "$D1_MGMT_PORT" -u user:pass >"$M5_L_IPV6_LOG" 2>&1 &
D1=$!
sleep 0.4
if kill -0 "$D1" 2>/dev/null; then
    # conexión por ::1 debe funcionar
    python3 -c "import socket,sys
try:
    socket.create_connection(('::1', $D1_PORT), timeout=1).close()
    sys.exit(0)
except OSError:
    sys.exit(1)" && f6_check 0 "D1: -l ::1 acepta conexiones en IPv6 loopback" \
        || f6_check 1 "D1: -l ::1 acepta conexiones en IPv6 loopback"
    # conexión por 127.0.0.1 (IPv4) NO debe funcionar (bind solo-IPv6)
    if python3 -c "import socket,sys
try:
    socket.create_connection(('127.0.0.1', $D1_PORT), timeout=1).close()
    sys.exit(0)
except OSError:
    sys.exit(1)"; then
        f6_check 1 "D1: -l ::1 NO escucha en 0.0.0.0 IPv4 (no debería aceptar 127.0.0.1)"
    else
        f6_check 0 "D1: -l ::1 NO escucha en 0.0.0.0 IPv4"
    fi
else
    f6_check 1 "D1: -l ::1 el server arrancó (no debería abortar con IPv6 loopback)"
fi
kill -TERM "$D1" 2>/dev/null; wait "$D1" 2>/dev/null

# D2: -l noEsUnaIP debe fallar con exit != 0 y diagnóstico en stderr.
./bin/server -l noEsUnaIP -p $((PORT + 2)) -P $((MGMT_PORT + 2)) -u user:pass >"$M5_L_BAD_LOG" 2>&1
D2_RC=$?
if [ "$D2_RC" -ne 0 ]; then
    f6_check 0 "D2: -l con literal inválido falla con exit != 0 (no cae mudo a 0.0.0.0)"
else
    f6_check 1 "D2: -l con literal inválido falla con exit != 0"
fi
if grep -qi "direcci\|-l\|literal\|IPv4\|IPv6" "$M5_L_BAD_LOG"; then
    f6_check 0 "D2: -l inválido emite diagnóstico en stderr"
else
    f6_check 1 "D2: -l inválido emite diagnóstico en stderr"
fi

if [ "$PY_RC" -ne 0 ] || [ "$f6_fail" -ne 0 ]; then
    exit 1
fi
exit 0
