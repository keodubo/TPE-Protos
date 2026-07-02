#!/usr/bin/env bash
# test/valgrind_traffic.sh
# ------------------------------------------------------------------------------
# Leak / use-after-free check del proxy SOCKS5 CON TRÁFICO REAL bajo valgrind.
#
# ¿Por qué existe?
#   El leak-check "tradicional" levanta el server bajo valgrind y solo le manda
#   un HELLO; nunca ejercita el camino REQUEST + CONNECT (origin fd, refcount,
#   teardown en rutas de error). Eso deja sin cubrir justo donde viven los bugs
#   de fd-lifecycle / use-after-free. Este script atraviesa el server bajo
#   valgrind con una batería de conexiones M3 y RECIÉN DESPUÉS lo apaga limpio
#   (SIGTERM) para que valgrind analice. Falla si hay errores o leaks.
#
# Batería de tráfico (cada caso recorre un teardown distinto):
#   - N CONNECT IPv4 exitosos (secuenciales + concurrentes) -> reuso del pool
#   - CONNECT a puerto cerrado -> connect async falla (REP 0x05) + unregister
#   - CMD no soportado (0x07), ATYP invalido (0x08) y FQDN localhost
#   - HELLO+AUTH+REQUEST pipelined con payload temprano
#   - cierres abruptos del cliente en CADA estado (HELLO, AUTH, REQUEST parcial,
#     post-reply)
#   - cliente cierra / floodea DURANTE un connect pendiente (IP no ruteable):
#     ejercita el teardown con origin fd registrado y connect en vuelo
#   - APAGADO BAJO CARGA DNS (f14): ráfaga de CONNECT por FQDN que lanzan
#     getaddrinfo en hilos detached, con cierres tempranos del cliente; el
#     SIGTERM puede caer con resoluciones en vuelo -> valida el drenaje de hilos
#     DNS (sin UAF del selector ni leak del struct socks5/origin_resolution)
#
# Uso (Linux con valgrind + python3; p.ej. pampero):
#   bash test/valgrind_traffic.sh [puerto]
#   make valgrind                       # equivalente vía Makefile
#
# Por defecto, si falta valgrind/python3 falla. Para saltear explícitamente en
# un entorno local sin esas herramientas:
#   SKIP_VALGRIND_IF_MISSING=1 bash test/valgrind_traffic.sh [puerto]
# ------------------------------------------------------------------------------
set -u
PORT="${1:-11090}"
cd "$(dirname "$0")/.."
# shellcheck source=integration_lib.sh
. "$(dirname "$0")/integration_lib.sh"

skip_if_missing="${SKIP_VALGRIND_IF_MISSING:-0}"
if ! command -v valgrind >/dev/null 2>&1; then
  if [ "$skip_if_missing" = "1" ]; then
    echo "(valgrind no instalado: saltando leak check con tráfico por SKIP_VALGRIND_IF_MISSING=1)"
    exit 0
  fi
  echo "valgrind no instalado: corré este target en Linux/pampero o usá SKIP_VALGRIND_IF_MISSING=1 para saltearlo explícitamente"
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  if [ "$skip_if_missing" = "1" ]; then
    echo "(python3 no instalado: saltando leak check con tráfico por SKIP_VALGRIND_IF_MISSING=1)"
    exit 0
  fi
  echo "python3 no instalado: no puedo generar tráfico SOCKS5"
  exit 1
fi

echo "===== build ====="
BUILD_LOG="$(tpe_mktemp vgt_build)"
SRV_LOG="$(tpe_mktemp vgt_srv)"
VGLOG="$(tpe_mktemp vg_traffic)"
make server >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA ❌"; cat "$BUILD_LOG"; exit 1; }

echo "===== valgrind + tráfico M3 (proxy en 127.0.0.1:$PORT) ====="

# Arch (pampero) stripea ld.so -> valgrind baja símbolos por debuginfod (sin root).
DEBUGINFOD_URLS="${DEBUGINFOD_URLS:-https://debuginfod.archlinux.org}" \
valgrind --leak-check=full --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect \
  --error-exitcode=99 --track-fds=yes --num-callers=20 \
  --log-file="$VGLOG" \
  ./bin/server -p "$PORT" -u user:pass >"$SRV_LOG" 2>&1 &
VG=$!

cleanup() {
  kill -TERM "$VG" 2>/dev/null
  sleep 0.2
  kill -9 "$VG" 2>/dev/null
  rm -f "$BUILD_LOG" "$SRV_LOG" "$VGLOG"
}
trap cleanup EXIT

# Esperar a que el proxy escuche (valgrind arranca lento).
ready=0
for _ in $(seq 1 60); do
  if python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),timeout=1).close()" 2>/dev/null; then
    ready=1; break
  fi
  sleep 0.5
done
if [ "$ready" -ne 1 ]; then
  echo "el proxy no llegó a escuchar bajo valgrind ❌"
  tail -n 30 "$VGLOG" 2>/dev/null | sed 's/^/  /'
  exit 1
fi

echo "--- generando tráfico SOCKS5 ---"
python3 - "$PORT" <<'PY'
import socket, struct, sys, threading, time

port  = int(sys.argv[1])
HELLO = bytes.fromhex("050102")
AUTH  = b"\x01\x04user\x04pass"

def mkreq(cmd, atyp, addr=b"\x7f\x00\x00\x01", dport=80, fqdn=b"example.com"):
    if atyp == 0x01:   body = addr
    elif atyp == 0x03: body = bytes([len(fqdn)]) + fqdn
    else:              body = b""
    return b"\x05" + bytes([cmd]) + b"\x00" + bytes([atyp]) + body + struct.pack("!H", dport)

def conn():
    s = socket.create_connection(("127.0.0.1", port), timeout=3); s.settimeout(3); return s

def rx(s, n):
    d = b""
    try:
        while len(d) < n:
            c = s.recv(n - len(d))
            if not c: break
            d += c
    except OSError:
        pass
    return d

def unused_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

class Origin:
    """Servidor de origin local que acepta y cierra conexiones hasta close()."""
    def __init__(self):
        self.s = socket.socket(); self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 0)); self.s.listen(16); self.port = self.s.getsockname()[1]
        self._stop = False
        self.t = threading.Thread(target=self._serve, daemon=True); self.t.start()
    def _serve(self):
        self.s.settimeout(0.5)
        while not self._stop:
            try:
                c, _ = self.s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try: c.settimeout(1); c.recv(16)
            except OSError: pass
            c.close()
    def close(self):
        self._stop = True
        try: self.s.close()
        except OSError: pass

def handshake(s):
    s.sendall(HELLO); rx(s, 2)
    s.sendall(AUTH);  rx(s, 2)

def full(req):
    s = conn()
    try:
        handshake(s); s.sendall(req); rx(s, 10)
    finally:
        s.close()

n = 0
org = Origin()

# 5 CONNECT exitosos secuenciales (alloc/free + reuso del pool)
for _ in range(5):
    full(mkreq(0x01, 0x01, dport=org.port)); n += 1

# 3 CONNECT concurrentes
ths = [threading.Thread(target=lambda: full(mkreq(0x01, 0x01, dport=org.port))) for _ in range(3)]
[t.start() for t in ths]; [t.join() for t in ths]; n += 3

# refused: puerto cerrado -> connect async falla -> REP 0x05 + unregister origin
full(mkreq(0x01, 0x01, dport=unused_port())); n += 1

# CMD no soportado (0x07) y ATYP invalido (0x08): error antes de crear el origin fd
full(mkreq(0x02, 0x01)); n += 1
full(mkreq(0x01, 0x09, dport=80)); n += 1

# FQDN localhost: ejercita pthread getaddrinfo + notify_block + connect
full(mkreq(0x01, 0x03, dport=org.port, fqdn=b"localhost")); n += 1

# f14: APAGADO BAJO CARGA DNS. Disparamos un puñado de CONNECT por FQDN que
# lanzan getaddrinfo en hilos detached y, en algunos casos, cortamos el cliente
# sin esperar la respuesta (EOF mientras el hilo DNS puede seguir en vuelo). El
# SIGTERM al server (más abajo) puede caer mientras hay resoluciones pendientes:
# así se ejercita el DRENAJE de hilos DNS de main.c (resolv_pending_count) y se
# valida que NO haya UAF del selector ni leak del struct socks5/origin_resolution
# (el objeto con la ref del hilo DNS no está en el pool al destruirlo).
def fqdn_abort(name):
    # handshake + REQUEST FQDN y cierre inmediato sin leer la reply.
    try:
        s = conn(); handshake(s)
        s.sendall(mkreq(0x01, 0x03, dport=org.port, fqdn=name))
        s.close()   # EOF posible mientras getaddrinfo sigue corriendo
    except OSError:
        pass

dns_names = [b"localhost", b"localhost", b"localhost.localdomain", b"localhost"]
dns_threads = [threading.Thread(target=fqdn_abort, args=(nm,)) for nm in dns_names]
[t.start() for t in dns_threads]
[t.join() for t in dns_threads]
n += len(dns_threads)

# pipelined HELLO+AUTH+REQUEST + payload temprano
s = conn()
try:
    s.sendall(HELLO + AUTH + mkreq(0x01, 0x01, dport=org.port) + b"x"); rx(s, 14)
finally:
    s.close()
n += 1

# cierres abruptos del cliente en cada estado del handshake
for stage in ("hello", "auth", "partial_req", "after_reply"):
    s = conn()
    try:
        if stage == "hello":
            s.sendall(HELLO)
        elif stage == "auth":
            s.sendall(HELLO); rx(s, 2); s.sendall(AUTH)
        elif stage == "partial_req":
            handshake(s); s.sendall(b"\x05\x01\x00\x01\x7f")   # REQUEST cortado a la mitad
        elif stage == "after_reply":
            handshake(s); s.sendall(mkreq(0x01, 0x01, dport=org.port)); rx(s, 10)
    finally:
        s.close()
    n += 1

# best-effort: cliente cierra DURANTE un connect pendiente (IP no ruteable)
try:
    s = conn(); handshake(s)
    s.sendall(mkreq(0x01, 0x01, addr=bytes([10, 255, 255, 1]), dport=9))
    s.close()  # sin leer la respuesta -> EOF mientras el connect está en vuelo
    n += 1
except OSError:
    pass

# best-effort: flood de payload temprano durante connect pendiente
# (ejercita el cierre limpio por buffer lleno en REQUEST_CONNECTING)
try:
    s = conn(); handshake(s)
    s.sendall(mkreq(0x01, 0x01, addr=bytes([10, 255, 255, 1]), dport=9))
    try: s.sendall(b"P" * 16384)
    except OSError: pass
    s.close()
    n += 1
except OSError:
    pass

time.sleep(0.5)
org.close()
print(f"  tráfico generado: {n} intercambios SOCKS5")
PY
TRAFFIC_RC=$?
if [ "$TRAFFIC_RC" -ne 0 ]; then
  echo "TRÁFICO SOCKS5 FALLA ❌ (rc=$TRAFFIC_RC); no se puede validar valgrind"
  kill -TERM "$VG" 2>/dev/null || true
  wait "$VG" 2>/dev/null || true
  trap - EXIT
  exit 1
fi

echo "--- apagando server (SIGTERM) para que valgrind haga el leak-check ---"
kill -TERM "$VG" 2>/dev/null || true
wait "$VG" 2>/dev/null; VG_RC=$?
trap - EXIT

echo "--- valgrind (resumen) ---"
grep -E "ERROR SUMMARY|definitely lost|indirectly lost|possibly lost|still reachable|All heap blocks were freed|FILE DESCRIPTORS|Open (AF_|file )" "$VGLOG" | sed 's/^/  /' || true

# Veredicto: 0 errores de memoria y 0 leaks definite/indirect.
# (cuando todo se libera, valgrind imprime "All heap blocks were freed" y NO
#  emite el bloque LEAK SUMMARY, así que ese caso se trata aparte.)
ok=1
grep -q "ERROR SUMMARY: 0 errors" "$VGLOG" || ok=0
if ! grep -q "All heap blocks were freed -- no leaks are possible" "$VGLOG"; then
  grep -q "definitely lost: 0 bytes" "$VGLOG" || ok=0
  grep -q "indirectly lost: 0 bytes" "$VGLOG" || ok=0
fi
fd_line="$(grep -E "FILE DESCRIPTORS: [0-9]+ open" "$VGLOG" | tail -n 1 || true)"
if [ -z "$fd_line" ]; then
  echo "no encontré resumen de file descriptors en $VGLOG"
  ok=0
else
  fd_open="$(printf "%s\n" "$fd_line" | sed -E 's/.*FILE DESCRIPTORS: ([0-9]+) open.*/\1/')"
  case "$fd_open" in
    ''|*[!0-9]*)
      echo "no pude parsear el resumen de file descriptors: $fd_line"
      ok=0
      ;;
    *)
      if [ "$fd_open" -gt 3 ]; then
        echo "file descriptors abiertos inesperados al salir: $fd_open (esperado <= 3 std)"
        ok=0
      fi
      ;;
  esac
fi
[ "${VG_RC:-1}" -eq 0 ] || ok=0

if [ "$ok" -eq 1 ]; then
  echo "===== VALGRIND+TRÁFICO: OK ✅ (0 errores, 0 leaks definite/indirect) ====="
  exit 0
else
  echo "===== VALGRIND+TRÁFICO: FALLA ❌ (rc=${VG_RC:-?}) — log completo en $VGLOG ====="
  echo "--- tail del log ---"; tail -n 40 "$VGLOG" | sed 's/^/  /'
  exit 1
fi
