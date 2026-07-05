#!/usr/bin/env bash
# test/m1_integration.sh — integración del HELLO (M1) sobre el socket real.
# Verifica la negociación de método extremo a extremo (bytes en el cable).
set -u
PORT="${1:-11080}"
MGMT_PORT=$((PORT + 1000))
cd "$(dirname "$0")/.."
# shellcheck source=integration_lib.sh
. "$(dirname "$0")/integration_lib.sh"
BUILD_LOG="$(tpe_mktemp m1_build)"
SRV_LOG="$(tpe_mktemp m1_srv)"
SRV=""
cleanup() {
    tpe_stop_server "$SRV"
    rm -f "$BUILD_LOG" "$SRV_LOG"
}
trap cleanup EXIT

echo "== build server =="
make server >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA"; cat "$BUILD_LOG"; exit 1; }

./bin/server -p "$PORT" -P "$MGMT_PORT" -u user:pass >"$SRV_LOG" 2>&1 &
SRV=$!
tpe_wait_server "$SRV" "$PORT" "$SRV_LOG" || exit 1

PASS=0; FAIL=0
chk(){ if [ "$1" = "$2" ]; then echo "  ok  - $3"; PASS=$((PASS+1));
       else echo "  FAIL- $3 (got [$1] want [$2])"; FAIL=$((FAIL+1)); fi; }

# manda un saludo (hex) y devuelve la respuesta (hex). $2=1 => byte a byte (parcial)
resp() {
python3 - "$PORT" "$1" "${2:-0}" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); greet = bytes.fromhex(sys.argv[2]); partial = sys.argv[3] == "1"
s = socket.create_connection(("127.0.0.1", port), timeout=2)
if partial:
    for b in greet:
        s.sendall(bytes([b])); time.sleep(0.05)
else:
    s.sendall(greet)
s.settimeout(2)
data = b""
try:
    while len(data) < 2:
        c = s.recv(16)
        if not c: break
        data += c
except socket.timeout:
    pass
s.close()
print(data.hex())
PY
}

chk "$(resp 050102)"   "0502" "A: ofrece user/pass (05 01 02) -> 05 02"
chk "$(resp 050100)"   "05ff" "B: solo no-auth   (05 01 00) -> 05 FF"
chk "$(resp 050102 1)" "0502" "C: bytes parciales            -> 05 02"
chk "$(resp 0503000102)" "0502" "D: varios métodos (05 03 00 01 02) -> 05 02"
chk "$(resp 0500)"     "05ff" "E: NMETHODS=0 (05 00)         -> 05 FF"
chk "$(resp 040100)"   ""     "F: versión inválida (04 ..)  -> cierra sin responder"
# El caso "HELLO + bytes pipelined" pasó a M2: con AUTH habilitado, el byte extra
# tras el HELLO es el inicio del sub-handshake usuario/contraseña, no se ignora.
# Se cubre end-to-end en test/m2_integration.sh (casos C y E).

tpe_stop_server "$SRV"
SRV=""
echo "== RESULTADO M1: $PASS ok, $FAIL fallas =="
[ "$FAIL" -eq 0 ]
