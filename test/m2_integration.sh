#!/usr/bin/env bash
# test/m2_integration.sh — integración del AUTH user/pass (M2, RFC1929) sobre el
# socket real. Hace HELLO (05 01 02) y luego el sub-handshake 01 ULEN U PLEN P.
set -u
PORT="${1:-11082}"
cd "$(dirname "$0")/.."

echo "== build server =="
make server >/tmp/m2_build.log 2>&1 || { echo "BUILD FALLA"; cat /tmp/m2_build.log; exit 1; }

./bin/server -p "$PORT" -u user:pass >/tmp/m2_srv.log 2>&1 &
SRV=$!
sleep 0.5

PASS=0; FAIL=0
chk(){ if [ "$1" = "$2" ]; then echo "  ok  - $3"; PASS=$((PASS+1));
       else echo "  FAIL- $3 (got [$1] want [$2])"; FAIL=$((FAIL+1)); fi; }

# exchange HELLO_hex AUTH_hex MODE  -> imprime todo lo recibido en hex
#   MODE: sep (default) | pipe (todo junto) | partial (auth byte a byte)
exchange() {
python3 - "$PORT" "$1" "$2" "${3:-sep}" <<'PY'
import socket, sys, time
port=int(sys.argv[1]); hello=bytes.fromhex(sys.argv[2]); auth=bytes.fromhex(sys.argv[3]); mode=sys.argv[4]
s=socket.create_connection(("127.0.0.1",port),timeout=2); s.settimeout(2)
out=b""
def drain(n):
    global out
    try:
        while True:
            c=s.recv(64)
            if not c: break
            out+=c
            if len(out)>=n: break
    except socket.timeout:
        pass
if mode=="pipe":
    s.sendall(hello+auth); drain(4)
elif mode=="partial":
    s.sendall(hello); drain(2)
    for b in auth: s.sendall(bytes([b])); time.sleep(0.02)
    drain(4)
else:  # sep
    s.sendall(hello); drain(2)
    s.sendall(auth);  drain(4)
s.close(); print(out.hex())
PY
}

HELLO=050102
AUTH_OK=0104757365720470617373       # 01 04 'user' 04 'pass'
AUTH_BADPASS=01047573657203626164    # 01 04 'user' 03 'bad'
AUTH_BADVER=0504757365720470617373   # VER=05 (inválida)
AUTH_EMPTYU=01000470617373           # ULEN=0 (usuario vacío) + 'pass'

chk "$(exchange $HELLO $AUTH_OK)"      "05020100" "A: cred correcta -> 05 02 / 01 00"
chk "$(exchange $HELLO $AUTH_BADPASS)" "05020101" "B: pass incorrecta -> 01 01 + cierre"
chk "$(exchange $HELLO $AUTH_OK pipe)" "05020100" "C: HELLO+AUTH pipelined -> 05 02 01 00"
chk "$(exchange $HELLO $AUTH_OK partial)" "05020100" "D: AUTH byte a byte -> 01 00"
chk "$(exchange $HELLO $AUTH_BADVER)"  "05020101" "E: VER!=0x01 -> 01 01 + cierre"
chk "$(exchange $HELLO $AUTH_EMPTYU)"  "05020101" "F: usuario vacío (ULEN=0) -> 01 01"

kill -TERM "$SRV" 2>/dev/null; sleep 0.3; kill -9 "$SRV" 2>/dev/null
echo "== RESULTADO M2: $PASS ok, $FAIL fallas =="
[ "$FAIL" -eq 0 ]
