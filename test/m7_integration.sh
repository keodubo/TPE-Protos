#!/usr/bin/env bash
# test/m7_integration.sh - smoke M7: listener de management en el mismo server.
set -u
SOCKS_PORT="${1:-11087}"
MGMT_PORT=$((SOCKS_PORT + 1000))
cd "$(dirname "$0")/.."

BUILD_LOG="/tmp/m7_build_${SOCKS_PORT}.log"
SRV_LOG="/tmp/m7_srv_${SOCKS_PORT}.log"

echo "== build server/client =="
make server client >"$BUILD_LOG" 2>&1 || { echo "BUILD FALLA"; cat "$BUILD_LOG"; exit 1; }

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
import subprocess
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


def socks_auth(user, password):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=2)
    s.settimeout(2)
    try:
        s.sendall(b"\x05\x01\x02")
        method = s.recv(2)
        u = user.encode("ascii")
        p = password.encode("ascii")
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        auth = s.recv(2)
        return method, auth
    finally:
        s.close()


def client_cmd(*args, expect_ok=True):
    cmd = ["./bin/client", "-L", "127.0.0.1", "-P", str(mgmt_port),
           "--admin", "root:toor", *args]
    cp = subprocess.run(cmd, text=True, capture_output=True, timeout=3)
    if expect_ok:
        check(cp.returncode == 0, f"CLI {' '.join(args)} exit 0",
              (cp.returncode, cp.stdout, cp.stderr))
    else:
        check(cp.returncode != 0, f"CLI {' '.join(args)} exit != 0",
              (cp.returncode, cp.stdout, cp.stderr))
    return cp


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

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nADD-USER pablito pass1234\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n"],
      "F: ADD-USER agrega usuario en runtime", got)

method, auth = socks_auth("pablito", "pass1234")
check(method == b"\x05\x02" and auth == b"\x01\x00",
      "F: usuario agregado autentica por SOCKS sin reiniciar", (method, auth))

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nADD-USER pablito otra\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"-ERR user exists\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"-ERR user exists\r\n"],
      "G: ADD-USER duplicado -> -ERR user exists", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nLIST-USERS\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK 2\r\n", b"user\r\n", b"pablito\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK 2\r\n", b"user\r\n", b"pablito\r\n"],
      "H: LIST-USERS devuelve count-prefix y nombres", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nMETRICS\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK 5\r\n", b"", b"", b"", b"", b""],
)
metric_keys = [line.split(b" ", 1)[0] for line in got[3:]]
check(got[:3] == [b"+OK 1\r\n", b"+OK\r\n", b"+OK 5\r\n"]
      and metric_keys == [
          b"historic-connections",
          b"concurrent-connections",
          b"bytes-transferred",
          b"current-users",
          b"failed-connections",
      ],
      "I: METRICS devuelve metricas con count-prefix", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nDEL-USER pablito\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n"],
      "J: DEL-USER elimina usuario en runtime", got)

method, auth = socks_auth("pablito", "pass1234")
check(method == b"\x05\x02" and auth == b"\x01\x01",
      "J: usuario eliminado deja de autenticar por SOCKS", (method, auth))

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nDEL-USER nadie\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"-ERR no such user\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"-ERR no such user\r\n"],
      "K: DEL-USER inexistente -> -ERR no such user", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nADD-USER mal.nombre pass\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"-ERR bad name\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"-ERR bad name\r\n"],
      "L: ADD-USER valida name PMC", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nQUIT\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK bye\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK bye\r\n"],
      "M: QUIT responde bye", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nGET-CONFIG buffer-size\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK 8192\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK 8192\r\n"],
      "N: GET-CONFIG buffer-size devuelve default", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nSET-CONFIG buffer-size 16384\r\nGET-CONFIG buffer-size\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n", b"+OK 16384\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"+OK\r\n", b"+OK 16384\r\n"],
      "O: SET-CONFIG buffer-size cambia runtime", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nGET-CONFIG nope\r\nSET-CONFIG nope 1\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"-ERR unknown key\r\n", b"-ERR unknown key\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"-ERR unknown key\r\n", b"-ERR unknown key\r\n"],
      "P: GET/SET-CONFIG key desconocida -> -ERR unknown key", got)

got = mgmt_exchange(
    b"HELLO 1\r\nAUTH root toor\r\nSET-CONFIG buffer-size 21\r\nSET-CONFIG buffer-size abc\r\n",
    [b"+OK 1\r\n", b"+OK\r\n", b"-ERR bad value\r\n", b"-ERR bad value\r\n"],
)
check(got == [b"+OK 1\r\n", b"+OK\r\n", b"-ERR bad value\r\n", b"-ERR bad value\r\n"],
      "Q: SET-CONFIG buffer-size valida rango y numero", got)

cp = client_cmd("add-user", "cliuser", "clipass")
check("+OK" in cp.stdout, "R: CLI add-user imprime +OK", cp.stdout)
method, auth = socks_auth("cliuser", "clipass")
check(method == b"\x05\x02" and auth == b"\x01\x00",
      "R: usuario creado por CLI autentica por SOCKS", (method, auth))

cp = client_cmd("list-users")
check("cliuser" in cp.stdout, "S: CLI list-users imprime usuario", cp.stdout)

cp = client_cmd("metrics")
check("historic-connections" in cp.stdout and "bytes-transferred" in cp.stdout,
      "T: CLI metrics imprime metricas", cp.stdout)

cp = client_cmd("set-config", "buffer-size", "32768")
check("+OK" in cp.stdout, "U: CLI set-config imprime +OK", cp.stdout)
cp = client_cmd("get-config", "buffer-size")
check("32768" in cp.stdout, "U: CLI get-config imprime nuevo valor", cp.stdout)

cp = client_cmd("del-user", "cliuser")
check("+OK" in cp.stdout, "V: CLI del-user imprime +OK", cp.stdout)
method, auth = socks_auth("cliuser", "clipass")
check(method == b"\x05\x02" and auth == b"\x01\x01",
      "V: usuario eliminado por CLI deja de autenticar", (method, auth))

bad = ["./bin/client", "-L", "127.0.0.1", "-P", str(mgmt_port),
       "--admin", "root:wrong", "metrics"]
cp = subprocess.run(bad, text=True, capture_output=True, timeout=3)
check(cp.returncode != 0 and "auth failed" in (cp.stdout + cp.stderr),
      "W: CLI devuelve exit != 0 en -ERR", (cp.returncode, cp.stdout, cp.stderr))

print(f"== RESULTADO M7: {checks - failures} ok, {failures} fallas ==")
sys.exit(0 if failures == 0 else 1)
PY
