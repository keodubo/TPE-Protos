#!/usr/bin/env bash
# =============================================================================
# EJEMPLO / PLANTILLA — Probar el TPE en pampero desde tu propia máquina.
#
# Para tus compañeros: COPIÁ este archivo (p. ej. a `extras/run-on-pampero.sh`,
# que está gitignoreado), cambiá PAMPERO_USER por TU usuario de pampero, y corré:
#
#     bash extras/run-on-pampero.sh
#
# Qué hace: abre UNA conexión SSH (te pide la password una sola vez), sube el
# repo con rsync, y compila + corre un smoke test en pampero (Linux real).
#
# ¿Por qué password y no clave pública?  En pampero los homes están en CephFS y
# el sshd central NO acepta autenticación por clave (aunque la instales bien con
# permisos 700/700/600). Por eso usamos "ControlMaster": ssh autentica una vez y
# reusamos esa conexión para rsync + comandos. La password la maneja ssh en su
# propio prompt; este script NUNCA la lee, guarda ni registra.
# =============================================================================
set -euo pipefail

# ----------------------------- CONFIG (editá esto) ---------------------------
PAMPERO_USER="TU_USUARIO"               # <-- tu usuario de pampero (ej. jperez)
HOST="pampero.itba.edu.ar"
REMOTE_DIR="tpe-test"                   # carpeta destino dentro de tu home
PORT="${1:-11080}"                      # puerto de prueba (cambialo si choca)

# Raíz del repo. Por defecto asume que este script vive en un subdir del repo
# (docs/ o extras/). Si lo copiás a otro lado, seteá REPO_ROOT a mano:
#   REPO_ROOT=/ruta/al/repo bash run-on-pampero.sh
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# -----------------------------------------------------------------------------

if [ "$PAMPERO_USER" = "TU_USUARIO" ]; then
  echo "ERROR: editá PAMPERO_USER en este script con tu usuario de pampero." >&2
  exit 1
fi
TARGET="$PAMPERO_USER@$HOST"

# socket de control: una sola conexión autenticada, reusada por todo el script
CTRL="$HOME/.ssh/cm-pampero-$$.sock"
cleanup() { ssh -S "$CTRL" -O exit "$TARGET" 2>/dev/null || true; rm -f "$CTRL"; }
trap cleanup EXIT INT TERM

echo "==> Conectando a $TARGET (te pedirá la password de pampero UNA vez)"
ssh -M -S "$CTRL" -o ControlPersist=10m -o ConnectTimeout=15 -fN "$TARGET"

echo "==> Subiendo repo a ~/$REMOTE_DIR (rsync, sin tmp/obj/bin/.git)"
rsync -az --delete -e "ssh -S $CTRL" \
  --exclude tmp --exclude obj --exclude bin --exclude .git --exclude '.DS_Store' \
  "$REPO_ROOT/" "$TARGET:$REMOTE_DIR/"

echo "==> Compilando y testeando en pampero"
echo "--------------------------------------------------------------"
# El bloque entre <<'REMOTE' ... REMOTE corre EN pampero. REMOTE_DIR y PORT se
# pasan por entorno. El test usa bash /dev/tcp (sin depender de python/nc).
ssh -S "$CTRL" "$TARGET" "REMOTE_DIR='$REMOTE_DIR' PORT='$PORT' bash -s" <<'REMOTE'
set -u
cd "$REMOTE_DIR"
echo "[entorno] $(uname -sr) | $(gcc --version 2>/dev/null | head -1)"

echo "[build]   make clean && make"
make clean >/dev/null 2>&1
if make 2>/tmp/tpe_build.log; then echo "          BUILD OK"; else
  echo "          BUILD FALLA"; cat /tmp/tpe_build.log; exit 1
fi

echo "[run]     ./bin/server -p $PORT  (echo + shutdown)"
./bin/server -p "$PORT" >/tmp/tpe_srv.log 2>&1 &
SRV=$!
sleep 1

# --- echo test sin dependencias (bash /dev/tcp) ---
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
printf 'hola pampero\n' >&3
RESP="$(head -c 12 <&3)"
exec 3>&- 3<&-
[ "$RESP" = "hola pampero" ] && echo "          echo: OK" || echo "          echo: FALLA ($RESP)"

# --- apagado limpio por SIGTERM ---
kill -TERM "$SRV" 2>/dev/null || true
sleep 1
if kill -0 "$SRV" 2>/dev/null; then echo "          shutdown: FALLA"; kill -9 "$SRV"
else echo "          shutdown: OK"; fi

# --- (opcional) valgrind: en Arch necesita debuginfod (sin root) ---
# Descomentá para chequear fugas. Requiere que pampero permita salida a internet.
# if command -v valgrind >/dev/null 2>&1; then
#   DEBUGINFOD_URLS=https://debuginfod.archlinux.org \
#     valgrind --leak-check=full --log-file=/tmp/tpe_vg.log ./bin/server -p "$((PORT+1))" &
#   VG=$!; sleep 5
#   exec 3<>"/dev/tcp/127.0.0.1/$((PORT+1))"; printf 'x\n' >&3; head -c 1 <&3 >/dev/null; exec 3>&- 3<&-
#   sleep 1; kill -TERM "$VG"; wait "$VG" 2>/dev/null
#   echo "[valgrind]"; tail -n 12 /tmp/tpe_vg.log | sed 's/^/          /'
# fi
REMOTE
echo "--------------------------------------------------------------"
echo "==> Listo. (la conexión se cierra sola)"
