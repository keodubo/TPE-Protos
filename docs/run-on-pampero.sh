#!/usr/bin/env bash
set -euo pipefail

# --------------------------------- CONFIG ------------------------------------
PAMPERO_USER="TU_USUARIO"               # <-- Cambiar por usuario de pampero
HOST="pampero.itba.edu.ar"
REMOTE_DIR="tp-protos-test"
PORT="${1:-11080}"                      # puerto de prueba

# Raíz del repo. Por defecto asume que este script vive en un subdir del repo
# (docs). Si lo copiás a otro lado, seteá REPO_ROOT a mano:
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
BUILD_LOG="$(mktemp /tmp/tpe_build_XXXXXX.log)"
if make 2>"$BUILD_LOG"; then echo "          BUILD OK"; else
  echo "          BUILD FALLA"; cat "$BUILD_LOG"; rm -f "$BUILD_LOG"; exit 1
fi
rm -f "$BUILD_LOG"

echo "[unit]  make test"
make test || echo "  (unit tests con fallas)"

echo "[integration] test/*_integration.sh"
for t in test/*_integration.sh; do
  [ -e "$t" ] || continue
  echo "  --- $t ---"; bash "$t" "$PORT"
done

# (opcional) valgrind — en Arch (pampero) necesita debuginfod (sin root):
#   DEBUGINFOD_URLS=https://debuginfod.archlinux.org \
#     valgrind --leak-check=full ./bin/server -p "$PORT" -u user:pass
REMOTE
echo "--------------------------------------------------------------"
echo "==> Listo. (la conexión se cierra sola)"