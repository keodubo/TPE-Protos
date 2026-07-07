#!/usr/bin/env bash
set -euo pipefail

# Sube el repo a Pampero y ejecuta los gates de entrega en Linux real.
# Uso:
#   PAMPERO_USER=<usuario> bash scripts/run-on-pampero.sh [PORT]

HOST="${PAMPERO_HOST:-pampero.itba.edu.ar}"
REMOTE_DIR="${PAMPERO_REMOTE_DIR:-tp-protos-test}"
PORT="${1:-12080}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "${PAMPERO_USER:-}" ]; then
  echo "ERROR: setear PAMPERO_USER con el usuario de Pampero." >&2
  echo "Ejemplo: PAMPERO_USER=usuario bash scripts/run-on-pampero.sh ${PORT}" >&2
  exit 2
fi

TARGET="${PAMPERO_USER}@${HOST}"
CTRL="${HOME}/.ssh/cm-pampero-$$.sock"
cleanup() {
  ssh -S "$CTRL" -O exit "$TARGET" 2>/dev/null || true
  rm -f "$CTRL"
}
trap cleanup EXIT INT TERM

echo "==> Conectando a ${TARGET} (ssh pedira la password si corresponde)"
ssh -M -S "$CTRL" -o ControlPersist=10m -o ConnectTimeout=15 -fN "$TARGET"

echo "==> Subiendo repo a ~/${REMOTE_DIR} (sin .git, obj, bin ni tmp)"
rsync -az --delete -e "ssh -S $CTRL" \
  --exclude .git --exclude obj --exclude bin --exclude tmp --exclude '.DS_Store' \
  "$REPO_ROOT/" "$TARGET:$REMOTE_DIR/"

echo "==> Ejecutando build, tests, integracion y Valgrind en Pampero"
ssh -S "$CTRL" "$TARGET" "REMOTE_DIR='$REMOTE_DIR' PORT='$PORT' bash -s" <<'REMOTE'
set -euo pipefail
cd "$REMOTE_DIR"

echo "===== entorno ====="
echo "host=$(hostname -f 2>/dev/null || hostname)"
echo "kernel=$(uname -sr)"
echo "gcc=$(gcc --version 2>/dev/null | head -1 || cc --version | head -1)"

echo "===== make clean && make ====="
make clean >/dev/null 2>&1
make
echo "BUILD OK"

echo "===== make test ====="
make test

echo "===== make check PORT=${PORT} ====="
make check PORT="$PORT"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "ERROR: valgrind no esta instalado en Pampero." >&2
  exit 1
fi

VG_PORT=$((PORT + 1))
echo "===== make valgrind PORT=${VG_PORT} ====="
DEBUGINFOD_URLS="${DEBUGINFOD_URLS:-https://debuginfod.archlinux.org}" \
  make valgrind PORT="$VG_PORT"

echo "RESULTADO: TODO OK"
REMOTE
