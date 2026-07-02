#!/usr/bin/env bash
# Archivos temporales únicos para tests de integración.
# En pampero /tmp es compartido: rutas fijas (/tmp/m1_build.log) fallan si otro
# usuario ya las creó (Permission denied al redirigir stdout).

tpe_mktemp() {
  mktemp "${TMPDIR:-/tmp}/tpe_${1}_XXXXXX.log"
}
