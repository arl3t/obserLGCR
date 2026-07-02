#!/usr/bin/env sh
# Aplica migraciones Postgres usando el contenedor API (tiene pg y variables PG_*).
# Uso desde la raíz del repo:
#   ./scripts/migrate.sh
set -eu
cd "$(dirname "$0")/.."
if ! docker compose ps api --status running 2>/dev/null | grep -q api; then
  echo "El contenedor api no está en ejecución. Levante el stack primero:"
  echo "  docker compose up -d"
  exit 1
fi
exec docker compose exec api node migrate.mjs
