#!/usr/bin/env bash
# Arranca el host runner leyendo .env del proyecto (alternativa a docker compose nmap-runner).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi
export NMAP_RUNNER_PORT="${NMAP_RUNNER_PORT:-8791}"
export NMAP_RUNNER_BIND="${NMAP_RUNNER_BIND:-0.0.0.0}"
export NMAP_RUNNER_TOKEN="${NMAP_RUNNER_TOKEN:-change-me-nmap-runner}"
export NMAP_TIMEOUT_SEC="${NMAP_TIMEOUT_SEC:-600}"
export NMAP_HOST_TIMEOUT_SEC="${NMAP_HOST_TIMEOUT_SEC:-5}"
exec python3 "$ROOT/scripts/nmap-host-runner.py"
