#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "Uso: scripts/run-lab-scenario.sh <cenario> [parametros...]"
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"
docker compose exec -T lab-linux-01 netguard-lab-control "$@"
