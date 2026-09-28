#!/bin/sh
set -eu

HOST_NAME="${1:-lab-linux-01}"
HOST_IP="${2:-172.30.10.10}"

docker compose exec -T db psql \
  -U netguard \
  -d netguard \
  -v ON_ERROR_STOP=1 \
  -v "demo_host_name=${HOST_NAME}" \
  -v "demo_host_ip=${HOST_IP}" \
  -f /opt/netguard-sql/demo_reset_lab_linux_01.sql
