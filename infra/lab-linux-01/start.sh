#!/bin/sh
set -eu

. /usr/local/lib/netguard-lab-lib.sh

lab_init
lab_start_rsyslog
lab_start_snmpd

sleep 2
logger -t netguard-demo "lab-linux-01 online; SNMP v2c community netguard; syslog forwarding enabled" 2>/dev/null || true

trap 'lab_cleanup; exit 0' TERM INT

while :; do
  sleep 3600 &
  wait "$!"
done
