#!/bin/sh
set -eu

IFACE="${1:-1/1/10}"
PAUSE="${PAUSE_SEC:-1}"
TAG="${SYSLOG_TAG:-lab-preloop}"

emit() {
  event_id="$1"
  severity="$2"
  subsystem="$3"
  iface="$4"
  message="$5"

  logger -t "$TAG" "Event|${event_id}|${severity}|${subsystem}|1|${iface}|${message}"
}

emit 1001 warning STP unknown STP_TOPOLOGY_CHANGE
sleep "$PAUSE"
emit 1002 warning L2 "$IFACE" MAC_FLAPPING
sleep "$PAUSE"
emit 1003 warning IF "$IFACE" INTERFACE_FLAP
sleep "$PAUSE"
emit 1004 critical L2 "$IFACE" BROADCAST_STORM

logger -t "$TAG" "Synthetic pre-loop burst emitted on ${IFACE}"
