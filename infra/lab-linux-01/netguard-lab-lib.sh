#!/bin/sh

LAB_STATE_DIR="${LAB_STATE_DIR:-/run/netguard-lab}"
SNMP_LOG_FILE="${SNMP_LOG_FILE:-/var/log/netguard-snmpd.log}"
CPU_PIDS_FILE="${LAB_STATE_DIR}/high_cpu.pids"
CPU_TIMER_FILE="${LAB_STATE_DIR}/high_cpu.timer"
HOST_LOSS_TIMER_FILE="${LAB_STATE_DIR}/host_loss.timer"

lab_init() {
  mkdir -p "$LAB_STATE_DIR" /var/spool/rsyslog /run
  touch /var/log/syslog /var/log/netguard-demo.log "$SNMP_LOG_FILE"
}

lab_echo() {
  printf '%s\n' "$*"
}

lab_logger() {
  logger -t "${SYSLOG_TAG:-lab-control}" "$*" 2>/dev/null || true
}

lab_emit_event() {
  event_id="$1"
  severity="$2"
  subsystem="$3"
  iface="$4"
  message="$5"

  logger -t "${SYSLOG_TAG:-lab-control}" "Event|${event_id}|${severity}|${subsystem}|1|${iface}|${message}" 2>/dev/null || true
  lab_echo "$message"
}

lab_have_process() {
  pgrep -x "$1" >/dev/null 2>&1
}

lab_start_rsyslog() {
  if lab_have_process rsyslogd; then
    return 0
  fi

  rm -f /run/rsyslogd.pid /var/run/rsyslogd.pid
  rsyslogd
  sleep 1
}

lab_stop_rsyslog() {
  if ! lab_have_process rsyslogd; then
    return 0
  fi

  pkill -x rsyslogd >/dev/null 2>&1 || true
  rm -f /run/rsyslogd.pid /var/run/rsyslogd.pid
  sleep 1
}

lab_start_snmpd() {
  if lab_have_process snmpd; then
    return 0
  fi

  nohup /usr/sbin/snmpd -f -Lo >>"$SNMP_LOG_FILE" 2>&1 &
  echo "$!" > "${LAB_STATE_DIR}/snmpd.pid"
  sleep 1
}

lab_stop_snmpd() {
  if ! lab_have_process snmpd; then
    rm -f "${LAB_STATE_DIR}/snmpd.pid"
    return 0
  fi

  pkill -x snmpd >/dev/null 2>&1 || true
  rm -f "${LAB_STATE_DIR}/snmpd.pid"
  sleep 1
}

lab_add_iptables_rule() {
  chain="$1"
  shift

  if ! iptables -C "$chain" "$@" >/dev/null 2>&1; then
    iptables -I "$chain" "$@"
  fi
}

lab_del_iptables_rule() {
  chain="$1"
  shift

  while iptables -C "$chain" "$@" >/dev/null 2>&1; do
    iptables -D "$chain" "$@"
  done
}

lab_apply_host_loss_rules() {
  lab_add_iptables_rule INPUT -p icmp --icmp-type echo-request -j DROP
  lab_add_iptables_rule OUTPUT -p icmp --icmp-type echo-reply -j DROP
  lab_add_iptables_rule INPUT -p udp --dport 161 -j DROP
}

lab_clear_host_loss_rules() {
  lab_del_iptables_rule INPUT -p icmp --icmp-type echo-request -j DROP
  lab_del_iptables_rule OUTPUT -p icmp --icmp-type echo-reply -j DROP
  lab_del_iptables_rule INPUT -p udp --dport 161 -j DROP
}

lab_host_loss_active() {
  iptables -C INPUT -p icmp --icmp-type echo-request -j DROP >/dev/null 2>&1
}

lab_stop_timer_file() {
  timer_file="$1"

  if [ ! -f "$timer_file" ]; then
    return 0
  fi

  timer_pid="$(cat "$timer_file" 2>/dev/null || true)"
  if [ -n "$timer_pid" ]; then
    kill "$timer_pid" >/dev/null 2>&1 || true
  fi

  rm -f "$timer_file"
}

lab_stop_cpu_load() {
  if [ -f "$CPU_PIDS_FILE" ]; then
    while IFS= read -r cpu_pid; do
      if [ -n "$cpu_pid" ]; then
        kill "$cpu_pid" >/dev/null 2>&1 || true
      fi
    done < "$CPU_PIDS_FILE"
    rm -f "$CPU_PIDS_FILE"
  fi

  lab_stop_timer_file "$CPU_TIMER_FILE"
}

lab_cleanup() {
  lab_stop_timer_file "$HOST_LOSS_TIMER_FILE"
  lab_stop_cpu_load
  lab_clear_host_loss_rules
  lab_stop_snmpd
  lab_stop_rsyslog
}
