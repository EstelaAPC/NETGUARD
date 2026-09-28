#!/bin/sh
set -eu

. /usr/local/lib/netguard-lab-lib.sh

CONTROL_BIN="/usr/local/bin/netguard-lab-control"

lab_init

is_positive_int() {
  case "${1:-}" in
    ''|*[!0-9]*)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

schedule_host_recover() {
  duration="${1:-0}"
  lab_stop_timer_file "$HOST_LOSS_TIMER_FILE"

  if ! is_positive_int "$duration" || [ "$duration" -le 0 ]; then
    return 0
  fi

  (
    sleep "$duration"
    "$CONTROL_BIN" host_recover >/dev/null 2>&1 || true
  ) &
  echo "$!" > "$HOST_LOSS_TIMER_FILE"
}

start_cpu_load() {
  duration="${1:-60}"
  workers="${2:-2}"

  if ! is_positive_int "$duration" || [ "$duration" -le 0 ]; then
    lab_echo "Duracao invalida para high_cpu: use um inteiro positivo em segundos."
    exit 1
  fi

  if ! is_positive_int "$workers" || [ "$workers" -le 0 ]; then
    lab_echo "Quantidade de workers invalida para high_cpu: use um inteiro positivo."
    exit 1
  fi

  lab_stop_cpu_load
  : > "$CPU_PIDS_FILE"

  index=1
  while [ "$index" -le "$workers" ]; do
    sh -c 'while :; do :; done' >/dev/null 2>&1 &
    echo "$!" >> "$CPU_PIDS_FILE"
    index=$((index + 1))
  done

  (
    sleep "$duration"
    "$CONTROL_BIN" high_cpu_stop >/dev/null 2>&1 || true
  ) &
  echo "$!" > "$CPU_TIMER_FILE"
}

emit_syslog_burst() {
  count="${1:-40}"
  pause_sec="${2:-0.05}"

  if ! is_positive_int "$count" || [ "$count" -le 0 ]; then
    lab_echo "Quantidade invalida para syslog_burst: use um inteiro positivo."
    exit 1
  fi

  index=1
  while [ "$index" -le "$count" ]; do
    logger -t lab-burst "Event|$((3000 + index))|info|LAB|1|eth0|SYSLOG_BURST_SEQ_${index}" 2>/dev/null || true
    sleep "$pause_sec"
    index=$((index + 1))
  done
}

print_help() {
  cat <<'EOF'
Uso:
  netguard-lab-control <cenario> [parametros]

Cenarios:
  preloop [iface]              Dispara os sinais STP/MAC/IF/BROADCAST de pre-loop.
  snmp_down                    Interrompe o snmpd.
  snmp_up                      Restaura o snmpd.
  host_loss [segundos]         Bloqueia ICMP e UDP/161. Se informar segundos, recupera automaticamente.
  host_recover                 Remove o bloqueio de host_loss.
  high_cpu [segundos] [workers]
                               Gera carga alta temporaria. Padrao: 60s com 2 workers.
  high_cpu_stop                Interrompe a carga alta manualmente.
  syslog_burst [quantidade] [pausa_seg]
                               Envia uma enxurrada controlada de syslogs. Padrao: 40 mensagens.
  service_fail                 Interrompe o rsyslog (falha do servico de encaminhamento).
  service_recover              Restaura o rsyslog.
  status                       Mostra o estado atual do laboratorio.
  help                         Mostra esta ajuda.
EOF
}

print_status() {
  if lab_have_process snmpd; then
    snmp_state="up"
  else
    snmp_state="down"
  fi

  if lab_have_process rsyslogd; then
    rsyslog_state="up"
  else
    rsyslog_state="down"
  fi

  if lab_host_loss_active; then
    host_loss_state="active"
  else
    host_loss_state="inactive"
  fi

  if [ -f "$CPU_PIDS_FILE" ]; then
    cpu_state="running"
  else
    cpu_state="idle"
  fi

  cat <<EOF
host=lab-linux-01
snmp=${snmp_state}
rsyslog=${rsyslog_state}
host_loss=${host_loss_state}
high_cpu=${cpu_state}
EOF
}

command_name="${1:-help}"
shift || true

case "$command_name" in
  help|-h|--help|list)
    print_help
    ;;
  status)
    print_status
    ;;
  preloop)
    iface="${1:-1/1/10}"
    /usr/local/bin/netguard-preloop-demo "$iface"
    lab_echo "Pre-loop emitido para ${iface}."
    ;;
  snmp_down)
    lab_emit_event 2001 warning SNMP host SNMP_DOWN
    lab_stop_snmpd
    lab_echo "SNMP interrompido."
    ;;
  snmp_up)
    lab_start_snmpd
    lab_emit_event 2002 notice SNMP host SNMP_UP
    lab_echo "SNMP restaurado."
    ;;
  host_loss)
    duration="${1:-0}"
    lab_apply_host_loss_rules
    schedule_host_recover "$duration"
    lab_emit_event 2003 critical NET host HOST_LOSS
    if is_positive_int "$duration" && [ "$duration" -gt 0 ]; then
      lab_echo "Host loss ativado por ${duration}s."
    else
      lab_echo "Host loss ativado ate executar host_recover."
    fi
    ;;
  host_recover)
    lab_stop_timer_file "$HOST_LOSS_TIMER_FILE"
    lab_clear_host_loss_rules
    lab_emit_event 2004 notice NET host HOST_RECOVER
    lab_echo "Host recover aplicado."
    ;;
  high_cpu)
    duration="${1:-60}"
    workers="${2:-2}"
    start_cpu_load "$duration" "$workers"
    lab_emit_event 2005 warning SYS cpu0 HIGH_CPU_START
    lab_echo "Carga alta iniciada por ${duration}s com ${workers} workers."
    ;;
  high_cpu_stop)
    lab_stop_cpu_load
    lab_emit_event 2006 notice SYS cpu0 HIGH_CPU_END
    lab_echo "Carga alta interrompida."
    ;;
  syslog_burst)
    count="${1:-40}"
    pause_sec="${2:-0.05}"
    emit_syslog_burst "$count" "$pause_sec"
    lab_emit_event 2009 info LAB eth0 SYSLOG_BURST_DONE
    lab_echo "Syslog burst emitido com ${count} mensagens."
    ;;
  service_fail)
    lab_emit_event 2007 warning SVC rsyslog SERVICE_FAIL_RSYSLOG
    sleep 1
    lab_stop_rsyslog
    lab_echo "rsyslog interrompido."
    ;;
  service_recover)
    lab_start_rsyslog
    lab_emit_event 2008 notice SVC rsyslog SERVICE_RECOVER_RSYSLOG
    lab_echo "rsyslog restaurado."
    ;;
  *)
    print_help
    exit 1
    ;;
esac
