# -*- coding: utf-8 -*-
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

DB = os.getenv("DATABASE_URL") or os.getenv("NETGUARD_DB_DSN")

INTERVAL = int(os.getenv("ANOMALY_INTERVAL_SEC", "30"))
ALPHA = float(os.getenv("EWMA_ALPHA", "0.3"))
DB_RETRY_SEC = max(1, int(float(os.getenv("DB_RETRY_SEC", "5"))))
DB_RETRY_MAX_SEC = max(DB_RETRY_SEC, int(float(os.getenv("DB_RETRY_MAX_SEC", "60"))))

# Mantem compatibilidade com o compose atual, que ainda usa Z_THRESHOLD unico.
COMMON_Z_THRESHOLD = os.getenv("Z_THRESHOLD")
Z_TRIG_OCTETS = float(os.getenv("Z_THRESHOLD_OCTETS", COMMON_Z_THRESHOLD or "1.5"))
Z_TRIG_ERRORS = float(os.getenv("Z_THRESHOLD_ERRORS", COMMON_Z_THRESHOLD or "2.5"))

# Evita divisao por zero / explosoes.
MIN_STD = float(os.getenv("MIN_STD", "0.5"))

# Janela de leitura do DB.
LOOKBACK_MIN = int(os.getenv("LOOKBACK_MIN", "10"))

WATCH_PREFIXES = [
    "snmp.if.in_errors|ifIndex=",
    "snmp.if.out_errors|ifIndex=",
    "snmp.if.in_discards|ifIndex=",
    "snmp.if.out_discards|ifIndex=",
    "snmp.if.in_octets|ifIndex=",
    "snmp.if.out_octets|ifIndex=",
]

IFINDEX_RE = re.compile(r"\|ifIndex=(\d+)$")


def parse_ifindex(metric: str) -> str:
    match = IFINDEX_RE.search(metric)
    return match.group(1) if match else "?"


def is_octets(metric: str) -> bool:
    return "snmp.if.in_octets" in metric or "snmp.if.out_octets" in metric


def is_errors_or_discards(metric: str) -> bool:
    return (
        "snmp.if.in_errors" in metric
        or "snmp.if.out_errors" in metric
        or "snmp.if.in_discards" in metric
        or "snmp.if.out_discards" in metric
    )


def metric_base(metric: str) -> str:
    return metric.split("|")[0] + ".delta"


def insert_score(cur, ts, asset_id, base_metric, key, score, z, value, mean, std, details):
    cur.execute(
        """
        insert into anomaly_scores
        (ts, asset_id, metric, key, score, z, value, baseline_mean, baseline_std, details)
        values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        on conflict do nothing
        """,
        (
            ts,
            asset_id,
            base_metric,
            key,
            float(score),
            float(z),
            float(value),
            float(mean),
            float(std),
            json.dumps(details),
        ),
    )


def main():
    if not DB:
        raise SystemExit("DATABASE_URL/NETGUARD_DB_DSN nao definido")

    # Estado em memoria por (asset_id, metric_raw).
    state = {}

    while True:
        conn = None
        wait_sec = DB_RETRY_SEC
        try:
            while True:
                try:
                    conn = psycopg2.connect(DB, cursor_factory=RealDictCursor)
                    break
                except psycopg2.OperationalError as exc:
                    print(f"[anomaly-engine] aguardando banco ficar pronto: {exc}", flush=True)
                    time.sleep(wait_sec)
                    wait_sec = min(DB_RETRY_MAX_SEC, max(DB_RETRY_SEC, wait_sec * 2))

            conn.autocommit = True
            cur = conn.cursor()

            while True:
                now = datetime.now(timezone.utc)
                since = now - timedelta(minutes=LOOKBACK_MIN)

                cur.execute(
                    """
                    select ts, asset_id, metric, value
                    from metrics
                    where ts > %s and (
                      """
                    + " OR ".join(["metric like %s"] * len(WATCH_PREFIXES))
                    + """
                    )
                    order by ts asc
                    """,
                    [since] + [prefix + "%" for prefix in WATCH_PREFIXES],
                )
                rows = cur.fetchall()

                for row in rows:
                    asset_id = int(row["asset_id"])
                    metric = str(row["metric"])
                    ts = row["ts"]
                    value = float(row["value"])

                    key = (asset_id, metric)
                    snapshot = state.get(key)
                    if not snapshot:
                        state[key] = {"prev": value, "mean": 0.0, "var": 1.0}
                        continue

                    delta = value - snapshot["prev"]
                    snapshot["prev"] = value

                    if delta < 0:
                        delta = 0.0

                    if is_octets(metric) and delta <= 0:
                        continue

                    mean = snapshot["mean"]
                    var = snapshot["var"]

                    mean_new = ALPHA * delta + (1 - ALPHA) * mean
                    var_new = (1 - ALPHA) * (var + ALPHA * (delta - mean) ** 2)

                    snapshot["mean"] = mean_new
                    snapshot["var"] = var_new

                    std = max(MIN_STD, var_new**0.5)
                    z = (delta - mean_new) / std if std > 0 else 0.0

                    z_scale = Z_TRIG_ERRORS * 2.0
                    score = min(1.0, max(0.0, abs(z) / z_scale))

                    ifindex = parse_ifindex(metric)
                    base_metric = metric_base(metric)
                    metric_key = f"ifIndex={ifindex}"
                    z_trigger = Z_TRIG_OCTETS if is_octets(metric) else Z_TRIG_ERRORS

                    details = {
                        "raw_metric": metric,
                        "delta": float(delta),
                        "ewma_mean": float(mean_new),
                        "ewma_std": float(std),
                        "z_trig_used": float(z_trigger),
                        "kind": "octets" if is_octets(metric) else ("errors_discard" if is_errors_or_discards(metric) else "other"),
                    }

                    insert_score(cur, ts, asset_id, base_metric, metric_key, score, z, delta, mean_new, std, details)

                time.sleep(INTERVAL)
        except psycopg2.Error as exc:
            print(f"[ANOMALY] banco indisponivel, reconectando em {DB_RETRY_SEC}s: {exc}", flush=True)
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
        time.sleep(DB_RETRY_SEC)


if __name__ == "__main__":
    main()
