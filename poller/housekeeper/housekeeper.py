# -*- coding: utf-8 -*-
import json
import os
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import Json, RealDictCursor


DB = os.getenv("DATABASE_URL") or os.getenv("NETGUARD_DB_DSN")
RUN_ONCE = os.getenv("RUN_ONCE", "false").strip().lower() in ("1", "true", "yes", "on")
HOUSEKEEPER_ENABLED = os.getenv("HOUSEKEEPER_ENABLED", "true").strip().lower() in ("1", "true", "yes", "on")
HOUSEKEEPER_INTERVAL_SEC = max(300, int(float(os.getenv("HOUSEKEEPER_INTERVAL_SEC", "3600"))))
HOUSEKEEPER_BATCH_ROWS = max(1000, int(float(os.getenv("HOUSEKEEPER_BATCH_ROWS", "50000"))))
DB_CONNECT_RETRY_SEC = float(os.getenv("DB_CONNECT_RETRY_SEC", "5"))
DB_CONNECT_RETRY_MAX_SEC = float(os.getenv("DB_CONNECT_RETRY_MAX_SEC", "60"))

RETENTION = {
    "metrics": max(1, int(float(os.getenv("RETENTION_METRICS_DAYS", "30")))),
    "syslog_events": max(1, int(float(os.getenv("RETENTION_SYSLOG_DAYS", "14")))),
    "anomaly_scores": max(1, int(float(os.getenv("RETENTION_ANOMALY_SCORES_DAYS", "30")))),
    "ai_insights": max(1, int(float(os.getenv("RETENTION_AI_INSIGHTS_DAYS", "30")))),
    "incident_notifications": max(1, int(float(os.getenv("RETENTION_NOTIFICATIONS_DAYS", "180")))),
    "resolved_incidents": max(1, int(float(os.getenv("RETENTION_RESOLVED_INCIDENTS_DAYS", "180")))),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def table_exists(cur, table: str) -> bool:
    cur.execute("select to_regclass(%s) as regclass", (table,))
    row = cur.fetchone()
    return bool(row and row.get("regclass") is not None)


def ensure_housekeeper_schema(cur) -> None:
    cur.execute(
        """
        create table if not exists housekeeper_runs (
          id bigserial primary key,
          started_at timestamptz not null default now(),
          finished_at timestamptz,
          status text not null default 'running',
          settings jsonb not null default '{}'::jsonb,
          deleted jsonb not null default '{}'::jsonb,
          error text
        )
        """
    )
    cur.execute(
        """
        create index if not exists ix_housekeeper_runs_started
          on housekeeper_runs (started_at desc, id desc)
        """
    )


def begin_run(cur) -> int:
    cur.execute(
        """
        insert into housekeeper_runs (started_at, status, settings)
        values (now(), 'running', %s)
        returning id
        """,
        (Json({"retention_days": RETENTION, "batch_rows": HOUSEKEEPER_BATCH_ROWS}),),
    )
    row = cur.fetchone()
    return int(row["id"])


def finish_run(cur, run_id: int, status: str, deleted: dict, error: str | None = None) -> None:
    cur.execute(
        """
        update housekeeper_runs
        set finished_at = now(),
            status = %s,
            deleted = %s,
            error = %s
        where id = %s
        """,
        (status, Json(deleted), error[:1000] if error else None, run_id),
    )


def delete_batch_by_ctid(cur, table: str, where_sql: str, params: tuple, batch_rows: int) -> int:
    if not table_exists(cur, table):
        return 0

    total = 0
    while True:
        cur.execute(
            f"""
            delete from {table}
            where ctid in (
              select ctid
              from {table}
              where {where_sql}
              limit %s
            )
            """,
            (*params, batch_rows),
        )
        deleted = cur.rowcount or 0
        total += deleted
        if deleted < batch_rows:
            return total


def prune_data(cur, now: datetime) -> dict:
    cutoffs = {
        name: now - timedelta(days=days)
        for name, days in RETENTION.items()
    }
    deleted = {}

    deleted["metrics"] = delete_batch_by_ctid(
        cur,
        "metrics",
        "ts < %s",
        (cutoffs["metrics"],),
        HOUSEKEEPER_BATCH_ROWS,
    )
    deleted["syslog_events"] = delete_batch_by_ctid(
        cur,
        "syslog_events",
        "ts < %s",
        (cutoffs["syslog_events"],),
        HOUSEKEEPER_BATCH_ROWS,
    )
    deleted["anomaly_scores"] = delete_batch_by_ctid(
        cur,
        "anomaly_scores",
        "ts < %s",
        (cutoffs["anomaly_scores"],),
        HOUSEKEEPER_BATCH_ROWS,
    )
    deleted["ai_insights"] = delete_batch_by_ctid(
        cur,
        "ai_insights",
        "coalesce(expires_at, created_at) < %s",
        (cutoffs["ai_insights"],),
        HOUSEKEEPER_BATCH_ROWS,
    )
    deleted["incident_notifications"] = delete_batch_by_ctid(
        cur,
        "incident_notifications",
        "sent_at < %s",
        (cutoffs["incident_notifications"],),
        HOUSEKEEPER_BATCH_ROWS,
    )
    deleted["resolved_incidents"] = delete_batch_by_ctid(
        cur,
        "incidents",
        """
        lower(coalesce(status, '')) in ('resolved', 'closed')
        and coalesce(resolved_at, last_seen_at, updated_at, created_at, opened_at) < %s
        """,
        (cutoffs["resolved_incidents"],),
        HOUSEKEEPER_BATCH_ROWS,
    )

    return deleted


def run_cycle(conn) -> dict:
    with conn:
        with conn.cursor() as cur:
            ensure_housekeeper_schema(cur)
            run_id = begin_run(cur)
            try:
                deleted = prune_data(cur, utc_now())
            except Exception as exc:
                finish_run(cur, run_id, "failed", {}, str(exc))
                raise
            finish_run(cur, run_id, "success", deleted)
            return {"run_id": run_id, "deleted": deleted}


def main() -> None:
    if not DB:
        raise SystemExit("DATABASE_URL/NETGUARD_DB_DSN nao definido")

    if not HOUSEKEEPER_ENABLED:
        print("Housekeeper desabilitado por HOUSEKEEPER_ENABLED=false", flush=True)
        return

    wait_sec = DB_CONNECT_RETRY_SEC
    while True:
        try:
            conn = psycopg2.connect(DB, cursor_factory=RealDictCursor)
            break
        except psycopg2.OperationalError as exc:
            print(f"Housekeeper aguardando banco ficar pronto: {exc}", flush=True)
            time.sleep(wait_sec)
            wait_sec = min(DB_CONNECT_RETRY_MAX_SEC, max(DB_CONNECT_RETRY_SEC, wait_sec * 2))

    try:
        while True:
            try:
                result = run_cycle(conn)
                print(f"Housekeeper ok: {json.dumps(result, ensure_ascii=False)}", flush=True)
            except Exception as exc:
                print(f"Housekeeper falhou: {exc}", flush=True)
                try:
                    conn.rollback()
                except Exception:
                    pass

            if RUN_ONCE:
                break
            time.sleep(HOUSEKEEPER_INTERVAL_SEC)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
