# -*- coding: utf-8 -*-
import logging
import os
import socket
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

import psycopg
from icmplib import ping
from psycopg.errors import OperationalError
from psycopg.types.json import Jsonb
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")

DB = os.environ.get("DATABASE_URL", "postgresql://netguard:netguard@db:5432/netguard")
FALLBACK_INTERVAL = max(5, int(float(os.environ.get("POLL_INTERVAL", "30"))))
SCHEDULER_TICK = float(os.environ.get("POLL_SCHEDULER_TICK_SEC", "5"))
DEFAULT_TIMEOUT = max(1, int(float(os.environ.get("DEFAULT_COLLECTION_TIMEOUT_SEC", "1"))))
DEFAULT_RETRIES = max(1, int(float(os.environ.get("DEFAULT_COLLECTION_RETRIES", "1"))))
TCP_PORTS = [53, 80, 443]
LEGACY_SNMP_ENABLED = os.environ.get("LEGACY_SNMP_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
)


def has_assets_collection_policy_schema(cur):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'assets'
              AND column_name = 'collection_policy_override'
        )
        """
    )
    return bool(cur.fetchone()[0])


def has_collection_requests_schema(cur):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'collection_requests'
        )
        """
    )
    return bool(cur.fetchone()[0])


def connect_with_retry(max_tries=60, delay=2):
    for i in range(max_tries):
        try:
            return psycopg.connect(DB)
        except OperationalError as exc:
            logging.info(f"DB aguardando... ({i + 1}/{max_tries}) {exc}")
            time.sleep(delay)
    raise RuntimeError("DB indisponivel apos varias tentativas")


def normalize_collection_policy(raw):
    data = raw if isinstance(raw, dict) else {}
    return {
        "icmp_interval_sec": max(5, int(float(data.get("icmp_interval_sec", FALLBACK_INTERVAL)))),
        "snmp_interval_sec": max(5, int(float(data.get("snmp_interval_sec", FALLBACK_INTERVAL)))),
        "timeout_sec": max(1, int(float(data.get("timeout_sec", DEFAULT_TIMEOUT)))),
        "retries": max(1, int(float(data.get("retries", DEFAULT_RETRIES)))),
    }


def resolve_collection_policy(template_definition, override):
    resolved = normalize_collection_policy({})

    if isinstance(template_definition, dict):
        template_policy = normalize_collection_policy(template_definition.get("collection_policy") or {})
        resolved.update(template_policy)

    if isinstance(override, dict):
        for key, value in (override or {}).items():
            if value in (None, "") or key not in resolved:
                continue
            resolved[key] = max(1, int(float(value)))

    return resolved


def get_assets():
    with connect_with_retry() as conn, conn.cursor() as cur:
        collection_policy_ready = has_assets_collection_policy_schema(cur)
        collection_policy_expr = (
            "COALESCE(a.collection_policy_override, '{}'::jsonb)"
            if collection_policy_ready
            else "'{}'::jsonb"
        )
        template_definition_expr = "COALESCE(t.definition, '{}'::jsonb)"
        cur.execute(
            f"""
            SELECT
                a.id,
                a.ip,
                a.snmp_profile,
                a.tags,
                {collection_policy_expr},
                {template_definition_expr}
            FROM assets a
            LEFT JOIN monitoring_templates t ON t.id = a.template_id
            WHERE a.enabled = true
            """
        )
        rows = cur.fetchall()

    assets = []
    for row in rows:
        policy = resolve_collection_policy(row[5] or {}, row[4] or {})
        assets.append(
            {
                "asset_id": row[0],
                "ip": str(row[1]).split("/")[0],
                "snmp_profile": row[2] or {},
                "tags": row[3] or {},
                "collection_policy": policy,
            }
        )
    return assets


def get_last_icmp_timestamps(asset_ids):
    if not asset_ids:
        return {}

    with connect_with_retry() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT DISTINCT ON (asset_id) asset_id, ts
            FROM metrics
            WHERE asset_id = ANY(%s)
              AND metric = 'host.alive'
            ORDER BY asset_id, ts DESC
            """,
            (asset_ids,),
        )
        rows = cur.fetchall()

    return {int(asset_id): ts for asset_id, ts in rows}


def get_pending_requests(asset_ids, protocol):
    if not asset_ids:
        return set()

    with connect_with_retry() as conn, conn.cursor() as cur:
        if not has_collection_requests_schema(cur):
            return set()
        cur.execute(
            """
            SELECT DISTINCT asset_id
            FROM collection_requests
            WHERE asset_id = ANY(%s)
              AND status = 'pending'
              AND protocol = %s
            """,
            (asset_ids, protocol),
        )
        rows = cur.fetchall()

    return {int(asset_id) for (asset_id,) in rows}


def mark_pending_requests(asset_id, protocol, status="processed", details=None):
    with connect_with_retry() as conn, conn.cursor() as cur:
        if not has_collection_requests_schema(cur):
            return
        cur.execute(
            """
            UPDATE collection_requests
            SET status = %s,
                processed_at = now(),
                details = COALESCE(details, '{}'::jsonb) || %s::jsonb
            WHERE asset_id = %s
              AND protocol = %s
              AND status = 'pending'
            """,
            (
                status,
                Jsonb(details or {"processed_by": "icmp-poller"}),
                asset_id,
                protocol,
            ),
        )
        conn.commit()


def write_metric(ts, asset_id, metric, value, labels=None):
    if value is None:
        return

    try:
        numeric_value = float(value)
    except Exception:
        logging.info(f"[METRIC] ignorando {metric} value={value!r} (nao numerico)")
        return

    with connect_with_retry() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO metrics (ts, asset_id, metric, value, labels) VALUES (%s,%s,%s,%s,%s)",
            (ts, asset_id, metric, numeric_value, Jsonb(labels) if labels is not None else None),
        )
        conn.commit()


def snmp_get(ip, oid, community="public", timeout=1, retries=1, version="v2c"):
    try:
        mp_model = 1 if version == "v2c" else 0

        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=mp_model),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        error_indication, error_status, _, var_binds = next(iterator)
        if error_indication or error_status:
            return None

        for _, value in var_binds:
            try:
                return int(value)
            except Exception:
                try:
                    return float(value)
                except Exception:
                    text = str(value).strip()
                    return text or None
    except Exception as exc:
        logging.info(f"[SNMP] {ip} erro: {exc}")
        return None


def tcp_check(host, ports=TCP_PORTS, timeout=1.0):
    for port in ports:
        try:
            with closing(socket.create_connection((host, port), timeout=timeout)):
                return True, port
        except Exception:
            continue
    return False, None


def should_collect(now, last_ts, interval_sec, forced):
    if forced or last_ts is None:
        return True
    return now >= last_ts + timedelta(seconds=int(interval_sec))


def collect_asset(asset):
    now = datetime.now(timezone.utc)
    asset_id = asset["asset_id"]
    ip = asset["ip"]
    snmp_profile = asset["snmp_profile"] or {}
    policy = asset["collection_policy"]

    rtt_ms = 0.0
    loss = 100.0

    try:
        result = ping(
            ip,
            count=3,
            interval=0.2,
            timeout=policy["timeout_sec"],
            privileged=True,
        )
        rtt_ms = float(result.avg_rtt or 0.0)
        loss = (1 - (result.packets_received / result.packets_sent)) * 100 if result.packets_sent else 100.0
    except Exception as exc:
        logging.info(f"[PING] {ip} erro ICMP: {exc}")

    tcp_ok, port = (False, None)
    if loss == 100.0:
        tcp_ok, port = tcp_check(ip, timeout=float(policy["timeout_sec"]))
        if tcp_ok:
            write_metric(now, asset_id, "tcp.alive", 1.0, {"port": port})
            logging.info(f"[TCP ] {ip} porta {port} OK (ICMP bloqueado)")
        else:
            write_metric(now, asset_id, "tcp.alive", 0.0, None)
            logging.info(f"[TCP ] {ip} indisponivel")

    host_alive = 1.0 if (loss < 100.0) or tcp_ok else 0.0
    write_metric(now, asset_id, "host.alive", host_alive, None)
    write_metric(now, asset_id, "icmp.rtt_ms", rtt_ms, None)
    write_metric(now, asset_id, "icmp.loss_pct", loss, None)
    logging.info(f"[PING] {ip} rtt={rtt_ms:.1f}ms loss={loss:.0f}%")

    if LEGACY_SNMP_ENABLED and snmp_profile:
        community = snmp_profile.get("community", "public")
        version = snmp_profile.get("version", "v2c")
        if_index = int(snmp_profile.get("ifIndex", 1))
        timeout = policy["timeout_sec"]
        retries = policy["retries"]

        in_oid = f"1.3.6.1.2.1.2.2.1.10.{if_index}"
        out_oid = f"1.3.6.1.2.1.2.2.1.16.{if_index}"
        up_oid = "1.3.6.1.2.1.1.3.0"

        in_octets = snmp_get(ip, in_oid, community, timeout=timeout, retries=retries, version=version)
        out_octets = snmp_get(ip, out_oid, community, timeout=timeout, retries=retries, version=version)
        uptime = snmp_get(ip, up_oid, community, timeout=timeout, retries=retries, version=version)

        if in_octets is not None:
            write_metric(now, asset_id, "snmp.ifInOctets", in_octets, {"ifIndex": if_index})
        if out_octets is not None:
            write_metric(now, asset_id, "snmp.ifOutOctets", out_octets, {"ifIndex": if_index})
        if uptime is not None:
            write_metric(now, asset_id, "snmp.sysUpTime", uptime, None)


def main():
    while True:
        now = datetime.now(timezone.utc)
        assets = get_assets()
        asset_ids = [asset["asset_id"] for asset in assets]
        last_icmp_by_asset = get_last_icmp_timestamps(asset_ids)
        forced_assets = get_pending_requests(asset_ids, "icmp")

        due_assets = []
        for asset in assets:
            last_icmp = last_icmp_by_asset.get(asset["asset_id"])
            forced = asset["asset_id"] in forced_assets
            if should_collect(now, last_icmp, asset["collection_policy"]["icmp_interval_sec"], forced):
                due_assets.append((asset, forced))

        logging.info(
            f"[ICMP] ciclo agendado com {len(due_assets)} host(s) devido(s) de {len(assets)} total"
        )

        for asset, forced in due_assets:
            try:
                collect_asset(asset)
                if forced:
                    mark_pending_requests(
                        asset["asset_id"],
                        "icmp",
                        status="processed",
                        details={"processed_by": "icmp-poller"},
                    )
            except Exception as exc:
                logging.exception(f"[ICMP] falha ao coletar asset_id={asset['asset_id']}: {exc}")
                if forced:
                    mark_pending_requests(
                        asset["asset_id"],
                        "icmp",
                        status="failed",
                        details={"processed_by": "icmp-poller", "error": str(exc)},
                    )

        time.sleep(SCHEDULER_TICK)


if __name__ == "__main__":
    main()
