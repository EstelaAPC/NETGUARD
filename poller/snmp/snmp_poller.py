# -*- coding: utf-8 -*-
import json
import os
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from psycopg2.extras import RealDictCursor
from pysnmp.hlapi import *

DB_DSN = os.getenv("DATABASE_URL") or os.getenv("NETGUARD_DB_DSN")
FALLBACK_INTERVAL = max(5, int(float(os.getenv("SNMP_INTERVAL_SEC", "30"))))
SCHEDULER_TICK = float(os.getenv("SNMP_SCHEDULER_TICK_SEC", "5"))
DEFAULT_TIMEOUT = max(1, int(float(os.getenv("DEFAULT_COLLECTION_TIMEOUT_SEC", "1"))))
DEFAULT_RETRIES = max(1, int(float(os.getenv("DEFAULT_COLLECTION_RETRIES", "1"))))
DB_RETRY_SEC = max(1, int(float(os.getenv("DB_RETRY_SEC", "5"))))

OIDS = {
  "sysName": "1.3.6.1.2.1.1.5.0",
  "sysDescr": "1.3.6.1.2.1.1.1.0",
  "sysObjectID": "1.3.6.1.2.1.1.2.0",
  "sysUpTime": "1.3.6.1.2.1.1.3.0",
  "ifDescr": "1.3.6.1.2.1.2.2.1.2",
  "ifName": "1.3.6.1.2.1.31.1.1.1.1",
  "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
  "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
  "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
  "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
  "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
  "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
  "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
  "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
  "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
  "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
  "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
  "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
  "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
  "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
}


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
    row = cur.fetchone()
    if isinstance(row, dict):
        return bool(next(iter(row.values()), False))
    return bool(row[0]) if row else False


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
    row = cur.fetchone()
    if isinstance(row, dict):
        return bool(next(iter(row.values()), False))
    return bool(row[0]) if row else False


def has_table(cur, table_name):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = %s
        )
        """,
        (table_name,),
    )
    row = cur.fetchone()
    if isinstance(row, dict):
        return bool(next(iter(row.values()), False))
    return bool(row[0]) if row else False


def has_monitoring_items_schema(cur):
    return has_table(cur, "monitoring_items")


def row_value(row, key, index=None, default=None):
    if isinstance(row, dict):
        return row.get(key, default)
    if isinstance(row, (list, tuple)):
        if index is not None and 0 <= index < len(row):
            return row[index]
        return default
    return default


def ip_without_cidr(value):
    text = str(value or "").strip()
    return text.split("/", 1)[0] if "/" in text else text


def is_false_tag(tags, key):
    if not isinstance(tags, dict):
        return False
    value = tags.get(key)
    if isinstance(value, bool):
        return value is False
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "nao", "não"}
    return False


def normalize_collection_policy(raw):
    data = raw if isinstance(raw, dict) else {}
    return {
        "icmp_interval_sec": max(5, int(float(data.get("icmp_interval_sec", FALLBACK_INTERVAL)))),
        "snmp_interval_sec": max(5, int(float(data.get("snmp_interval_sec", FALLBACK_INTERVAL)))),
        "tcp_interval_sec": max(5, int(float(data.get("tcp_interval_sec", 60)))),
        "timeout_sec": max(1, int(float(data.get("timeout_sec", DEFAULT_TIMEOUT)))),
        "retries": max(0, int(float(data.get("retries", DEFAULT_RETRIES)))),
        "history_retention_days": max(1, int(float(data.get("history_retention_days", 30)))),
        "trend_retention_days": max(1, int(float(data.get("trend_retention_days", 90)))),
        "log_retention_days": max(1, int(float(data.get("log_retention_days", 14)))),
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


def get_conn():
    if not DB_DSN:
        raise SystemExit("DATABASE_URL/NETGUARD_DB_DSN não definido")
    while True:
        try:
            return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)
        except psycopg2.OperationalError as exc:
            print(f"[SNMP] banco indisponivel, nova tentativa em {DB_RETRY_SEC}s: {exc}", flush=True)
            time.sleep(DB_RETRY_SEC)


def walk_v2c(ip, community, port, timeout, retries, oid):
    if str(oid).endswith(".0"):
        it = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        out = {}
        for errInd, errStat, errIdx, varBinds in it:
            if errInd or errStat:
                break
            for vb in varBinds:
                name, val = vb
                out[0] = val.prettyPrint()
        return out

    it = nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    )
    out = {}
    for errInd, errStat, errIdx, varBinds in it:
        if errInd or errStat:
            break
        for vb in varBinds:
            name, val = vb
            idx = int(str(name).split(".")[-1])
            out[idx] = val.prettyPrint()
    return out


def get_assets(cur):
    collection_policy_ready = has_assets_collection_policy_schema(cur)
    snmp_profile_expr = "COALESCE(a.snmp_profile, '{}'::jsonb)"
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
            a.name,
            a.ip,
            a.enabled,
            a.template_id,
            {snmp_profile_expr} AS snmp_profile,
            {collection_policy_expr} AS collection_policy_override,
            {template_definition_expr} AS template_definition,
            COALESCE(a.tags, '{{}}'::jsonb) AS tags,
            COALESCE(t.slug, '') AS template_slug
        FROM assets a
        LEFT JOIN monitoring_templates t ON t.id = a.template_id
        WHERE a.enabled = true
        """
    )
    rows = cur.fetchall()

    assets = []
    for row in rows:
        prof = row_value(row, "snmp_profile", 5, {}) or {}
        tags = row_value(row, "tags", 8, {}) or {}
        template_slug = str(row_value(row, "template_slug", 9, "") or "").strip().lower()
        if prof.get("enabled", True) is False:
            continue
        if is_false_tag(tags, "snmp_expected") or is_false_tag(tags, "snmp"):
            continue
        if template_slug == "icmp-only":
            continue

        assets.append({
            "asset_id": row_value(row, "id", 0),
            "name": row_value(row, "name", 1),
            "ip": ip_without_cidr(row_value(row, "ip", 2)),
            "template_id": row_value(row, "template_id", 4),
            "profile": prof,
            "template_slug": template_slug,
            "collection_policy": resolve_collection_policy(
                row_value(row, "template_definition", 7, {}) or {},
                row_value(row, "collection_policy_override", 6, {}) or {},
            ),
        })
    return assets


def get_last_snmp_timestamps(cur, asset_ids):
    if not asset_ids:
        return {}

    cur.execute(
        """
        SELECT DISTINCT ON (asset_id) asset_id, ts
        FROM metrics
        WHERE asset_id = ANY(%s)
          AND metric LIKE 'snmp.%%'
        ORDER BY asset_id, ts DESC
        """,
        (asset_ids,),
    )
    rows = cur.fetchall()
    return {
        int(row_value(row, "asset_id", 0)): row_value(row, "ts", 1)
        for row in rows
        if row_value(row, "asset_id", 0) is not None and row_value(row, "ts", 1) is not None
    }


def get_pending_requests(cur, asset_ids):
    if not asset_ids:
        return set()
    if not has_collection_requests_schema(cur):
        return set()

    cur.execute(
        """
        SELECT DISTINCT asset_id
        FROM collection_requests
        WHERE asset_id = ANY(%s)
          AND status = 'pending'
          AND protocol = 'snmp'
        """,
        (asset_ids,),
    )
    return {
        int(row_value(row, "asset_id", 0))
        for row in cur.fetchall()
        if row_value(row, "asset_id", 0) is not None
    }


def mark_pending_requests(cur, asset_id, status="processed", details=None):
    if not has_collection_requests_schema(cur):
        return
    cur.execute(
        """
        UPDATE collection_requests
        SET status = %s,
            processed_at = now(),
            details = COALESCE(details, '{}'::jsonb) || %s::jsonb
        WHERE asset_id = %s
          AND protocol = 'snmp'
          AND status = 'pending'
        """,
        (
            status,
            json.dumps(details or {"processed_by": "snmp-poller"}),
            asset_id,
        ),
    )


def ensure_host_monitoring_items(cur, asset_id, template_id):
    if not template_id or not has_monitoring_items_schema(cur):
        return
    cur.execute(
        """
        INSERT INTO monitoring_items (
            host_id, protocol, item_key, display_name, oid, unit, enabled,
            poll_interval_seconds, timeout_seconds, retries,
            history_retention_days, trend_retention_days, log_retention_days, config
        )
        SELECT
            %s, protocol, item_key, display_name, oid, unit, enabled,
            poll_interval_seconds, timeout_seconds, retries,
            history_retention_days, trend_retention_days, log_retention_days, config
        FROM monitoring_items
        WHERE template_id = %s
          AND host_id IS NULL
        ON CONFLICT DO NOTHING
        """,
        (asset_id, template_id),
    )


def get_enabled_item_keys(cur, asset_id, template_id):
    default_keys = set()
    if not has_monitoring_items_schema(cur):
        return None
    ensure_host_monitoring_items(cur, asset_id, template_id)
    cur.execute(
        """
        SELECT item_key
        FROM monitoring_items
        WHERE host_id=%s
          AND enabled=true
        """,
        (asset_id,),
    )
    for row in cur.fetchall():
        default_keys.add(row_value(row, "item_key", 0))
    return default_keys


def item_enabled(enabled_keys, key):
    return enabled_keys is None or key in enabled_keys


def mark_items_collected(cur, asset_id, item_keys, error=None):
    if not item_keys or not has_monitoring_items_schema(cur):
        return
    cur.execute(
        """
        UPDATE monitoring_items
        SET last_collected_at = CASE WHEN %s IS NULL THEN now() ELSE last_collected_at END,
            last_error = %s,
            updated_at = now()
        WHERE host_id=%s
          AND item_key = ANY(%s)
        """,
        (error, error, asset_id, list(item_keys)),
    )


def safe_walk_v2c(ip, community, port, timeout, retries, oid):
    try:
        return walk_v2c(ip, community, port, timeout, retries, oid)
    except Exception:
        return {}


def should_select_interface(ifdescr, admin_status):
    name = str(ifdescr or "").strip().lower()
    if not name or name in {"lo", "loopback", "null0", "vlan1"}:
        return False
    return safe_int(admin_status) == 1


def upsert_interface_inventory(cur, asset_id, maps, ts):
    descr = maps.get("ifDescr", {})
    ifname = maps.get("ifName", {})
    ifalias = maps.get("ifAlias", {})
    admin = maps.get("ifAdminStatus", {})
    oper = maps.get("ifOperStatus", {})
    highspeed = maps.get("ifHighSpeed", {})
    speed = maps.get("ifSpeed", {})
    mac = maps.get("ifPhysAddress", {})
    in_oct = maps.get("ifInOctetsEffective", {})
    out_oct = maps.get("ifOutOctetsEffective", {})
    in_err = maps.get("ifInErrors", {})
    out_err = maps.get("ifOutErrors", {})
    in_dis = maps.get("ifInDiscards", {})
    out_dis = maps.get("ifOutDiscards", {})

    for ifi, ifdescr in descr.items():
        admin_status = safe_int(admin.get(ifi))
        highspeed_bps = safe_int(highspeed.get(ifi)) * 1000000 if highspeed.get(ifi) is not None else 0
        speed_bps = highspeed_bps or safe_int(speed.get(ifi)) or None
        selected = should_select_interface(ifdescr, admin_status)
        cur.execute(
            """
            INSERT INTO discovered_interfaces (
                asset_id, ifindex, ifdescr, if_name, if_alias, admin_status, oper_status,
                speed_bps, mac_address, last_in_octets, last_out_octets, last_in_errors,
                last_out_errors, last_in_discards, last_out_discards, selected,
                last_seen_at, updated_at
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (asset_id, ifindex) DO UPDATE SET
                ifdescr=EXCLUDED.ifdescr,
                if_name=EXCLUDED.if_name,
                if_alias=EXCLUDED.if_alias,
                admin_status=EXCLUDED.admin_status,
                oper_status=EXCLUDED.oper_status,
                speed_bps=EXCLUDED.speed_bps,
                mac_address=EXCLUDED.mac_address,
                last_in_octets=EXCLUDED.last_in_octets,
                last_out_octets=EXCLUDED.last_out_octets,
                last_in_errors=EXCLUDED.last_in_errors,
                last_out_errors=EXCLUDED.last_out_errors,
                last_in_discards=EXCLUDED.last_in_discards,
                last_out_discards=EXCLUDED.last_out_discards,
                selected=discovered_interfaces.selected OR EXCLUDED.selected,
                last_seen_at=EXCLUDED.last_seen_at,
                updated_at=EXCLUDED.updated_at,
                last_error=NULL
            """,
            (
                asset_id,
                ifi,
                ifdescr,
                ifname.get(ifi),
                ifalias.get(ifi),
                admin_status or None,
                safe_int(oper.get(ifi)) or None,
                speed_bps,
                mac.get(ifi),
                safe_int(in_oct.get(ifi)),
                safe_int(out_oct.get(ifi)),
                safe_int(in_err.get(ifi)),
                safe_int(out_err.get(ifi)),
                safe_int(in_dis.get(ifi)),
                safe_int(out_dis.get(ifi)),
                selected,
                ts,
                ts,
            ),
        )


def get_selected_interfaces(cur, asset_id):
    cur.execute(
        """
        SELECT ifindex, ifdescr, if_name, if_alias
        FROM discovered_interfaces
        WHERE asset_id = %s
          AND selected = true
        ORDER BY ifindex
        """,
        (asset_id,),
    )
    rows = cur.fetchall()
    return {
        int(row_value(row, "ifindex", 0)): (
            row_value(row, "if_name", 2)
            or row_value(row, "ifdescr", 1)
            or row_value(row, "if_alias", 3)
        )
        for row in rows
        if row_value(row, "ifindex", 0) is not None
    }


def insert_metric(cur, ts, asset_id, metric, value, labels):
    cur.execute(
        """
        INSERT INTO metrics (ts, asset_id, metric, value, labels)
        VALUES (%s,%s,%s,%s,%s::jsonb)
        ON CONFLICT (ts, asset_id, metric) DO NOTHING
        """,
        (ts, asset_id, metric, float(value), json.dumps(labels) if labels else None)
    )


def safe_int(x):
    try:
        return int(x)
    except Exception:
        return 0


def should_collect(now, last_ts, interval_sec, forced):
    if forced or last_ts is None:
        return True
    return now >= last_ts + timedelta(seconds=int(interval_sec))


def collect_asset(cur, asset):
    ts = datetime.now(timezone.utc)
    profile = asset["profile"]
    policy = asset["collection_policy"]
    ip = asset["ip"]
    asset_id = asset["asset_id"]
    enabled_keys = get_enabled_item_keys(cur, asset_id, asset.get("template_id"))
    version = (profile.get("version") or "v2c").lower()
    if version not in ("v2c", "2c"):
        return False, {"processed_by": "snmp-poller", "reason": "unsupported_version"}

    community = profile.get("community", "public")
    port = int(profile.get("port", 161))
    timeout = float(policy["timeout_sec"])
    retries = int(policy["retries"])

    system_values = {}
    for item_key, oid_name in (
        ("snmp.sysName", "sysName"),
        ("snmp.sysDescr", "sysDescr"),
        ("snmp.sysObjectID", "sysObjectID"),
        ("snmp.sysUpTime", "sysUpTime"),
    ):
        if item_enabled(enabled_keys, item_key):
            values = safe_walk_v2c(ip, community, port, timeout, retries, OIDS[oid_name])
            if values:
                system_values[item_key] = next(iter(values.values()))

    if system_values:
        cur.execute(
            """
            UPDATE assets
            SET tags = COALESCE(tags, '{}'::jsonb) || %s::jsonb
            WHERE id=%s
            """,
            (json.dumps({"snmp_system": system_values}), asset_id),
        )
        mark_items_collected(cur, asset_id, system_values.keys())

    descr = walk_v2c(ip, community, port, timeout, retries, OIDS["ifDescr"])
    ifname = safe_walk_v2c(ip, community, port, timeout, retries, OIDS["ifName"])
    ifalias = safe_walk_v2c(ip, community, port, timeout, retries, OIDS["ifAlias"])
    in_oct = walk_v2c(ip, community, port, timeout, retries, OIDS["ifHCInOctets"])
    out_oct = walk_v2c(ip, community, port, timeout, retries, OIDS["ifHCOutOctets"])
    if not in_oct:
        in_oct = walk_v2c(ip, community, port, timeout, retries, OIDS["ifInOctets"])
    if not out_oct:
        out_oct = walk_v2c(ip, community, port, timeout, retries, OIDS["ifOutOctets"])
    in_err = walk_v2c(ip, community, port, timeout, retries, OIDS["ifInErrors"])
    out_err = walk_v2c(ip, community, port, timeout, retries, OIDS["ifOutErrors"])
    in_dis = walk_v2c(ip, community, port, timeout, retries, OIDS["ifInDiscards"])
    out_dis = walk_v2c(ip, community, port, timeout, retries, OIDS["ifOutDiscards"])
    oper = walk_v2c(ip, community, port, timeout, retries, OIDS["ifOperStatus"])
    admin = walk_v2c(ip, community, port, timeout, retries, OIDS["ifAdminStatus"])
    speed = safe_walk_v2c(ip, community, port, timeout, retries, OIDS["ifSpeed"])
    highspeed = safe_walk_v2c(ip, community, port, timeout, retries, OIDS["ifHighSpeed"])
    mac = safe_walk_v2c(ip, community, port, timeout, retries, OIDS["ifPhysAddress"])

    maps = {
        "ifDescr": descr,
        "ifName": ifname,
        "ifAlias": ifalias,
        "ifInOctetsEffective": in_oct,
        "ifOutOctetsEffective": out_oct,
        "ifInErrors": in_err,
        "ifOutErrors": out_err,
        "ifInDiscards": in_dis,
        "ifOutDiscards": out_dis,
        "ifOperStatus": oper,
        "ifAdminStatus": admin,
        "ifSpeed": speed,
        "ifHighSpeed": highspeed,
        "ifPhysAddress": mac,
    }
    upsert_interface_inventory(cur, asset_id, maps, ts)
    mark_items_collected(
        cur,
        asset_id,
        {
            "snmp.ifDescr",
            "snmp.ifName",
            "snmp.ifAlias",
            "snmp.ifOperStatus",
            "snmp.ifAdminStatus",
            "snmp.ifHCInOctets",
            "snmp.ifHCOutOctets",
            "snmp.ifInErrors",
            "snmp.ifOutErrors",
            "snmp.ifInDiscards",
            "snmp.ifOutDiscards",
        },
    )

    selected_interfaces = get_selected_interfaces(cur, asset_id)
    if not selected_interfaces:
        selected_interfaces = {
            ifi: (ifname.get(ifi) or name)
            for ifi, name in descr.items()
            if should_select_interface(name, admin.get(ifi))
        }
    if not selected_interfaces:
        return False, {"processed_by": "snmp-poller", "reason": "no_interfaces_available"}

    for ifi, ifname in selected_interfaces.items():
        labels = {"ifIndex": ifi, "ifName": ifname}
        if item_enabled(enabled_keys, "snmp.ifHCInOctets"):
            insert_metric(cur, ts, asset_id, f"snmp.if.in_octets|ifIndex={ifi}", safe_int(in_oct.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifHCOutOctets"):
            insert_metric(cur, ts, asset_id, f"snmp.if.out_octets|ifIndex={ifi}", safe_int(out_oct.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifInErrors"):
            insert_metric(cur, ts, asset_id, f"snmp.if.in_errors|ifIndex={ifi}", safe_int(in_err.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifOutErrors"):
            insert_metric(cur, ts, asset_id, f"snmp.if.out_errors|ifIndex={ifi}", safe_int(out_err.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifInDiscards"):
            insert_metric(cur, ts, asset_id, f"snmp.if.in_discards|ifIndex={ifi}", safe_int(in_dis.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifOutDiscards"):
            insert_metric(cur, ts, asset_id, f"snmp.if.out_discards|ifIndex={ifi}", safe_int(out_dis.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifOperStatus"):
            insert_metric(cur, ts, asset_id, f"snmp.if.oper_status|ifIndex={ifi}", safe_int(oper.get(ifi)), labels)
        if item_enabled(enabled_keys, "snmp.ifAdminStatus"):
            insert_metric(cur, ts, asset_id, f"snmp.if.admin_status|ifIndex={ifi}", safe_int(admin.get(ifi)), labels)

    return True, {"processed_by": "snmp-poller", "interfaces_polled": len(selected_interfaces)}


def main():
    while True:
        conn = get_conn()
        try:
            conn.autocommit = True
            cur = conn.cursor()

            while True:
                now = datetime.now(timezone.utc)
                assets = get_assets(cur)
                asset_ids = [asset["asset_id"] for asset in assets]
                last_snmp_by_asset = get_last_snmp_timestamps(cur, asset_ids)
                forced_assets = get_pending_requests(cur, asset_ids)

                due_assets = []
                for asset in assets:
                    last_snmp = last_snmp_by_asset.get(asset["asset_id"])
                    forced = asset["asset_id"] in forced_assets
                    if should_collect(now, last_snmp, asset["collection_policy"]["snmp_interval_sec"], forced):
                        due_assets.append((asset, forced))

                for asset, forced in due_assets:
                    try:
                        collected, details = collect_asset(cur, asset)
                        if forced:
                            mark_pending_requests(
                                cur,
                                asset["asset_id"],
                                status="processed",
                                details=details,
                            )
                    except psycopg2.Error:
                        raise
                    except Exception as exc:
                        print(f"[SNMP] falha ao coletar asset_id={asset['asset_id']} ip={asset['ip']}: {exc}", flush=True)
                        if forced:
                            mark_pending_requests(
                                cur,
                                asset["asset_id"],
                                status="failed",
                                details={"processed_by": "snmp-poller", "error": str(exc)},
                            )

                time.sleep(SCHEDULER_TICK)
        except psycopg2.Error as exc:
            print(f"[SNMP] conexao com banco perdida, reconectando em {DB_RETRY_SEC}s: {exc}", flush=True)
            try:
                conn.close()
            except Exception:
                pass
            time.sleep(DB_RETRY_SEC)


if __name__ == "__main__":
    main()
