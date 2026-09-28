ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL;

ALTER TABLE syslog_events
  ADD COLUMN IF NOT EXISTS asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL;

UPDATE incidents i
SET asset_id = (
  SELECT a.id AS asset_id
  FROM assets a
  WHERE split_part(a.ip::text, '/', 1) = split_part(i.src_ip::text, '/', 1)
     OR LOWER(a.name) = LOWER(i.hostname)
  ORDER BY
    CASE WHEN split_part(a.ip::text, '/', 1) = split_part(i.src_ip::text, '/', 1) THEN 0 ELSE 1 END,
    CASE WHEN LOWER(a.name) = LOWER(i.hostname) THEN 0 ELSE 1 END,
    a.id
  LIMIT 1
)
WHERE i.asset_id IS NULL;

UPDATE syslog_events s
SET asset_id = (
  SELECT a.id AS asset_id
  FROM assets a
  WHERE split_part(a.ip::text, '/', 1) = split_part(s.src_ip::text, '/', 1)
     OR LOWER(a.name) = LOWER(s.hostname)
  ORDER BY
    CASE WHEN split_part(a.ip::text, '/', 1) = split_part(s.src_ip::text, '/', 1) THEN 0 ELSE 1 END,
    CASE WHEN LOWER(a.name) = LOWER(s.hostname) THEN 0 ELSE 1 END,
    a.id
  LIMIT 1
)
WHERE s.asset_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_incidents_asset_status_last_seen
  ON incidents (asset_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS ix_incidents_asset_severity_last_seen
  ON incidents (asset_id, severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS ix_incidents_status_opened
  ON incidents (status, opened_at DESC);

CREATE INDEX IF NOT EXISTS ix_incidents_severity_opened
  ON incidents (severity, opened_at DESC);

CREATE INDEX IF NOT EXISTS ix_incidents_type_last_seen
  ON incidents (incident_type, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS ix_syslog_events_asset_ts
  ON syslog_events (asset_id, ts DESC);

CREATE INDEX IF NOT EXISTS ix_syslog_events_severity_ts
  ON syslog_events (severity, ts DESC);

CREATE INDEX IF NOT EXISTS ix_syslog_events_subsystem_ts
  ON syslog_events (subsystem, ts DESC);

INSERT INTO schema_migrations (version, description)
VALUES (
  '012_operation_v2',
  'Vinculos operacionais entre assets, incidents e syslog_events para operacao v2'
)
ON CONFLICT (version) DO NOTHING;
