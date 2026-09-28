CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  ip   INET NOT NULL,
  snmp_profile JSONB,
  tags JSONB,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE assets ADD COLUMN IF NOT EXISTS snmp_profile JSONB;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS enabled BOOLEAN;
UPDATE assets
SET enabled = TRUE
WHERE enabled IS NULL;
ALTER TABLE assets ALTER COLUMN enabled SET DEFAULT TRUE;
ALTER TABLE assets ALTER COLUMN enabled SET NOT NULL;

CREATE TABLE IF NOT EXISTS metrics (
  ts timestamptz NOT NULL,
  asset_id INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  metric TEXT NOT NULL,
  value DOUBLE PRECISION NOT NULL,
  labels JSONB,
  PRIMARY KEY (ts, asset_id, metric)
);

ALTER TABLE metrics ADD COLUMN IF NOT EXISTS labels JSONB;
SELECT create_hypertable('metrics','ts', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_metrics_asset_metric_ts ON metrics(asset_id, metric, ts DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_brin_ts ON metrics USING BRIN(ts);

insert into schema_migrations (version, description)
values ('001_netguard', 'Schema base de assets e metrics consolidado')
on conflict (version) do nothing;
