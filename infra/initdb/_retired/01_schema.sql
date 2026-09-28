CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  ip INET NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS metrics (
  ts TIMESTAMPTZ NOT NULL,
  asset_id INT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  metric TEXT NOT NULL,
  value DOUBLE PRECISION NOT NULL,
  labels JSONB,
  PRIMARY KEY (ts, asset_id, metric)
);

SELECT create_hypertable('metrics','ts', if_not_exists => TRUE);
