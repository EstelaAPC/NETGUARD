create table if not exists anomaly_scores (
  ts timestamptz not null,
  asset_id integer not null references assets(id) on delete cascade,
  metric text not null,                 -- ex: "snmp.if.in_errors.delta"
  key text not null,                    -- ex: "ifIndex=3"
  score double precision not null,      -- 0..1
  z double precision,
  value double precision,
  baseline_mean double precision,
  baseline_std double precision,
  details jsonb,
  primary key (ts, asset_id, metric, key)
);

create index if not exists anomaly_scores_ts_idx on anomaly_scores (ts desc);
create index if not exists anomaly_scores_asset_ts_idx on anomaly_scores (asset_id, ts desc);

insert into schema_migrations (version, description)
values ('007_anomaly', 'Schema de anomaly_scores consolidado')
on conflict (version) do nothing;
