create unique index if not exists ux_incidents_open_key
on incidents(key)
where status = 'open';

create index if not exists ix_syslog_events_loop_ts_src
on syslog_events (ts desc, src_ip);

create index if not exists ix_syslog_events_loop_ts_host
on syslog_events (ts desc, hostname);

create index if not exists ix_syslog_events_loop_host_lower_ts
on syslog_events ((lower(hostname)), ts desc);

create index if not exists ix_anomaly_scores_asset_metric_ts
on anomaly_scores (asset_id, metric, ts desc);

create index if not exists ix_incidents_src_type_status_opened
on incidents (src_ip, incident_type, status, opened_at desc);

create index if not exists ix_incidents_host_lower_type_status_opened
on incidents ((lower(hostname)), incident_type, status, opened_at desc);

insert into schema_migrations (version, description)
values ('008_loop_risk_pipeline', 'Indexes e garantias para o pipeline nativo de loop_risk')
on conflict (version) do nothing;
