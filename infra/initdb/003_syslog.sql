create table if not exists syslog_events (
  id bigserial primary key,
  ts timestamptz not null,
  hostname text not null,
  src_ip inet not null,
  process text,
  pid int,
  event_id int,
  severity text,
  subsystem text,
  slot text,
  iface text,
  message text not null,
  raw text not null
);

create index if not exists ix_syslog_events_ts on syslog_events(ts desc);
create index if not exists ix_syslog_events_host_ts on syslog_events(hostname, ts desc);
create index if not exists ix_syslog_events_ip_ts on syslog_events(src_ip, ts desc);

create table if not exists incidents (
  id bigserial primary key,
  opened_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  status text not null default 'open',
  hostname text not null,
  src_ip inet not null,
  incident_type text not null,
  key text not null,
  severity text not null,
  title text not null,
  details jsonb not null default '{}'::jsonb
);

create unique index if not exists ux_incidents_open_key
on incidents(key)
where status = 'open';

insert into schema_migrations (version, description)
values ('003_syslog', 'Schema de syslog_events e incidents consolidado')
on conflict (version) do nothing;
