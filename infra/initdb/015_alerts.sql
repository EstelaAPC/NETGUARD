alter table incidents
  add column if not exists device_name text,
  add column if not exists device_ip inet,
  add column if not exists problem_type text,
  add column if not exists description text,
  add column if not exists first_detected_at timestamptz,
  add column if not exists last_detected_at timestamptz,
  add column if not exists resolved_at timestamptz,
  add column if not exists notification_sent boolean default false,
  add column if not exists created_at timestamptz default now(),
  add column if not exists updated_at timestamptz default now();

update incidents
set
  device_name = coalesce(device_name, hostname),
  device_ip = coalesce(device_ip, src_ip),
  problem_type = coalesce(problem_type, incident_type),
  description = coalesce(description, title),
  first_detected_at = coalesce(first_detected_at, opened_at),
  last_detected_at = coalesce(last_detected_at, last_seen_at),
  notification_sent = coalesce(notification_sent, false),
  created_at = coalesce(created_at, opened_at, now()),
  updated_at = coalesce(updated_at, last_seen_at, opened_at, now()),
  resolved_at = case
    when resolved_at is null and lower(status) = 'resolved' then last_seen_at
    else resolved_at
  end;

alter table incidents
  alter column notification_sent set default false,
  alter column notification_sent set not null,
  alter column created_at set default now(),
  alter column created_at set not null,
  alter column updated_at set default now(),
  alter column updated_at set not null;

create index if not exists ix_incidents_alert_open_dedupe
  on incidents (device_ip, problem_type, status, last_detected_at desc);

create index if not exists ix_incidents_alert_resolved
  on incidents (resolved_at desc)
  where resolved_at is not null;

create table if not exists incident_notifications (
  id bigserial primary key,
  incident_id bigint references incidents(id) on delete cascade,
  channel text not null,
  provider text,
  delivery_status text not null,
  error text,
  sent_at timestamptz not null default now()
);

create index if not exists ix_incident_notifications_incident_sent
  on incident_notifications (incident_id, sent_at desc);

insert into schema_migrations (version, description)
values (
  '015_alerts',
  'Alertas por email e webhook com deduplicacao operacional de incidentes'
)
on conflict (version) do nothing;
