update incidents
set
  device_name = coalesce(device_name, hostname),
  device_ip = coalesce(device_ip, src_ip),
  problem_type = coalesce(problem_type, upper(incident_type)),
  description = coalesce(description, title),
  first_detected_at = coalesce(first_detected_at, opened_at),
  last_detected_at = greatest(
    coalesce(last_detected_at, '-infinity'::timestamptz),
    coalesce(last_seen_at, '-infinity'::timestamptz),
    coalesce(opened_at, '-infinity'::timestamptz)
  ),
  resolved_at = case
    when resolved_at is null and lower(status) in ('resolved', 'closed') then last_seen_at
    else resolved_at
  end,
  updated_at = greatest(
    coalesce(updated_at, '-infinity'::timestamptz),
    coalesce(last_detected_at, '-infinity'::timestamptz),
    coalesce(last_seen_at, '-infinity'::timestamptz),
    coalesce(opened_at, '-infinity'::timestamptz)
  ),
  created_at = coalesce(created_at, opened_at, now())
where
  device_name is null
  or device_ip is null
  or problem_type is null
  or description is null
  or first_detected_at is null
  or last_detected_at is null
  or last_detected_at < coalesce(last_seen_at, opened_at, last_detected_at)
  or (
    lower(status) in ('resolved', 'closed')
    and resolved_at is null
  )
  or updated_at < coalesce(last_seen_at, opened_at, updated_at);

insert into schema_migrations (version, description)
values (
  '018_incident_alert_compatibility',
  'Compatibilidade entre incidentes operacionais e tela de alertas'
)
on conflict (version) do nothing;
