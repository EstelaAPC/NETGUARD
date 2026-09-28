alter table incidents
  add column if not exists opening_notification_sent boolean default false,
  add column if not exists recovery_notification_sent boolean default false,
  add column if not exists opening_notified_at timestamptz,
  add column if not exists recovery_notified_at timestamptz,
  add column if not exists last_notification_at timestamptz,
  add column if not exists notification_fingerprint text;

with first_success as (
  select incident_id, min(sent_at) as sent_at
  from incident_notifications
  where lower(coalesce(delivery_status, '')) = 'success'
    and lower(coalesce(provider, '')) <> 'anti_spam'
  group by incident_id
),
recovery_success as (
  select i.id as incident_id, min(n.sent_at) as sent_at
  from incidents i
  join incident_notifications n on n.incident_id = i.id
  where i.resolved_at is not null
    and n.sent_at >= i.resolved_at
    and lower(coalesce(n.delivery_status, '')) = 'success'
    and lower(coalesce(n.provider, '')) <> 'anti_spam'
  group by i.id
),
lifecycle as (
  select
    i.id,
    first_success.sent_at as opening_success_at,
    recovery_success.sent_at as recovery_success_at
  from incidents i
  left join first_success on first_success.incident_id = i.id
  left join recovery_success on recovery_success.incident_id = i.id
)
update incidents i
set
  opening_notification_sent = coalesce(i.opening_notification_sent, false)
    or coalesce(i.notification_sent, false)
    or lifecycle.opening_success_at is not null,
  opening_notified_at = coalesce(i.opening_notified_at, lifecycle.opening_success_at),
  recovery_notification_sent = coalesce(i.recovery_notification_sent, false)
    or lifecycle.recovery_success_at is not null,
  recovery_notified_at = coalesce(i.recovery_notified_at, lifecycle.recovery_success_at),
  last_notification_at = nullif(greatest(
    coalesce(i.last_notification_at, '-infinity'::timestamptz),
    coalesce(i.opening_notified_at, '-infinity'::timestamptz),
    coalesce(lifecycle.opening_success_at, '-infinity'::timestamptz),
    coalesce(i.recovery_notified_at, '-infinity'::timestamptz),
    coalesce(lifecycle.recovery_success_at, '-infinity'::timestamptz)
  ), '-infinity'::timestamptz),
  notification_fingerprint = coalesce(
    nullif(i.notification_fingerprint, ''),
    nullif(i.details->>'notification_fingerprint', ''),
    nullif(i.details->>'loop_fingerprint', ''),
    concat_ws('|',
      split_part(coalesce(i.device_ip::text, i.src_ip::text, ''), '/', 1),
      upper(coalesce(i.problem_type, i.incident_type, '')),
      coalesce(
        nullif(i.details->>'interface_pair', ''),
        nullif(i.details->>'affected_context', ''),
        nullif(i.details->>'ifName', ''),
        nullif(i.details->>'item', ''),
        'host'
      )
    )
  ),
  notification_sent = coalesce(i.notification_sent, false)
    or coalesce(i.opening_notification_sent, false)
    or lifecycle.opening_success_at is not null
from lifecycle
where i.id = lifecycle.id
  and (
    lifecycle.opening_success_at is not null
    or lifecycle.recovery_success_at is not null
    or i.opening_notification_sent is null
    or i.recovery_notification_sent is null
    or i.notification_fingerprint is null
  );

alter table incidents
  alter column opening_notification_sent set default false,
  alter column opening_notification_sent set not null,
  alter column recovery_notification_sent set default false,
  alter column recovery_notification_sent set not null;

create index if not exists ix_incidents_notification_lifecycle
  on incidents (status, notification_sent, recovery_notification_sent, resolved_at desc);

create index if not exists ix_incidents_notification_fingerprint
  on incidents (notification_fingerprint, last_notification_at desc);

insert into schema_migrations (version, description)
values (
  '019_notification_lifecycle',
  'Controle persistente de abertura, recuperacao e fingerprint de notificacoes de incidentes'
)
on conflict (version) do nothing;
