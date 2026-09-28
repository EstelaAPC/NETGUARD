alter table assets
  add column if not exists collection_policy_override jsonb;

update assets
set collection_policy_override = '{}'::jsonb
where collection_policy_override is null;

alter table assets
  alter column collection_policy_override set default '{}'::jsonb;

alter table assets
  alter column collection_policy_override set not null;

create table if not exists collection_requests (
  id bigserial primary key,
  asset_id bigint not null references assets(id) on delete cascade,
  protocol text not null,
  status text not null default 'pending',
  requested_at timestamptz not null default now(),
  processed_at timestamptz,
  details jsonb not null default '{}'::jsonb
);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'ck_collection_requests_protocol'
  ) then
    alter table collection_requests
      add constraint ck_collection_requests_protocol
      check (protocol in ('icmp', 'snmp', 'all'));
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'ck_collection_requests_status'
  ) then
    alter table collection_requests
      add constraint ck_collection_requests_status
      check (status in ('pending', 'processed', 'failed'));
  end if;
end $$;

create index if not exists ix_collection_requests_asset_status
on collection_requests (asset_id, status, requested_at desc);

create index if not exists ix_collection_requests_pending
on collection_requests (status, requested_at asc);

create or replace function netguard_collection_policy(
  icmp_interval integer,
  snmp_interval integer,
  timeout_sec integer,
  retries integer
) returns jsonb
language sql
immutable
as $$
  select jsonb_build_object(
    'icmp_interval_sec', icmp_interval,
    'snmp_interval_sec', snmp_interval,
    'timeout_sec', timeout_sec,
    'retries', retries
  );
$$;

update monitoring_templates
set definition = jsonb_set(
  coalesce(definition, '{}'::jsonb),
  '{collection_policy}',
  netguard_collection_policy(30, 60, 1, 1),
  true
)
where slug = 'linux-basic';

update monitoring_templates
set definition = jsonb_set(
  coalesce(definition, '{}'::jsonb),
  '{collection_policy}',
  netguard_collection_policy(30, 30, 1, 1),
  true
)
where slug = 'generic-snmp-switch';

update monitoring_templates
set definition = jsonb_set(
  coalesce(definition, '{}'::jsonb),
  '{collection_policy}',
  netguard_collection_policy(30, 30, 1, 1),
  true
)
where slug = 'netguard-lab-device';

drop function if exists netguard_collection_policy(integer, integer, integer, integer);

insert into schema_migrations (version, description)
values (
  '014_collection_policy',
  'Politica de coleta por template e override por host, com fila de coleta sob demanda'
)
on conflict (version) do nothing;
