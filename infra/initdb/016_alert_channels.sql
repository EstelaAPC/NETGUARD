create table if not exists alert_channels (
  id bigserial primary key,
  name text not null,
  provider text not null,
  enabled boolean not null default true,
  min_severity text not null default 'LOW',
  config jsonb not null default '{}'::jsonb,
  last_test_status text,
  last_test_error text,
  last_test_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'ck_alert_channels_provider'
  ) then
    alter table alert_channels
      add constraint ck_alert_channels_provider
      check (provider in ('email', 'discord', 'telegram'));
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'ck_alert_channels_min_severity'
  ) then
    alter table alert_channels
      add constraint ck_alert_channels_min_severity
      check (min_severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));
  end if;
end $$;

create index if not exists ix_alert_channels_enabled_provider
  on alert_channels (enabled, provider, min_severity);

insert into schema_migrations (version, description)
values (
  '016_alert_channels',
  'Canais configuraveis de alerta para email, Discord e Telegram'
)
on conflict (version) do nothing;
