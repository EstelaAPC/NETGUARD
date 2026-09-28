create table if not exists monitoring_profiles (
  id serial primary key,
  name text not null,
  display_name text,
  kind text not null default 'profile',
  description text,
  config jsonb not null default '{}'::jsonb,
  enabled boolean not null default true
);

alter table monitoring_profiles add column if not exists id bigserial;
alter table monitoring_profiles add column if not exists display_name text;
alter table monitoring_profiles add column if not exists kind text;
update monitoring_profiles
set kind = 'profile'
where kind is null;
alter table monitoring_profiles alter column kind set default 'profile';
alter table monitoring_profiles alter column kind set not null;
alter table monitoring_profiles add column if not exists description text;
alter table monitoring_profiles add column if not exists config jsonb;
update monitoring_profiles
set config = '{}'::jsonb
where config is null;
alter table monitoring_profiles alter column config set default '{}'::jsonb;
alter table monitoring_profiles alter column config set not null;
alter table monitoring_profiles add column if not exists enabled boolean;
update monitoring_profiles
set enabled = true
where enabled is null;
alter table monitoring_profiles alter column enabled set default true;
alter table monitoring_profiles alter column enabled set not null;

create index if not exists ix_monitoring_profiles_enabled_display_name
on monitoring_profiles (enabled, display_name);

create index if not exists ix_monitoring_profiles_name_lower
on monitoring_profiles ((lower(name)));

create table if not exists asset_profiles (
  asset_id int not null references assets(id) on delete cascade,
  profile_id int not null references monitoring_profiles(id) on delete cascade,
  params jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  primary key (asset_id, profile_id)
);

alter table asset_profiles add column if not exists asset_id int;
alter table asset_profiles add column if not exists profile_id int;
alter table asset_profiles add column if not exists params jsonb;
update asset_profiles
set params = '{}'::jsonb
where params is null;
alter table asset_profiles alter column params set default '{}'::jsonb;
alter table asset_profiles alter column params set not null;
alter table asset_profiles add column if not exists enabled boolean;
update asset_profiles
set enabled = true
where enabled is null;
alter table asset_profiles alter column enabled set default true;
alter table asset_profiles alter column enabled set not null;

create index if not exists ix_asset_profiles_asset_enabled
on asset_profiles (asset_id, enabled);

create index if not exists ix_asset_profiles_profile_id
on asset_profiles (profile_id);

create table if not exists discovered_interfaces (
  id bigserial primary key,
  asset_id int not null references assets(id) on delete cascade,
  ifindex int not null,
  ifdescr text not null,
  admin_status int,
  oper_status int,
  selected boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table discovered_interfaces add column if not exists id bigserial;
alter table discovered_interfaces add column if not exists asset_id int;
alter table discovered_interfaces add column if not exists ifindex int;
alter table discovered_interfaces add column if not exists ifdescr text;
alter table discovered_interfaces add column if not exists admin_status int;
alter table discovered_interfaces add column if not exists oper_status int;
alter table discovered_interfaces add column if not exists selected boolean;
update discovered_interfaces
set selected = true
where selected is null;
alter table discovered_interfaces alter column selected set default true;
alter table discovered_interfaces alter column selected set not null;
alter table discovered_interfaces add column if not exists updated_at timestamptz;
update discovered_interfaces
set updated_at = now()
where updated_at is null;
alter table discovered_interfaces alter column updated_at set default now();
alter table discovered_interfaces alter column updated_at set not null;

with ranked as (
  select
    ctid,
    row_number() over (
      partition by asset_id, ifindex
      order by updated_at desc nulls last, id desc
    ) as rn
  from discovered_interfaces
)
delete from discovered_interfaces d
using ranked r
where d.ctid = r.ctid
  and r.rn > 1;

create unique index if not exists ux_discovered_interfaces_id
on discovered_interfaces (id);

create unique index if not exists ux_discovered_interfaces_asset_ifindex
on discovered_interfaces (asset_id, ifindex);

create index if not exists ix_discovered_interfaces_asset_selected_ifindex
on discovered_interfaces (asset_id, selected, ifindex);

insert into monitoring_profiles (name, display_name, kind, description, config, enabled)
select
  'icmp_basic',
  'ICMP Basic',
  'availability',
  'Coleta disponibilidade e latencia basica por ICMP/TCP.',
  '{"metrics":["host.alive","icmp.rtt_ms","icmp.loss_pct"]}'::jsonb,
  true
where not exists (
  select 1
  from monitoring_profiles
  where lower(name) = 'icmp_basic'
);

insert into monitoring_profiles (name, display_name, kind, description, config, enabled)
select
  'generic_if_mib',
  'Generic IF-MIB',
  'snmp',
  'Descobre interfaces e coleta metricas operacionais basicas de IF-MIB.',
  '{"discovery":"interfaces","metrics":["snmp.if.in_octets","snmp.if.out_octets","snmp.if.in_errors","snmp.if.out_errors","snmp.if.in_discards","snmp.if.out_discards","snmp.if.oper_status","snmp.if.admin_status"]}'::jsonb,
  true
where not exists (
  select 1
  from monitoring_profiles
  where lower(name) = 'generic_if_mib'
);

insert into monitoring_profiles (name, display_name, kind, description, config, enabled)
select
  'snmp_system',
  'SNMP System',
  'snmp',
  'Mantem a base de identificacao e parametros do host monitorado por SNMP.',
  '{"section":"system"}'::jsonb,
  true
where not exists (
  select 1
  from monitoring_profiles
  where lower(name) = 'snmp_system'
);

insert into schema_migrations (version, description)
values ('009_profiles_and_discovery', 'Formaliza monitoring_profiles, asset_profiles e discovered_interfaces com seed minimo do lab')
on conflict (version) do nothing;
