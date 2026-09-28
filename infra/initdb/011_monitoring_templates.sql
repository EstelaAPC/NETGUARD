create table if not exists monitoring_templates (
  id bigserial primary key,
  name text not null,
  slug text not null,
  asset_type text not null default 'generic',
  vendor text,
  family text,
  summary text,
  definition jsonb not null default '{}'::jsonb,
  preview jsonb not null default '{}'::jsonb,
  enabled boolean not null default true
);

alter table monitoring_templates add column if not exists id bigserial;
alter table monitoring_templates add column if not exists name text;
alter table monitoring_templates add column if not exists slug text;
alter table monitoring_templates add column if not exists asset_type text;
update monitoring_templates
set asset_type = 'generic'
where asset_type is null or btrim(asset_type) = '';
alter table monitoring_templates alter column asset_type set default 'generic';
alter table monitoring_templates alter column asset_type set not null;
alter table monitoring_templates add column if not exists vendor text;
alter table monitoring_templates add column if not exists family text;
alter table monitoring_templates add column if not exists summary text;
alter table monitoring_templates add column if not exists definition jsonb;
update monitoring_templates
set definition = '{}'::jsonb
where definition is null;
alter table monitoring_templates alter column definition set default '{}'::jsonb;
alter table monitoring_templates alter column definition set not null;
alter table monitoring_templates add column if not exists preview jsonb;
update monitoring_templates
set preview = '{}'::jsonb
where preview is null;
alter table monitoring_templates alter column preview set default '{}'::jsonb;
alter table monitoring_templates alter column preview set not null;
alter table monitoring_templates add column if not exists enabled boolean;
update monitoring_templates
set enabled = true
where enabled is null;
alter table monitoring_templates alter column enabled set default true;
alter table monitoring_templates alter column enabled set not null;

create unique index if not exists ux_monitoring_templates_slug
on monitoring_templates (slug);

create unique index if not exists ux_monitoring_templates_name
on monitoring_templates (name);

create index if not exists ix_monitoring_templates_enabled_asset_type
on monitoring_templates (enabled, asset_type);

create table if not exists template_profiles (
  template_id bigint not null references monitoring_templates(id) on delete cascade,
  profile_id int not null references monitoring_profiles(id) on delete cascade,
  params jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  sort_order int not null default 0,
  primary key (template_id, profile_id)
);

alter table template_profiles add column if not exists template_id bigint;
alter table template_profiles add column if not exists profile_id int;
alter table template_profiles add column if not exists params jsonb;
update template_profiles
set params = '{}'::jsonb
where params is null;
alter table template_profiles alter column params set default '{}'::jsonb;
alter table template_profiles alter column params set not null;
alter table template_profiles add column if not exists enabled boolean;
update template_profiles
set enabled = true
where enabled is null;
alter table template_profiles alter column enabled set default true;
alter table template_profiles alter column enabled set not null;
alter table template_profiles add column if not exists sort_order int;
update template_profiles
set sort_order = 0
where sort_order is null;
alter table template_profiles alter column sort_order set default 0;
alter table template_profiles alter column sort_order set not null;

create index if not exists ix_template_profiles_template_enabled
on template_profiles (template_id, enabled, sort_order);

create index if not exists ix_template_profiles_profile
on template_profiles (profile_id);

alter table assets add column if not exists template_id bigint;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'fk_assets_template_id'
  ) then
    alter table assets
      add constraint fk_assets_template_id
      foreign key (template_id) references monitoring_templates(id) on delete set null;
  end if;
end $$;

create index if not exists ix_assets_template_id
on assets (template_id);

insert into monitoring_templates (name, slug, asset_type, vendor, family, summary, definition, preview, enabled)
values (
  'Linux Basic',
  'linux-basic',
  'server',
  'Generic',
  'Linux',
  'Template base para servidores Linux com disponibilidade, identificação SNMP e leitura operacional simples.',
  '{
    "capabilities": {
      "icmp": true,
      "snmp": true,
      "discovery": false,
      "syslog": true,
      "correlation": false,
      "loop_risk": false
    }
  }'::jsonb,
  '{
    "summary": "Disponibilidade ICMP, informações básicas por SNMP e contexto para syslog operacional.",
    "monitors": ["Disponibilidade do host", "RTT e perda ICMP", "Identificação SNMP do sistema"],
    "signals": ["host.alive", "icmp.rtt_ms", "icmp.loss_pct", "snmp_system"],
    "discovery": [],
    "syslog": ["Eventos do host e serviços"],
    "correlation": ["Sem correlação especializada nesta fase"]
  }'::jsonb,
  true
)
on conflict (slug) do update
set
  name = excluded.name,
  asset_type = excluded.asset_type,
  vendor = excluded.vendor,
  family = excluded.family,
  summary = excluded.summary,
  definition = excluded.definition,
  preview = excluded.preview,
  enabled = excluded.enabled;

insert into monitoring_templates (name, slug, asset_type, vendor, family, summary, definition, preview, enabled)
values (
  'Generic SNMP Switch',
  'generic-snmp-switch',
  'switch',
  'Generic',
  'SNMP',
  'Template base para switches SNMP com interfaces, disponibilidade e suporte a correlação operacional.',
  '{
    "capabilities": {
      "icmp": true,
      "snmp": true,
      "discovery": true,
      "syslog": true,
      "correlation": true,
      "loop_risk": true
    }
  }'::jsonb,
  '{
    "summary": "Disponibilidade ICMP, descoberta de interfaces, métricas IF-MIB, syslog e preparação para loop_risk.",
    "monitors": ["Disponibilidade do host", "Tráfego e erros por interface", "Status administrativo e operacional"],
    "signals": ["host.alive", "icmp.rtt_ms", "icmp.loss_pct", "snmp.if.*"],
    "discovery": ["Descoberta de interfaces IF-MIB"],
    "syslog": ["Eventos de camada 2, flapping e storm control"],
    "correlation": ["Correlaciona syslog, anomalias e loop_risk"]
  }'::jsonb,
  true
)
on conflict (slug) do update
set
  name = excluded.name,
  asset_type = excluded.asset_type,
  vendor = excluded.vendor,
  family = excluded.family,
  summary = excluded.summary,
  definition = excluded.definition,
  preview = excluded.preview,
  enabled = excluded.enabled;

insert into monitoring_templates (name, slug, asset_type, vendor, family, summary, definition, preview, enabled)
values (
  'NetGuard Lab Device',
  'netguard-lab-device',
  'lab-device',
  'NetGuard',
  'Lab',
  'Template do laboratório controlado do NetGuard, alinhado ao fluxo do lab-linux-01 e à demonstração de loop_risk.',
  '{
    "capabilities": {
      "icmp": true,
      "snmp": true,
      "discovery": true,
      "syslog": true,
      "correlation": true,
      "loop_risk": true
    }
  }'::jsonb,
  '{
    "summary": "Template principal do laboratório: disponibilidade, SNMP, discovery de interfaces, syslog e correlação temporal.",
    "monitors": ["Disponibilidade do host", "Métricas de interface", "Contexto SNMP do sistema", "Incidentes e previsões"],
    "signals": ["host.alive", "icmp.rtt_ms", "icmp.loss_pct", "snmp.if.*", "loop_risk"],
    "discovery": ["Descoberta e seleção de interfaces do host de laboratório"],
    "syslog": ["Eventos precursores e sinais operacionais do laboratório"],
    "correlation": ["loop_risk, anomalias e incidentes do cenário controlado"]
  }'::jsonb,
  true
)
on conflict (slug) do update
set
  name = excluded.name,
  asset_type = excluded.asset_type,
  vendor = excluded.vendor,
  family = excluded.family,
  summary = excluded.summary,
  definition = excluded.definition,
  preview = excluded.preview,
  enabled = excluded.enabled;

insert into monitoring_templates (name, slug, asset_type, vendor, family, summary, definition, preview, enabled)
values
(
  'Aruba AOS-CX Basic',
  'aruba-aos-cx-basic',
  'switch',
  'Aruba',
  'AOS-CX',
  'Placeholder preparado para uma futura variação de template focada em switches Aruba AOS-CX.',
  '{"capabilities":{"icmp":true,"snmp":true,"discovery":true,"syslog":true,"correlation":true,"loop_risk":true}}'::jsonb,
  '{"summary":"Planejado para a próxima fase.","monitors":["Disponibilidade","Interfaces","Syslog"],"signals":[],"discovery":["Descoberta de interfaces"],"syslog":["Eventos de switching"],"correlation":["loop_risk e anomalias"]}'::jsonb,
  false
),
(
  'Cisco IOS Basic',
  'cisco-ios-basic',
  'switch',
  'Cisco',
  'IOS',
  'Placeholder preparado para uma futura variação de template focada em Cisco IOS.',
  '{"capabilities":{"icmp":true,"snmp":true,"discovery":true,"syslog":true,"correlation":true,"loop_risk":true}}'::jsonb,
  '{"summary":"Planejado para a próxima fase.","monitors":["Disponibilidade","Interfaces","Syslog"],"signals":[],"discovery":["Descoberta de interfaces"],"syslog":["Eventos de switching"],"correlation":["loop_risk e anomalias"]}'::jsonb,
  false
),
(
  'Dell OS10 Basic',
  'dell-os10-basic',
  'switch',
  'Dell',
  'OS10',
  'Placeholder preparado para uma futura variação de template focada em Dell OS10.',
  '{"capabilities":{"icmp":true,"snmp":true,"discovery":true,"syslog":true,"correlation":true,"loop_risk":true}}'::jsonb,
  '{"summary":"Planejado para a próxima fase.","monitors":["Disponibilidade","Interfaces","Syslog"],"signals":[],"discovery":["Descoberta de interfaces"],"syslog":["Eventos de switching"],"correlation":["loop_risk e anomalias"]}'::jsonb,
  false
),
(
  'HPE/ProCurve Basic',
  'hpe-procurve-basic',
  'switch',
  'HPE',
  'ProCurve',
  'Placeholder preparado para uma futura variação de template focada em HPE/ProCurve.',
  '{"capabilities":{"icmp":true,"snmp":true,"discovery":true,"syslog":true,"correlation":true,"loop_risk":true}}'::jsonb,
  '{"summary":"Planejado para a próxima fase.","monitors":["Disponibilidade","Interfaces","Syslog"],"signals":[],"discovery":["Descoberta de interfaces"],"syslog":["Eventos de switching"],"correlation":["loop_risk e anomalias"]}'::jsonb,
  false
)
on conflict (slug) do update
set
  name = excluded.name,
  asset_type = excluded.asset_type,
  vendor = excluded.vendor,
  family = excluded.family,
  summary = excluded.summary,
  definition = excluded.definition,
  preview = excluded.preview,
  enabled = excluded.enabled;

insert into template_profiles (template_id, profile_id, params, enabled, sort_order)
select t.id, p.id, '{}'::jsonb, true, 10
from monitoring_templates t
join monitoring_profiles p on lower(p.name) = 'icmp_basic'
where t.slug = 'linux-basic'
on conflict (template_id, profile_id) do update
set params = excluded.params, enabled = excluded.enabled, sort_order = excluded.sort_order;

insert into template_profiles (template_id, profile_id, params, enabled, sort_order)
select t.id, p.id, '{}'::jsonb, true, 20
from monitoring_templates t
join monitoring_profiles p on lower(p.name) = 'snmp_system'
where t.slug = 'linux-basic'
on conflict (template_id, profile_id) do update
set params = excluded.params, enabled = excluded.enabled, sort_order = excluded.sort_order;

insert into template_profiles (template_id, profile_id, params, enabled, sort_order)
select t.id, p.id, '{}'::jsonb, true, 10
from monitoring_templates t
join monitoring_profiles p on lower(p.name) = 'icmp_basic'
where t.slug in ('generic-snmp-switch', 'netguard-lab-device')
on conflict (template_id, profile_id) do update
set params = excluded.params, enabled = excluded.enabled, sort_order = excluded.sort_order;

insert into template_profiles (template_id, profile_id, params, enabled, sort_order)
select t.id, p.id, '{}'::jsonb, true, 20
from monitoring_templates t
join monitoring_profiles p on lower(p.name) = 'generic_if_mib'
where t.slug in ('generic-snmp-switch', 'netguard-lab-device')
on conflict (template_id, profile_id) do update
set params = excluded.params, enabled = excluded.enabled, sort_order = excluded.sort_order;

insert into template_profiles (template_id, profile_id, params, enabled, sort_order)
select t.id, p.id, '{}'::jsonb, true, 30
from monitoring_templates t
join monitoring_profiles p on lower(p.name) = 'snmp_system'
where t.slug in ('generic-snmp-switch', 'netguard-lab-device')
on conflict (template_id, profile_id) do update
set params = excluded.params, enabled = excluded.enabled, sort_order = excluded.sort_order;

with lab_template as (
  select id
  from monitoring_templates
  where slug = 'netguard-lab-device'
  limit 1
)
update assets a
set template_id = lab_template.id
from lab_template
where a.template_id is null
  and (
    lower(a.name) = 'lab-linux-01'
    or a.ip::text = '172.30.10.10'
    or coalesce(a.tags, '{}'::jsonb) @> '{"lab_host": true}'::jsonb
    or coalesce(a.tags, '{}'::jsonb) @> '{"demo_primary": true}'::jsonb
  );

insert into schema_migrations (version, description)
values ('011_monitoring_templates', 'Introduz monitoring_templates MVP, template_profiles e template_id em assets com seed inicial do catalogo')
on conflict (version) do nothing;
