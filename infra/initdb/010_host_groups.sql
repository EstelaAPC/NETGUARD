create table if not exists host_groups (
  id bigserial primary key,
  name text not null,
  slug text not null,
  parent_id bigint,
  path text not null,
  tags jsonb not null default '{}'::jsonb,
  enabled boolean not null default true
);

alter table host_groups add column if not exists id bigserial;
alter table host_groups add column if not exists name text;
alter table host_groups add column if not exists slug text;
update host_groups
set slug = lower(regexp_replace(coalesce(name, 'group'), '[^a-zA-Z0-9]+', '-', 'g'))
where slug is null or btrim(slug) = '';
update host_groups
set slug = trim(both '-' from slug)
where slug is not null;
update host_groups
set slug = 'group'
where slug is null or slug = '';
alter table host_groups alter column slug set not null;
alter table host_groups add column if not exists parent_id bigint;
alter table host_groups add column if not exists path text;
update host_groups
set path = slug
where path is null or btrim(path) = '';
alter table host_groups alter column path set not null;
alter table host_groups add column if not exists tags jsonb;
update host_groups
set tags = '{}'::jsonb
where tags is null;
alter table host_groups alter column tags set default '{}'::jsonb;
alter table host_groups alter column tags set not null;
alter table host_groups add column if not exists enabled boolean;
update host_groups
set enabled = true
where enabled is null;
alter table host_groups alter column enabled set default true;
alter table host_groups alter column enabled set not null;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'fk_host_groups_parent_id'
  ) then
    alter table host_groups
      add constraint fk_host_groups_parent_id
      foreign key (parent_id) references host_groups(id) on delete set null;
  end if;
end $$;

create unique index if not exists ux_host_groups_path_lower
on host_groups ((lower(path)));

create index if not exists ix_host_groups_parent_name
on host_groups (parent_id, name);

alter table assets add column if not exists group_id bigint;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'fk_assets_group_id'
  ) then
    alter table assets
      add constraint fk_assets_group_id
      foreign key (group_id) references host_groups(id) on delete set null;
  end if;
end $$;

create index if not exists ix_assets_group_id
on assets (group_id);

insert into host_groups (name, slug, parent_id, path, tags, enabled)
select
  'Lab',
  'lab',
  null,
  'lab',
  '{"system": true, "lab": true}'::jsonb,
  true
where not exists (
  select 1
  from host_groups
  where lower(path) = 'lab'
     or lower(name) = 'lab'
);

with lab_group as (
  select id
  from host_groups
  where lower(path) = 'lab'
     or lower(name) = 'lab'
  order by id
  limit 1
)
update assets a
set group_id = lab_group.id
from lab_group
where a.group_id is null
  and (
    lower(a.name) = 'lab-linux-01'
    or a.ip::text = '172.30.10.10'
    or coalesce(a.tags, '{}'::jsonb) @> '{"lab_host": true}'::jsonb
    or coalesce(a.tags, '{}'::jsonb) @> '{"demo_primary": true}'::jsonb
  );

insert into schema_migrations (version, description)
values ('010_host_groups', 'Introduz host_groups MVP, group_id opcional em assets e seed/backfill conservador do grupo Lab')
on conflict (version) do nothing;
