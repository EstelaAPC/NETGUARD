\set ON_ERROR_STOP on

with target as (
  select id, name, ip
  from assets
  where lower(name) = lower(:'demo_host_name')
     or ip::text = :'demo_host_ip'
  order by case when lower(name) = lower(:'demo_host_name') then 0 else 1 end, id
  limit 1
)
delete from anomaly_scores
where asset_id in (select id from target)
  and metric = 'loop_risk';

with target as (
  select name, ip
  from assets
  where lower(name) = lower(:'demo_host_name')
     or ip::text = :'demo_host_ip'
  order by case when lower(name) = lower(:'demo_host_name') then 0 else 1 end, id
  limit 1
)
delete from incidents
where incident_type = 'loop_risk'
  and (
    src_ip::text in (select ip::text from target)
    or lower(hostname) in (select lower(name) from target)
  );
