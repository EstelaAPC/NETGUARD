create table if not exists snmp_interface_samples (
  ts timestamptz not null,
  hostname text not null,
  src_ip inet not null,
  ifindex int not null,
  ifname text,
  in_octets bigint,
  out_octets bigint,
  in_errors bigint,
  out_errors bigint,
  in_discards bigint,
  out_discards bigint,
  oper_status int,
  admin_status int,
  primary key (ts, hostname, ifindex)
);

create index if not exists ix_snmp_if_ts on snmp_interface_samples(ts desc);
create index if not exists ix_snmp_if_host_ts on snmp_interface_samples(hostname, ts desc);

insert into schema_migrations (version, description)
values ('004_snmp', 'Schema legado de amostras SNMP preservado')
on conflict (version) do nothing;
