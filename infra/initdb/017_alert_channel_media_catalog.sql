do $$
begin
  if exists (
    select 1
    from pg_constraint
    where conname = 'ck_alert_channels_provider'
  ) then
    alter table alert_channels
      drop constraint ck_alert_channels_provider;
  end if;

  alter table alert_channels
    add constraint ck_alert_channels_provider
    check (
      provider in (
        'email',
        'discord',
        'telegram',
        'slack',
        'msteams',
        'google_chat',
        'mattermost',
        'rocketchat',
        'pushover',
        'webhook'
      )
    );
end $$;

insert into schema_migrations (version, description)
values (
  '017_alert_channel_media_catalog',
  'Expande canais de alerta para Slack, MS Teams, Google Chat, Mattermost, Rocket.Chat, Pushover e webhook generico'
)
on conflict (version) do nothing;
