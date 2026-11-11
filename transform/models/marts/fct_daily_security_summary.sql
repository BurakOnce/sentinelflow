{{ config(order_by='summary_date') }}

with events as (
    select
        event_date as summary_date,
        count() as events,
        countIf(source_type = 'nginx') as web_events,
        countIf(source_type = 'ssh') as ssh_events,
        countIf(source_type = 'firewall') as firewall_events,
        countIf(source_type = 'app') as app_events,
        countIf(event_category = 'authentication' and event_outcome = 'failure'
            and event_action in ('ssh_login', 'app_login')) as failed_logins,
        countIf(event_action = 'firewall_drop') as dropped_connections
    from {{ ref('stg_events') }}
    group by summary_date
),

alerts as (
    select
        alert_date as summary_date,
        count() as alerts,
        countIf(level = 'low') as low_alerts,
        countIf(level = 'medium') as medium_alerts,
        countIf(level = 'high') as high_alerts,
        countIf(level = 'critical') as critical_alerts,
        uniqExactIf(entity, entity_type = 'ip') as unique_attacker_ips,
        avg(risk_score) as avg_risk_score
    from {{ ref('stg_alerts') }}
    group by summary_date
)

select
    assumeNotNull(coalesce(events.summary_date, alerts.summary_date)) as summary_date,
    coalesce(events.events, 0) as events,
    coalesce(events.web_events, 0) as web_events,
    coalesce(events.ssh_events, 0) as ssh_events,
    coalesce(events.firewall_events, 0) as firewall_events,
    coalesce(events.app_events, 0) as app_events,
    coalesce(events.failed_logins, 0) as failed_logins,
    coalesce(events.dropped_connections, 0) as dropped_connections,
    coalesce(alerts.alerts, 0) as alerts,
    coalesce(alerts.low_alerts, 0) as low_alerts,
    coalesce(alerts.medium_alerts, 0) as medium_alerts,
    coalesce(alerts.high_alerts, 0) as high_alerts,
    coalesce(alerts.critical_alerts, 0) as critical_alerts,
    coalesce(alerts.unique_attacker_ips, 0) as unique_attacker_ips,
    alerts.avg_risk_score as avg_risk_score
from events
full outer join alerts on alerts.summary_date = events.summary_date
settings join_use_nulls = 1
