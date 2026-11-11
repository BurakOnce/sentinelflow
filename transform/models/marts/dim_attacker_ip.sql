{{ config(order_by='ip') }}

with alert_summary as (
    select
        entity as ip,
        min(first_seen) as first_seen,
        max(last_seen) as last_seen,
        count() as alerts,
        arraySort(groupUniqArray(rule_name)) as triggered_rules,
        arraySort(groupUniqArray(arrayJoin(mitre_techniques))) as techniques,
        max(risk_score) as max_risk_score,
        max(is_known_malicious) as is_known_malicious,
        max(abuse_score) as abuse_score,
        sum(event_count) as alert_events
    from {{ ref('stg_alerts') }}
    where entity_type = 'ip'
    group by ip
),

auth as (
    select
        source_ip as ip,
        sum(attempts) as login_attempts,
        sum(failures) as failed_logins,
        max(distinct_users) as max_daily_distinct_users
    from {{ ref('int_auth_attempts_by_ip') }}
    group by ip
)

select
    alert_summary.ip as ip,
    alert_summary.first_seen as first_seen,
    alert_summary.last_seen as last_seen,
    alert_summary.alerts as alerts,
    alert_summary.triggered_rules as triggered_rules,
    alert_summary.techniques as techniques,
    alert_summary.max_risk_score as max_risk_score,
    alert_summary.is_known_malicious as is_known_malicious,
    alert_summary.abuse_score as abuse_score,
    alert_summary.alert_events as alert_events,
    coalesce(auth.login_attempts, 0) as login_attempts,
    coalesce(auth.failed_logins, 0) as failed_logins,
    coalesce(auth.max_daily_distinct_users, 0) as max_daily_distinct_users,
    dictGetOrDefault('{{ source_database() }}.geoip_city', 'country_code', toIPv4(alert_summary.ip), '') as country_code,
    dictGetOrDefault('{{ source_database() }}.geoip_city', 'country', toIPv4(alert_summary.ip), '') as country,
    dictGetOrDefault('{{ source_database() }}.geoip_city', 'city', toIPv4(alert_summary.ip), '') as city,
    dictGetOrDefault('{{ source_database() }}.geoip_city', 'latitude', toIPv4(alert_summary.ip), toFloat64(0)) as latitude,
    dictGetOrDefault('{{ source_database() }}.geoip_city', 'longitude', toIPv4(alert_summary.ip), toFloat64(0)) as longitude,
    dictGetOrDefault('{{ source_database() }}.geoip_asn', 'asn', toIPv4(alert_summary.ip), toUInt32(0)) as asn,
    dictGetOrDefault('{{ source_database() }}.geoip_asn', 'as_org', toIPv4(alert_summary.ip), '') as as_org
from alert_summary
left join auth on auth.ip = alert_summary.ip
