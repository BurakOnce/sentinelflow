{{ config(order_by='user_name') }}

with user_alerts as (
    select
        coalesce(if(entity_type = 'user', entity, null), user_name) as user_name,
        count() as alerts,
        countIf(rule_name = 'impossible_travel') as impossible_travel_alerts,
        countIf(rule_name = 'brute_force_success') as compromised_login_alerts,
        max(risk_score) as max_risk_score,
        arraySort(groupUniqArray(rule_name)) as triggered_rules,
        max(last_seen) as last_alert_at
    from {{ ref('stg_alerts') }}
    where coalesce(if(entity_type = 'user', entity, null), user_name) is not null
    group by user_name
),

failures as (
    select user_name, count() as failed_logins, uniqExact(source_ip) as failed_login_sources
    from {{ ref('stg_events') }}
    where event_category = 'authentication'
      and event_outcome = 'failure'
      and event_action in ('ssh_login', 'app_login')
      and user_name is not null
    group by user_name
)

select
    assumeNotNull(baseline.user_name) as user_name,
    baseline.successful_logins as successful_logins,
    baseline.usual_country as usual_country,
    length(baseline.countries) as login_countries,
    baseline.typical_first_hour as typical_first_hour,
    baseline.typical_last_hour as typical_last_hour,
    baseline.distinct_devices as distinct_devices,
    coalesce(failures.failed_logins, 0) as failed_logins,
    coalesce(failures.failed_login_sources, 0) as failed_login_sources,
    coalesce(user_alerts.alerts, 0) as alerts,
    coalesce(user_alerts.impossible_travel_alerts, 0) as impossible_travel_alerts,
    coalesce(user_alerts.compromised_login_alerts, 0) as compromised_login_alerts,
    coalesce(user_alerts.max_risk_score, 0) as max_risk_score,
    user_alerts.triggered_rules as triggered_rules,
    least(
        100,
        coalesce(user_alerts.max_risk_score, 0)
        + 10 * least(length(baseline.countries) - 1, 3)
        + least(coalesce(failures.failed_logins, 0), 20)
    ) as risk_indicator
from {{ ref('int_user_login_baseline') }} as baseline
left join failures on failures.user_name = baseline.user_name
left join user_alerts on user_alerts.user_name = baseline.user_name
