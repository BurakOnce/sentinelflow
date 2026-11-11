with logins as (
    select
        user_name,
        event_time,
        toHour(event_time) as login_hour,
        user_agent,
        dictGetOrDefault('{{ source_database() }}.geoip_city', 'country_code', toIPv4(source_ip), '') as country_code
    from {{ ref('stg_events') }}
    where event_category = 'authentication'
      and event_outcome = 'success'
      and event_action in ('ssh_login', 'app_login')
      and user_name is not null
      and source_ip is not null
      and not isIPAddressInRange(source_ip, '10.0.0.0/8')
)

select
    user_name,
    count() as successful_logins,
    topKIf(1)(country_code, country_code != '')[1] as usual_country,
    groupUniqArrayIf(country_code, country_code != '') as countries,
    quantileExact(0.1)(login_hour) as typical_first_hour,
    quantileExact(0.9)(login_hour) as typical_last_hour,
    uniqExact(user_agent) as distinct_devices,
    topK(1)(user_agent)[1] as usual_user_agent,
    min(event_time) as first_login,
    max(event_time) as last_login
from logins
group by user_name
