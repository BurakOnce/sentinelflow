select
    source_ip,
    event_date,
    count() as attempts,
    countIf(event_outcome = 'failure') as failures,
    countIf(event_outcome = 'success') as successes,
    uniqExact(user_name) as distinct_users,
    groupUniqArray(event_action) as actions,
    min(event_time) as first_attempt,
    max(event_time) as last_attempt,
    failures / attempts as failure_ratio
from {{ ref('stg_events') }}
where event_category = 'authentication'
  and event_action in ('ssh_login', 'app_login')
  and source_ip is not null
group by source_ip, event_date
