select
    attack_id,
    any(scenario) as scenario,
    min(window_start) as window_start,
    max(window_end) as window_end,
    groupUniqArray(src_ip) as source_ips,
    arrayFilter(user -> user != '', groupUniqArray(ifNull(user_name, ''))) as user_names,
    groupUniqArray(technique_id) as techniques,
    count() as labelled_events
from {{ ref('stg_ground_truth') }}
group by attack_id
