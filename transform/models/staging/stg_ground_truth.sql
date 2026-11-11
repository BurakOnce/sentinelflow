select
    attack_id,
    scenario,
    technique_id,
    stage,
    source as source_type,
    event_time,
    window_start,
    window_end,
    src_ip,
    user as user_name,
    line_sha256 as event_id
from {{ source('sentinelflow', 'ground_truth') }} final
