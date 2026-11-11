with alert_events as (
    select alert_id, rule_id, rule_name, detected_at, arrayJoin(event_ids) as event_id
    from {{ ref('stg_alerts') }}
),

labelled as (
    select distinct attack_id, event_id
    from {{ ref('stg_ground_truth') }}
)

select
    alert_events.alert_id as alert_id,
    any(alert_events.rule_id) as rule_id,
    any(alert_events.rule_name) as rule_name,
    any(alert_events.detected_at) as detected_at,
    labelled.attack_id as attack_id,
    any(attacks.scenario) as scenario,
    any(attacks.window_start) as window_start,
    count() as labelled_events,
    greatest(dateDiff('millisecond', window_start, detected_at) / 1000.0, 0) as latency_seconds
from alert_events
inner join labelled on labelled.event_id = alert_events.event_id
inner join {{ ref('int_attacks') }} as attacks on attacks.attack_id = labelled.attack_id
group by alert_id, attack_id
