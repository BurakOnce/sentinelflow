{{ config(order_by='rule_name') }}

with rules as (
    select rule_id, rule_name, rule_title, rule_type, level
    from {{ ref('rule_catalog') }}
),

alert_outcomes as (
    select
        alerts.rule_name as rule_name,
        alerts.alert_id as alert_id,
        countIf(matches.attack_id != '') > 0 as is_true_positive
    from {{ ref('stg_alerts') }} as alerts
    left join {{ ref('int_alert_attack_matches') }} as matches
        on alerts.alert_id = matches.alert_id
    group by rule_name, alert_id
),

alert_counts as (
    select
        rule_name,
        count() as alerts,
        countIf(is_true_positive) as true_positive_alerts,
        countIf(not is_true_positive) as false_positive_alerts
    from alert_outcomes
    group by rule_name
),

expected as (
    select
        mapping.rule_name as rule_name,
        attacks.attack_id as attack_id,
        attacks.window_start as window_start
    from {{ ref('rule_scenario_map') }} as mapping
    inner join {{ ref('int_attacks') }} as attacks
        on attacks.scenario = mapping.scenario
),

detected as (
    select
        expected.rule_name as rule_name,
        expected.attack_id as attack_id,
        min(matches.latency_seconds) as latency_seconds
    from expected
    inner join {{ ref('int_alert_attack_matches') }} as matches
        on matches.attack_id = expected.attack_id
       and matches.rule_name = expected.rule_name
    group by rule_name, attack_id
),

attack_counts as (
    select
        expected.rule_name as rule_name,
        uniqExact(expected.attack_id) as expected_attacks,
        uniqExactIf(expected.attack_id, detected.attack_id != '') as detected_attacks,
        avgIf(detected.latency_seconds, detected.attack_id != '') as avg_latency_seconds
    from expected
    left join detected
        on detected.attack_id = expected.attack_id
       and detected.rule_name = expected.rule_name
    group by rule_name
)

select
    rules.rule_id as rule_id,
    rules.rule_name as rule_name,
    rules.rule_title as rule_title,
    rules.rule_type as rule_type,
    rules.level as level,
    coalesce(alert_counts.alerts, 0) as alerts,
    coalesce(alert_counts.true_positive_alerts, 0) as true_positives,
    coalesce(alert_counts.false_positive_alerts, 0) as false_positives,
    coalesce(attack_counts.expected_attacks, 0) as expected_attacks,
    coalesce(attack_counts.detected_attacks, 0) as detected_attacks,
    coalesce(attack_counts.expected_attacks, 0) - coalesce(attack_counts.detected_attacks, 0)
        as false_negatives,
    if(
        coalesce(alert_counts.alerts, 0) = 0,
        null,
        alert_counts.true_positive_alerts / alert_counts.alerts
    ) as precision,
    if(
        coalesce(attack_counts.expected_attacks, 0) = 0,
        null,
        attack_counts.detected_attacks / attack_counts.expected_attacks
    ) as recall,
    if(isNaN(attack_counts.avg_latency_seconds), null, attack_counts.avg_latency_seconds)
        as avg_detection_latency_seconds,
    now() as computed_at
from rules
left join alert_counts on alert_counts.rule_name = rules.rule_name
left join attack_counts on attack_counts.rule_name = rules.rule_name
