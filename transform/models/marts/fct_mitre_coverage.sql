{{ config(order_by='technique_id') }}

with rule_techniques as (
    select
        rule_name,
        arrayJoin(splitByChar('|', techniques)) as technique_id
    from {{ ref('rule_catalog') }}
    where techniques != ''
),

recent_alerts as (
    select arrayJoin(mitre_techniques) as technique_id, count() as alerts
    from {{ ref('stg_alerts') }}
    where first_seen >= now() - interval 30 day
    group by technique_id
)

select
    techniques.technique_id as technique_id,
    techniques.technique_name as technique_name,
    techniques.tactic as tactic,
    uniqExactIf(rule_techniques.rule_name, rule_techniques.rule_name != '') as rule_count,
    arraySort(groupUniqArrayIf(rule_techniques.rule_name, rule_techniques.rule_name != ''))
        as rules,
    any(coalesce(recent_alerts.alerts, 0)) as alerts_last_30_days,
    rule_count > 0 as is_covered
from {{ ref('mitre_techniques') }} as techniques
left join rule_techniques on rule_techniques.technique_id = techniques.technique_id
left join recent_alerts on recent_alerts.technique_id = techniques.technique_id
group by techniques.technique_id, techniques.technique_name, techniques.tactic
