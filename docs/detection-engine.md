# Detection engine

The engine in `detections/engine` loads Sigma rules from `detections/rules`, validates them and
compiles them for two backends: Spark column expressions for the streaming job and a Python
evaluator for tests, fixtures and backtests. Both backends share one intermediate
representation, and parity tests run the same events through both.

This document lists what is supported. Anything not listed is rejected with an error that names
the file, the rule and the problem.

## Rule files

A file can hold several YAML documents separated by `---`. Correlation rules usually live in the
same file as the detection rule they build on.

| Field | Support |
|---|---|
| `title`, `id` (UUID), `status`, `description`, `level` | required |
| `name` | optional, referenced by correlations, defaults to the id |
| `references`, `author`, `date`, `modified`, `fields`, `falsepositives` | optional |
| `tags` | `attack.<tactic>` and `attack.tNNNN[.NNN]`; alerting rules need at least one technique |
| `logsource` | `category` becomes a filter on `event_category`, `service` on `source_type`, `product` is ignored |
| `detection` | see below |
| `correlation` | see below |
| `sentinelflow` | project extension, see below |

Unknown top level keys are rejected.

## Fields

Rules match the normalized event schema defined in `streaming/schema.py`, not vendor field
names. Unknown fields are rejected at load time.

## Detection section

- A selection is a mapping of field to value, or a list of such mappings. Fields in one mapping
  are combined with AND, mappings in a list with OR.
- A list of values is combined with OR, or with AND when the `all` modifier is present.
- `null` matches a missing value.
- Plain values containing `*` or `?` are wildcards.
- Keyword selections (lists of bare strings) are not supported.

| Modifier | Meaning |
|---|---|
| none | case-insensitive equality, numeric equality for numeric fields |
| `contains`, `startswith`, `endswith` | case-insensitive substring tests |
| `re` | regular expression search, case-sensitive, must work in Python and Java |
| `cidr` | address in network, only on address fields |
| `gt`, `gte`, `lt`, `lte` | numeric comparisons, only on numeric fields |
| `all` | combine the value list with AND |

Only one value modifier per field is allowed. `base64`, `windash`, `expand` and field references
are not supported.

Conditions support `and`, `or`, `not`, parentheses, `1 of pattern*`, `all of pattern*`,
`1 of them` and `all of them`. Aggregation pipes (`| count() by ...`) are not supported; use a
correlation rule instead.

## Correlation rules

The subset follows the Sigma correlation specification.

| Key | Support |
|---|---|
| `type` | `event_count`, `value_count`, `temporal`, `temporal_ordered` |
| `rules` | names of detection rules; `temporal` and `temporal_ordered` may also name an `event_count` correlation, whose threshold becomes the minimum count of that step |
| `group-by` | event fields; the first one is the alert entity |
| `timespan` | `Ns`, `Nm`, `Nh`, `Nd` |
| `condition` | `gt`, `gte`, `lt`, `lte`, `eq`; `field` is required for `value_count`; a lower bound is required |
| `generate` | `true` lets referenced rules raise their own alerts |

Rules referenced by a correlation do not raise alerts on their own unless `generate` is true.

Semantics:

- `event_count` counts distinct events in a window.
- `value_count` counts distinct values of `field` in a window.
- `temporal` requires every referenced rule to match at least its minimum count in the window.
- `temporal_ordered` requires the referenced rules to be satisfied in order. Events only count
  towards a step after the previous step was complete.

Windows are sliding and aligned to the epoch. Their length is the timespan and they start every
slide, by default a fifth of the timespan. See ADR 0007.

## Extension: `sentinelflow`

| Key | Applies to | Meaning |
|---|---|---|
| `entity` | detection and detector rules | field used as the alert entity, default `source_ip` for detection rules and `user_name` for detectors |
| `suppression` | all | suppression window, default `ALERT_SUPPRESSION` (30m) |
| `slide` | correlations | window slide, must divide the timespan |
| `having` | correlations | extra conditions that must hold together with the main condition |
| `detector`, `parameters` | detector rules | name and settings of a Python detector |

`having` entries:

```yaml
having:
  - aggregate: value_count      # distinct values of a field
    field: user_name
    gte: 30
  - aggregate: ratio            # share of events where field equals a value
    field: event_outcome
    equals: failure
    gte: 0.8
```

Lower bounds are checked when the alert fires. Upper bounds (`lt`, `lte`) must also hold for the
whole window, which makes them suitable as guards such as "at most two user agents".

## Python detectors

Some logic does not fit field matching or counting. A detector rule keeps its metadata in YAML
and names a function registered with `@register` in `detections/engine/detectors`. The detection
section selects the events the detector receives. Detectors get a state store and a GeoIP
lookup and return hits.

`impossible_travel` compares every successful login of a user with the previous one:

| Parameter | Default | Meaning |
|---|---|---|
| `max_speed_kmh` | 900 | speeds above this are impossible |
| `min_distance_km` | 500 | ignore shorter moves between countries |
| `min_domestic_distance_km` | `min_distance_km` | ignore shorter moves within one country |
| `ignore_same_asn` | false | ignore moves where both addresses belong to the same network operator |

## Alerts and suppression

Every rule produces hits: an entity, the matching event ids, first and last event time and the
time the condition was met. Hits for the same rule and entity that fall within the suppression
window of an open alert extend that alert: event ids are merged as a set, times are widened.
Otherwise a new alert is created. Alert ids are derived from rule, entity and first event time,
so replays produce the same ids. See ADR 0008.

## Testing a rule

- `detections/fixtures/<rule>.yml` holds positive and negative cases as raw log lines. Lines
  can repeat with `repeat` and `every`, and `{ts}` and `{n}` are filled in per line. The lines
  go through the real parser before the rules run.
- `sentinelflow-rules validate` loads all rules, runs every fixture and fails if an alerting
  rule has no positive case.
- `tests/test_detection_rules.py` runs rules against simulated scenarios and a simulated normal
  workday.
- `tests/test_spark_detection.py` checks that the Spark backend produces the same hits and
  alerts as the Python evaluator.
