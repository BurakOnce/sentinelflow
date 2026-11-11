# Detection tuning

This document records how the first rule set was measured against simulator ground truth, which
weaknesses the measurements exposed and how the rules changed. All numbers come from runs of the
full pipeline (Vector, Redpanda, the Spark normalize and detect jobs, ClickHouse and dbt), read
from `analytics.fct_detection_efficacy`.

## How efficacy is measured

- An alert is a **true positive** when at least one of the events it was raised on is a
  labelled attack line. Alerts and labels are joined on `event_id`, the SHA-256 of the raw line
  (ADR 0003).
- **Recall** is computed per rule over the attacks of the scenarios that rule is designed for
  (`transform/seeds/rule_scenario_map.csv`). An attack is detected when an alert of that rule
  contains one of its lines.
- **Latency** is the time between the first labelled line of an attack and the event that
  completed the rule condition, both in event time.

An earlier version of the matching counted an alert as a true positive when its entity appeared
anywhere in an overlapping attack. That was too lenient: spraying attacks list dozens of target
accounts, so any user alert during a spraying window matched. Line level matching replaced it
before any tuning was done.

## Datasets

Every dataset uses 200 simulated users and all seven attack scenarios. Mixing intensities adds
low and slow variants that sit close to rule thresholds.

| Dataset | Purpose | Command arguments | Lines | Labelled lines | Attacks |
|---|---|---|---|---|---|
| Smoke | first end to end run | `--start 2026-09-29T00:00:00Z --duration 24h --seed 42 --attack all --attack-repeat 3` | 26,954 | 7,058 | 21 |
| Tuning | find weaknesses | `--start 2026-09-26T00:00:00Z --duration 72h --seed 7 --attack all:0.5 --attack all:1 --attack all:2 --attack-repeat 2` | 52,504 | 16,623 | 42 |
| Holdout | check the first changes | `--start 2026-09-20T00:00:00Z --duration 48h --seed 11 --attack all:0.5 --attack all:1 --attack all:2` | 34,815 | 8,361 | 21 |
| Validation | check the final rule set | `--start 2026-09-14T00:00:00Z --duration 48h --seed 23 --attack all:0.5 --attack all:1 --attack all:2` | 46,510 | 8,508 | 21 |

The smoke dataset only uses the default intensity. Every rule scored precision and recall of 1.0
on it, which said more about the dataset than about the rules, so the tuning dataset was built to
be harder.

## Round 1: baseline rules on the tuning dataset

| Rule | Alerts | TP | FP | Detected | FN | Precision | Recall | Latency (s) |
|---|---|---|---|---|---|---|---|---|
| brute_force_success | 6 | 6 | 0 | 6/6 | 0 | 1.000 | 1.000 | 61.5 |
| credential_stuffing | 6 | 6 | 0 | 6/6 | 0 | 1.000 | 1.000 | 95.3 |
| impossible_travel | 11 | 10 | 1 | 6/6 | 0 | 0.909 | 1.000 | 2249.8 |
| password_spraying | 14 | 14 | 0 | 3/6 | 3 | 1.000 | 0.500 | 248.2 |
| port_scan | 6 | 6 | 0 | 6/6 | 0 | 1.000 | 1.000 | 0.3 |
| scanner_user_agent | 6 | 6 | 0 | 6/6 | 0 | 1.000 | 1.000 | 0.0 |
| ssh_bruteforce | 12 | 12 | 0 | 12/12 | 0 | 1.000 | 1.000 | 14.1 |
| web_attack_pattern | 6 | 6 | 0 | 6/6 | 0 | 1.000 | 1.000 | 29.4 |

Two problems stood out.

**Password spraying missed half of the attacks.** The missed attacks spread their attempts over
three to five addresses and tried seven to nine accounts per address, just under the threshold of
ten distinct accounts per address in ten minutes. This is the textbook way to evade a per source
threshold.

**Impossible travel raised one false positive.** A user in Germany switched from a home line that
geolocates to Munich to a mobile line that geolocates to Berlin within 21 minutes. The distance is
about 500 km, so the implied speed exceeded 900 km/h. Both addresses belong to Deutsche Telekom.
The rule already listed carrier geolocation as a known false positive.

## Round 2: lower the spraying threshold, guard it, add a domestic distance

Changes:

1. `password_spraying` counts five distinct accounts instead of ten.
2. To keep a busy shared address such as an office NAT from matching, the rule now looks at all
   password logins of the address, successful or not, and requires at least 80 percent of them to
   have failed.
3. `impossible_travel` gained `min_domestic_distance_km: 1500`. Moves inside one country need to
   cover 1500 km before they count; moves across borders keep the 500 km minimum.

Result on the tuning dataset:

| Rule | Alerts | Detected | Recall | Latency (s) | False positives |
|---|---|---|---|---|---|
| password_spraying | 152 | 6/6 | 1.000 | 112.5 | 0 |
| impossible_travel | 10 | 6/6 | 1.000 | 2249.8 | 0 |

Recall and latency improved, but spraying alerts rose from 14 to 152. All of them were true
positives, and precision stayed at 1.0, so the precision metric alone would have called this a
success. Breaking the alerts down by matched scenario showed that 129 came from credential
stuffing: each of the stuffing proxies tried five or six accounts and now crossed the lower
threshold on its own. Those attacks were already covered by the credential stuffing rule with
one alert each, so the extra 129 alerts were pure analyst load.

## Round 3: separate spraying from stuffing by client behaviour

Stuffing tools rotate the user agent from request to request across their proxy pool. Spraying
tools tend to run as one client. `password_spraying` gained a guard of at most two distinct user
agents per address.

| Rule | Alerts | Detected | Recall | Latency (s) |
|---|---|---|---|---|
| password_spraying | 27 | 6/6 | 1.000 | 112.5 |

Alert volume dropped from 152 to 27 without losing an attack. The remaining alerts are one per
spraying address plus a handful of stuffing proxies that happened to reuse a user agent.

## Holdout: does it generalise?

The rules from round 3 (v2) and the original rules (v1) were run on the holdout dataset, which had
not been looked at before.

| Rule | Version | Alerts | FP | Detected | Precision | Recall | Latency (s) |
|---|---|---|---|---|---|---|---|
| password_spraying | v1 | 5 | 0 | 1/3 | 1.000 | 0.333 | 236.5 |
| password_spraying | v2 | 14 | 0 | 3/3 | 1.000 | 1.000 | 120.2 |
| impossible_travel | v1 | 13 | 6 | 3/3 | 0.538 | 1.000 | 3577.4 |
| impossible_travel | v2 | 9 | 2 | 3/3 | 0.778 | 1.000 | 3577.4 |

The spraying change held up. Impossible travel improved but kept two false positives. Both were
users in the United States moving between a desktop and a phone whose addresses geolocate to New
York and San Francisco, 4100 km apart and inside one country. A domestic distance threshold does
not help in large countries. Both addresses belonged to the same operator (Comcast).

## Round 4: ignore moves within one network operator

`impossible_travel` gained `ignore_same_asn: true`: if both logins come from the same autonomous
system, the move is treated as geolocation noise. The trade-off is explicit in the rule: an
attacker on the same operator as the victim is not reported.

This change was derived from the holdout, so it was checked on the validation dataset instead.
The first run showed no difference at all. The cause was a bug: the rule loader parsed parameter
values as `float | int | str`, so pydantic turned the YAML `true` into `1.0` and the detector,
which compared against the string `"true"`, never enabled the check. The parameter type now
accepts booleans first, and a unit test asserts that the value stays a boolean.

Validation dataset, all rule versions:

| Rule | Version | Alerts | FP | Detected | Precision | Recall | Latency (s) |
|---|---|---|---|---|---|---|---|
| password_spraying | v1 | 10 | 0 | 2/3 | 1.000 | 0.667 | 253.3 |
| password_spraying | v2 | 12 | 0 | 3/3 | 1.000 | 1.000 | 100.5 |
| impossible_travel | v1 | 11 | 4 | 3/3 | 0.636 | 1.000 | 2730.2 |
| impossible_travel | v2 | 9 | 2 | 3/3 | 0.778 | 1.000 | 2730.2 |
| impossible_travel | v3 | 7 | 0 | 3/3 | 1.000 | 1.000 | 2730.2 |

The other six rules had identical results in every version on every dataset:

| Rule | Tuning | Holdout | Validation |
|---|---|---|---|
| brute_force_success | 6/6, 61.5 s | 3/3, 60.4 s | 3/3, 61.6 s |
| credential_stuffing | 6/6, 95.3 s | 3/3, 86.1 s | 3/3, 72.8 s |
| port_scan | 6/6, 0.3 s | 3/3, 0.3 s | 3/3, 0.3 s |
| scanner_user_agent | 6/6, 0.0 s | 3/3, 0.0 s | 3/3, 0.0 s |
| ssh_bruteforce | 12/12, 14.1 s | 6/6, 14.1 s | 6/6, 14.2 s |
| web_attack_pattern | 6/6, 29.4 s | 3/3, 29.0 s | 3/3, 29.5 s |

All of them with precision 1.0.

## Observations

- Impossible travel latency is large by construction: the simulated attacker logs in 10 to 90
  minutes after the victim, and the rule cannot fire before the second login.
- Several impossible travel alerts matched attacks of other scenarios. When a brute force,
  spraying or stuffing attack succeeded, the attacker logged in as the victim from a hostile
  country and the impossible travel detector flagged the account takeover. These count as true
  positives and are a useful overlap between rules.
- Web attack and scanner latencies are close to zero because both are single event rules. The
  nginx timestamp has second resolution, so latencies are floored at zero.

## Limitations

- The simulator produces the attacks the rules were written for. The numbers show that the rules
  work on this traffic, not how they would perform on real logs.
- The simulator has no shared egress addresses. The office NAT guard of the spraying rule is only
  exercised by rule fixtures, not by the datasets.
- No dataset contains an attacker on the victim's own operator, so the recall cost of
  `ignore_same_asn` is not measured.
- Three datasets of two to three days are small. A single false positive moves precision a lot.

## Reproducing a run

```sh
make clean && make up
uv run sentinelflow-sim run --start 2026-09-14T00:00:00Z --duration 48h --seed 23 \
    --attack all:0.5 --attack all:1 --attack all:2
make summary
```

To re-run detection on the same data with changed rules, run `make redetect` and then
`make summary`. It stops `spark-detect`, deletes `checkpoints/detect` in MinIO, truncates
`alerts` and `detector_state` and starts the job again, which reprocesses `events.normalized`
from the beginning. Rules are mounted into the container, so rule changes need no image
rebuild.
