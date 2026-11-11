# Risk scoring

Every alert gets a risk score between 0 and 100 when the detect job writes it. The score helps
order the queue; it does not replace the rule level.

## Formula

Each factor is a number between 0 and 1. The score is the weighted mean of the factors, scaled
to 100 and rounded:

```
risk = round(100 * sum(weight_i * factor_i) / sum(weight_i))
```

Normalising by the sum of the weights keeps the score within 0 to 100 whatever weights are
configured.

| Factor | Value | Default weight |
|---|---|---|
| `level` | informational 0, low 0.25, medium 0.5, high 0.75, critical 1 | 40 |
| `threat_intel` | 1 if any provider lists the address as malicious, otherwise the abuse score divided by 100, otherwise 0 | 20 |
| `foreign_country` | 1 if the source country is unusual (see below) | 15 |
| `successful_login` | 1 if the alert contains a successful authentication | 15 |
| `recurrence` | other alerts for the same entity in the previous 24 hours divided by 5, capped at 1 | 10 |

A country is unusual when:

- the alert has a user and that user has at least three successful logins from other countries
  but none from this one, or
- the alert has no user baseline and the country accounts for less than two percent of all
  successful logins in the organisation.

Addresses without a GeoIP match, such as internal ranges, never count as foreign.

## Configuration

Weights, level factors and the recurrence saturation live in `enrichment/risk_weights.yml`:

```yaml
weights:
  level: 40
  threat_intel: 20
  foreign_country: 15
  successful_login: 15
  recurrence: 10
level_factors:
  critical: 1.0
recurrence_saturation: 5
```

The factor values are stored with each alert in `risk_factors`, so a score can be explained
from the alert row alone.

## Examples

| Alert | Factors | Score |
|---|---|---|
| Port scan (medium), unknown address | level 0.5 | 20 |
| Port scan (medium), address on a blocklist | level 0.5, threat intel 1 | 40 |
| Password spraying (high) from a country outside the organisation | level 0.75, foreign 1 | 45 |
| Brute force followed by success (critical), foreign, listed, third alert today | 1, 1, 1, 1, 0.4 | 94 |

The table tests in `tests/test_enrichment.py` pin these values.

## Limitations

- The weights are chosen by hand and not calibrated against analyst verdicts.
- The user baseline comes from the `events` table at scoring time, so a compromised account
  whose attacker logs in many times from the same country slowly makes that country usual.
- Threat intel verdicts depend on the configured feeds. In offline mode only the fixture list is
  available.
