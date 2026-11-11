# 4. Parse logs with native Spark expressions built from one format spec

Date: 2026-09-30

## Status

Accepted

## Context

Four log formats have to be turned into the common event schema: nginx combined, sshd syslog,
iptables kernel lines and JSON from the portal. The parsers must be easy to test without Spark,
and the streaming job must keep up with bursts such as a port scan that produces a thousand
lines in a few seconds.

Three options were considered:

1. Plain Python parsers wrapped in a row level Python UDF.
2. The same Python parsers applied with a vectorised `mapInPandas` or `mapInArrow`.
3. Native Spark expressions (`regexp_extract`, `rlike`, `try_to_timestamp`, `get_json_object`).

Row level Python UDFs move every row between the JVM and a Python worker. Arrow based
functions batch that transfer but still pay for serialisation and run the regular expressions
in Python. Native expressions stay inside the JVM, take part in whole stage code generation and
let the optimiser drop unused columns.

The drawback of native expressions is duplication: the Python parser used in tests and the
Spark parser could drift apart.

## Decision

Each format is described once in `streaming/parsing/formats.py` as data: regular expressions
with named groups, constant fields, captured fields, lookups and the timestamp format in both
Python and Spark notation. Two small interpreters read that description:

- `python_parser.py` evaluates it with `re` and `datetime.strptime`. It is used by unit tests,
  by rule fixtures and by the detection test suite.
- `spark_parser.py` compiles it into a single `select` of native column expressions. Named
  groups are stripped for Spark and referenced by their numeric index, which is the same in
  Python and Java regular expressions.

Parse failures are reported the same way in both: `unrecognized_format`, `invalid_timestamp`,
`invalid_json`, `missing_field`, `invalid_field` or `number_out_of_range`. A parity test runs a
simulated hour of traffic plus deliberately broken lines through both interpreters and requires
identical output.

## Consequences

- Parsing runs at native speed and the streaming job needs no Python workers for it.
- Adding a log format is a matter of adding a spec; both interpreters pick it up.
- Only features that exist in both regular expression engines may be used in patterns:
  no look-behind, no possessive quantifiers, no Python-only syntax.
- `CASE WHEN` chains evaluate one `rlike` per pattern before extracting groups. With five
  sshd patterns this is cheap, but formats with dozens of variants would call for a different
  design.
