# 8. Evaluate thresholds and suppress alerts on the Spark driver

Date: 2026-09-30

## Status

Accepted

## Context

Spark does the heavy work of filtering events and maintaining correlation windows. Three steps
remain after that:

1. Deciding whether a window satisfies its rule, including conditions Spark SQL expresses
   poorly: ordered sequences, distinct counts combined with ratios, and the time at which a
   threshold was crossed.
2. Running stateful Python detectors such as impossible travel, which need a GeoIP lookup.
3. Merging hits into alerts with a suppression window per rule and entity.

Doing these inside Spark would mean a second stateful operator after the aggregation. Spark
only allows chained stateful operators in append mode, which would delay every alert until its
window closed.

## Decision

The three detection queries end in `foreachBatch`. The driver collects the matched events or
aggregated windows of the batch and:

- evaluates windows with `evaluate_window`, the same function the Python reference evaluator
  and the rule tests use;
- runs detector plugins with a state store backed by the `detector_state` table;
- applies hits to an `AlertManager` that merges hits for the same rule and entity whose times
  are within the suppression window, and keeps alert state in memory with the `alerts` table
  as its durable copy.

On startup the manager reloads alerts from ClickHouse and the detector state from
`detector_state`.

## Consequences

- One implementation of the threshold logic is shared by tests, fixtures and the streaming job,
  and a Spark parity test checks the compiled filters and window assignment.
- Suppression is based on event time, so a backfill yields the same alerts as live traffic.
- The driver sees every matched event of a batch. This is fine for the event rates of this
  project (thousands of matches per batch) but would have to move into a stateful operator
  such as `transformWithStateInPandas` for much larger volumes.
- The three query threads share the alert manager, which is guarded by a lock. Rules belong to
  exactly one query type, so no two threads update the same alert.
