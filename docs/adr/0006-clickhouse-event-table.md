# 6. Layout of the ClickHouse events table

Date: 2026-09-30

## Status

Accepted

## Context

The `events` table receives every normalized log line. It is queried by the dashboards (time
ranges, one source type or one address), by the alert enrichment (successful logins of a
user) and by dbt. Duplicates can reach the table as described in ADR 0005. Old data has to be
removed automatically.

## Decision

```sql
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_type, event_action, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS non_replicated_deduplication_window = 1000, ttl_only_drop_parts = 1
```

- **Sorting key.** Most queries filter on the source and the action (failed ssh logins,
  firewall drops) and then on time. Putting the low cardinality columns first keeps those
  ranges contiguous. `event_id` is last so that the key is unique per event, which is what
  `ReplacingMergeTree` needs to collapse duplicates.
- **ReplacingMergeTree.** Duplicates of an event have the same `event_id` and the same parsed
  timestamp, so they share a sorting key and a partition and collapse during merges. The
  version column keeps the latest ingest time.
- **Insert deduplication.** Merges happen eventually, so `FINAL` is still needed for exact
  counts. Batch replays are stopped earlier by insert tokens and the deduplication window.
- **Daily partitions.** Retention works on whole partitions with `ttl_only_drop_parts`, so
  expiry is a cheap metadata operation. Ninety daily partitions stay well below the part
  limits.
- **Skip indexes.** Bloom filters on `source_ip`, `user_name` and `event_id` serve the drill
  down queries that do not match the sorting key.
- **Types.** Addresses are `IPv4`, which allows `dictGet` on the `ip_trie` dictionaries without
  conversion. Categorical strings are `LowCardinality`. The raw line is compressed with ZSTD.

Alternatives considered:

- A plain `MergeTree` with deduplication only at insert time. Simpler, but duplicates from
  Vector re-sends would stay forever.
- `CollapsingMergeTree`. It needs a sign column and a writer that knows the previous row,
  which does not fit an append only stream.

## Consequences

- Dashboards that count events should use `FINAL` or accept a small overcount until merges
  run. The dbt staging model reads with `FINAL`.
- Rows cannot move between partitions. If a later parser change altered the parsed timestamp
  of existing lines, old and new versions would not collapse.
