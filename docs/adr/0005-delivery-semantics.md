# 5. Delivery semantics of the streaming pipeline

Date: 2026-09-30

## Status

Accepted

## Context

The normalize job reads `raw.*` topics and writes to four places: the bronze and silver
Parquet datasets in MinIO, the `events.normalized` topic and the ClickHouse `events` table.
The detect job reads `events.normalized` and writes alerts to ClickHouse and to the `alerts`
topic. After a crash or a redeploy both jobs restart from checkpoints stored in MinIO. The
question is what a restart does to each sink.

This record describes what the pipeline guarantees today, including where it does not provide
exactly-once delivery.

## Decision

Spark Structured Streaming tracks Kafka offsets per micro batch in the checkpoint. A batch is
replayed in full if the job stops after writing but before committing the batch. Each sink
handles that replay differently.

### Vector to Redpanda: at least once

Vector tails the log files and checkpoints file positions. End to end acknowledgements are
enabled, so a position only advances after Redpanda confirmed the write. Without them Vector
checkpointed lines it had failed to deliver, which lost data during the first test run. A crash
between the Kafka acknowledgement and the checkpoint write re-sends lines.

### Bronze and silver Parquet: exactly once

Both datasets use the Spark file sink. It writes files first and then records them in the
`_spark_metadata` log of the batch. Readers that go through Spark only see files listed in
that log, so a replayed batch does not produce duplicates for them. Readers that list the
directory directly (pyarrow, Trino without the log) can see orphaned files from an aborted
batch. The daily compaction job reads the directory directly and therefore deduplicates by
`event_id` when it writes `events_daily`.

### ClickHouse events: effectively once

Rows are inserted from `foreachBatch` with `insert_deduplication_token` set to
`normalize-<batch id>`. The table keeps a window of recent insert tokens
(`non_replicated_deduplication_window`), so replaying a batch with the same id is dropped by
the server. As a second line of defence the table is a `ReplacingMergeTree` whose sorting key
contains `event_id`, so rows that still arrive twice, for example because Vector re-sent a line,
collapse during merges. Queries that need exact counts use `FINAL`.

### events.normalized and raw.dlq: at least once

The Spark Kafka sink is not transactional. A replayed batch publishes its events again.
Downstream consumers must be idempotent:

- `event_id` is the SHA-256 of the raw line, so duplicates carry the same id.
- Correlation windows count `collect_set(event_id)`, and alerts store event ids as a set.
- The detector state for impossible travel ignores events older than the last one it saw.

### ClickHouse alerts: effectively once

Alert ids are derived from rule, entity and first event time. Alerts are written as new
versions of a `ReplacingMergeTree(updated_at)` row, with an insert deduplication token per
micro batch. Merging a hit into an alert is a set union, so replaying a batch does not change
event counts.

### alerts topic: at least once

The detect job publishes a message for every new alert version. The notifier keeps the ids it
has already sent and notifies once per alert.

## Consequences

- No sink loses data on restart as long as the checkpoints in MinIO survive.
- Exactly-once holds for Spark readers of the lake. ClickHouse is exact after deduplication and
  merges. Kafka topics are at least once and every consumer in the project tolerates that.
- Identical raw lines get the same `event_id` and are treated as one event. With microsecond
  timestamps on ssh, firewall and app lines this is rare. nginx has second resolution, so two
  identical requests in the same second from the same client collapse into one.
- S3A has no atomic rename. The checkpoint manager writes a temporary file and renames it, and
  MinIO implements the rename as copy and delete. A crash in that window can leave a partial
  checkpoint file that Spark rejects on restart. This has not happened in testing, but
  production use should put checkpoints on a store with atomic rename.
