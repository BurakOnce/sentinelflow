# 7. Windowing and late data in the detection job

Date: 2026-09-30

## Status

Accepted

## Context

Correlation rules count events per group within a time span: fifteen failed ssh logins per
address in five minutes, twenty distinct ports per address in one minute. Events can arrive out
of order and late: Vector batches lines, a backfill replays hours of history, and a paused
producer can resume minutes later. The job needs bounded state and early alerts.

## Decision

### Event time, not processing time

All windows use the timestamp parsed from the log line. Backfills therefore produce the same
alerts as live traffic, which is what makes the precision and recall measurements repeatable.

### Sliding windows aligned to the epoch

Each correlation rule uses windows of its `timespan` that start every `slide`, where `slide`
defaults to a fifth of the timespan. A burst shorter than four fifths of the timespan always
fits into at least one window. Window starts are computed with the same formula in Spark and
in the Python reference evaluator (`window_starts`), so both assign every event to the same
windows.

All correlation rules share one streaming aggregation. Events are exploded into
`(rule, group, window)` rows and grouped once, instead of running one query per rule.

### Watermark on the window end

The watermark is set on `window_end` with a delay of ten minutes (`DETECTION_WATERMARK`).
State for a window is dropped once the watermark passes its end. An event is accepted if its
window has not been dropped yet, so events up to ten minutes behind the newest event are still
counted.

### Update output mode

The aggregation emits every window that changed in a micro batch, not only closed windows.
An alert can therefore fire as soon as a threshold is crossed, instead of waiting for the
window and the watermark delay to pass. Repeated emissions of a growing window are merged by
alert suppression, and event ids are kept as a set so nothing is counted twice.

### Detection time

For each emitted window the driver replays the window entries in time order and records the
event that first satisfied the condition. That event time is stored as `detected_at` and used
for the latency measurement.

### Late data

- Events later than the watermark delay are dropped by Spark for correlation rules. The
  per-query progress metrics expose the row counts, but the dropped events are not reported
  individually.
- Single event rules and detectors are stateless per micro batch and accept late events of any
  age.
- The impossible travel detector keeps the last login per user. A login older than the stored
  one is ignored, which keeps replays idempotent but means a very late login is never compared.

## Consequences

- State is bounded by the number of active groups times the windows per timespan.
- A ten minute watermark is a trade-off: longer delays keep more state and accept later data;
  shorter delays drop slow producers.
- Backfilling data older than the watermark after newer data has been processed will not raise
  correlation alerts for the older data. Replaying history requires resetting the detection
  checkpoint, as the tuning runs did.
