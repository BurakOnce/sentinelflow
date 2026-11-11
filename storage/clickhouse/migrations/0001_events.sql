CREATE TABLE IF NOT EXISTS events
(
    event_id String,
    timestamp DateTime64(6, 'UTC'),
    ingest_time DateTime64(6, 'UTC'),
    source_type LowCardinality(String),
    event_category LowCardinality(String),
    event_action LowCardinality(String),
    event_outcome LowCardinality(Nullable(String)),
    source_ip Nullable(IPv4),
    source_port Nullable(UInt16),
    destination_ip Nullable(IPv4),
    destination_port Nullable(UInt16),
    host_name LowCardinality(Nullable(String)),
    user_name Nullable(String),
    user_agent Nullable(String),
    http_method LowCardinality(Nullable(String)),
    url_path Nullable(String),
    http_status Nullable(UInt16),
    raw_message String CODEC(ZSTD(3)),
    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user_name user_name TYPE bloom_filter GRANULARITY 4,
    INDEX idx_event_id event_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_type, event_action, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS non_replicated_deduplication_window = 1000, ttl_only_drop_parts = 1;

CREATE TABLE IF NOT EXISTS parse_failures
(
    source_type LowCardinality(String),
    error LowCardinality(String),
    topic LowCardinality(String),
    kafka_partition UInt32,
    kafka_offset UInt64,
    ingest_time DateTime64(6, 'UTC'),
    raw_message String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ingest_time)
ORDER BY (topic, kafka_partition, kafka_offset)
TTL toDateTime(ingest_time) + INTERVAL 30 DAY DELETE
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS pipeline_batches
(
    job LowCardinality(String),
    query LowCardinality(String),
    batch_id UInt64,
    processed_at DateTime64(3, 'UTC'),
    input_rows UInt64,
    input_rows_per_second Float64,
    processed_rows_per_second Float64,
    duration_ms UInt64,
    offsets_behind_latest Float64
)
ENGINE = ReplacingMergeTree(processed_at)
ORDER BY (job, query, batch_id)
TTL toDateTime(processed_at) + INTERVAL 14 DAY DELETE;
