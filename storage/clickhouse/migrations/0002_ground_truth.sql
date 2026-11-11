CREATE TABLE IF NOT EXISTS ground_truth
(
    attack_id String,
    scenario LowCardinality(String),
    technique_id LowCardinality(String),
    stage LowCardinality(String),
    source LowCardinality(String),
    event_time DateTime64(6, 'UTC'),
    window_start DateTime64(6, 'UTC'),
    window_end DateTime64(6, 'UTC'),
    src_ip String,
    user Nullable(String),
    line_sha256 String,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (attack_id, line_sha256);

CREATE TABLE IF NOT EXISTS ground_truth_queue
(
    attack_id String,
    scenario String,
    technique_id String,
    stage String,
    source String,
    event_time String,
    window_start String,
    window_end String,
    src_ip String,
    user Nullable(String),
    line_sha256 String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list = '${KAFKA_BROKERS}',
    kafka_topic_list = 'labels.ground_truth',
    kafka_group_name = 'clickhouse-ground-truth',
    kafka_format = 'JSONEachRow',
    kafka_skip_broken_messages = 100;

CREATE MATERIALIZED VIEW IF NOT EXISTS ground_truth_consumer TO ground_truth AS
SELECT
    attack_id,
    scenario,
    technique_id,
    stage,
    source,
    parseDateTime64BestEffort(event_time, 6, 'UTC') AS event_time,
    parseDateTime64BestEffort(window_start, 6, 'UTC') AS window_start,
    parseDateTime64BestEffort(window_end, 6, 'UTC') AS window_end,
    src_ip,
    user,
    line_sha256
FROM ground_truth_queue;
