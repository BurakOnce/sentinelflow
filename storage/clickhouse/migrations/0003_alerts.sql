CREATE TABLE IF NOT EXISTS alerts
(
    alert_id String,
    rule_id String,
    rule_name LowCardinality(String),
    rule_title LowCardinality(String),
    rule_type LowCardinality(String),
    level LowCardinality(String),
    mitre_tactics Array(LowCardinality(String)),
    mitre_techniques Array(LowCardinality(String)),
    entity_type LowCardinality(String),
    entity String,
    first_seen DateTime64(6, 'UTC'),
    last_seen DateTime64(6, 'UTC'),
    detected_at DateTime64(6, 'UTC'),
    event_count UInt32,
    sample_event_ids Array(String),
    event_ids Array(String) CODEC(ZSTD(3)),
    status LowCardinality(String),
    created_at DateTime64(3, 'UTC'),
    updated_at DateTime64(3, 'UTC'),
    country_code LowCardinality(Nullable(String)),
    country LowCardinality(Nullable(String)),
    city Nullable(String),
    asn Nullable(UInt32),
    as_org Nullable(String),
    is_known_malicious UInt8,
    abuse_score Nullable(UInt8),
    risk_score UInt8,
    risk_factors Map(String, Float32)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY alert_id
TTL toDateTime(first_seen) + INTERVAL 365 DAY DELETE;

CREATE TABLE IF NOT EXISTS detector_state
(
    detector LowCardinality(String),
    key String,
    value String,
    updated_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (detector, key);
