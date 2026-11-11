CREATE TABLE IF NOT EXISTS geoip_city_networks
(
    network String,
    country_code LowCardinality(String),
    country LowCardinality(String),
    city String,
    latitude Float64,
    longitude Float64,
    source LowCardinality(String),
    loaded_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY network;

CREATE TABLE IF NOT EXISTS geoip_asn_networks
(
    network String,
    asn UInt32,
    as_org String,
    source LowCardinality(String),
    loaded_at DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY network;

CREATE DICTIONARY IF NOT EXISTS geoip_city
(
    network String,
    country_code String,
    country String,
    city String,
    latitude Float64,
    longitude Float64
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    QUERY 'SELECT network, country_code, country, city, latitude, longitude FROM ${CLICKHOUSE_DB}.geoip_city_networks'
    USER '${CLICKHOUSE_USER}' PASSWORD '${CLICKHOUSE_PASSWORD}'
))
LAYOUT(IP_TRIE())
LIFETIME(MIN 60 MAX 300);

CREATE DICTIONARY IF NOT EXISTS geoip_asn
(
    network String,
    asn UInt32,
    as_org String
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    QUERY 'SELECT network, asn, as_org FROM ${CLICKHOUSE_DB}.geoip_asn_networks'
    USER '${CLICKHOUSE_USER}' PASSWORD '${CLICKHOUSE_PASSWORD}'
))
LAYOUT(IP_TRIE())
LIFETIME(MIN 60 MAX 300);

CREATE TABLE IF NOT EXISTS threat_intel
(
    network String,
    provider LowCardinality(String),
    is_malicious UInt8,
    abuse_score Nullable(UInt8),
    categories Array(LowCardinality(String)),
    fetched_at DateTime,
    expires_at DateTime
)
ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY (provider, network)
TTL expires_at DELETE;

CREATE DICTIONARY IF NOT EXISTS threat_intel_networks
(
    network String,
    is_malicious UInt8,
    abuse_score Int16,
    providers String
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    QUERY 'SELECT network, max(is_malicious) AS is_malicious, max(ifNull(abuse_score, -1)) AS abuse_score, arrayStringConcat(groupUniqArray(provider), \',\') AS providers FROM ${CLICKHOUSE_DB}.threat_intel FINAL WHERE expires_at > now() GROUP BY network'
    USER '${CLICKHOUSE_USER}' PASSWORD '${CLICKHOUSE_PASSWORD}'
))
LAYOUT(IP_TRIE())
LIFETIME(MIN 60 MAX 300);
