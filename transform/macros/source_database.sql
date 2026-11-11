{% macro source_database() %}{{ env_var('CLICKHOUSE_DB', 'sentinelflow') }}{% endmacro %}
