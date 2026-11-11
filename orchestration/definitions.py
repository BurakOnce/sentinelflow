import dagster as dg

from orchestration.checks import asset_checks, source_tables
from orchestration.dbt import dbt_resource, efficacy_selection, sentinelflow_dbt
from orchestration.jobs import (
    bronze_retention_job,
    geoip_job,
    silver_compaction_job,
    threat_intel_job,
)
from orchestration.sensors import ground_truth_sensor_factory

dbt_build_job = dg.define_asset_job(
    "dbt_build_job", selection=dg.AssetSelection.assets(sentinelflow_dbt)
)
efficacy_job = dg.define_asset_job("detection_efficacy_job", selection=efficacy_selection)
source_checks_job = dg.define_asset_job(
    "source_checks_job", selection=dg.AssetSelection.checks(*asset_checks)
)

defs = dg.Definitions(
    assets=[sentinelflow_dbt, *source_tables],
    asset_checks=asset_checks,
    jobs=[
        dbt_build_job,
        efficacy_job,
        source_checks_job,
        threat_intel_job,
        geoip_job,
        silver_compaction_job,
        bronze_retention_job,
    ],
    schedules=[
        dg.ScheduleDefinition(job=dbt_build_job, cron_schedule="0 * * * *"),
        dg.ScheduleDefinition(job=source_checks_job, cron_schedule="*/30 * * * *"),
        dg.ScheduleDefinition(job=threat_intel_job, cron_schedule="0 2 * * *"),
        dg.ScheduleDefinition(job=geoip_job, cron_schedule="0 3 * * 1"),
        dg.ScheduleDefinition(job=silver_compaction_job, cron_schedule="30 1 * * *"),
        dg.ScheduleDefinition(job=bronze_retention_job, cron_schedule="0 4 * * *"),
    ],
    sensors=[ground_truth_sensor_factory(efficacy_job.name)],
    resources={"dbt": dbt_resource},
)
