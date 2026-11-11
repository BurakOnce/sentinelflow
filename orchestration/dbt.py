import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dagster as dg
from dagster_dbt import DbtCliResource, DbtProject, build_dbt_asset_selection, dbt_assets

PROJECT_DIR = Path(os.environ.get("DBT_PROJECT_DIR", Path(__file__).parent.parent / "transform"))
project = DbtProject(project_dir=PROJECT_DIR, profiles_dir=PROJECT_DIR)
project.prepare_if_dev()


@dbt_assets(manifest=project.manifest_path, project=project)
def sentinelflow_dbt(context: dg.AssetExecutionContext, dbt: DbtCliResource) -> Iterator[Any]:
    yield from dbt.cli(["build"], context=context).stream()


efficacy_selection = build_dbt_asset_selection(
    [sentinelflow_dbt], dbt_select="+fct_detection_efficacy +fct_mitre_coverage"
)
dbt_resource = DbtCliResource(project_dir=project)
