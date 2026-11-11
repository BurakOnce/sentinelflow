# 2. Single Python package with optional dependency groups

Date: 2026-09-30

## Status

Accepted

## Context

The Python code is split across `simulator`, `streaming`, `detections`, `enrichment` and
`orchestration`. These modules share code: the normalized event schema and the detection rule
engine are used by the streaming jobs, the batch pipelines and the test suite.

Their runtime dependencies differ considerably. PySpark is only needed inside the Spark
containers, while Dagster and dbt are only needed inside the orchestration containers.
Installing everything into every image would make images large and slow to build.

Two layouts were considered:

1. A uv workspace with one `pyproject.toml` per member.
2. A single `pyproject.toml` with optional dependency groups (extras).

## Decision

Use a single `pyproject.toml` and a single `uv.lock`. Each top-level directory is an importable
package. Heavy dependencies are declared as extras: `simulator`, `streaming` and
`orchestration`. Each container image installs only the extra it needs with
`uv sync --frozen --extra <name>`. Local development installs all extras.

## Consequences

- One lockfile guarantees that every container resolves the same versions of shared
  dependencies such as pydantic.
- Ruff, mypy and pytest share one configuration and run over the whole codebase.
- Shared code is imported directly without inter-package version management.
- All extras must be resolvable together. A conflict between, for example, Dagster and
  PySpark dependencies would need to be solved in one environment. If that happens, this
  decision should be revisited in favour of a workspace.
- Modules cannot be released independently. This is acceptable because nothing is published.
