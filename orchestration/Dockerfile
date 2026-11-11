FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    DAGSTER_HOME=/opt/dagster/home \
    TZ=UTC

WORKDIR /opt/sentinelflow

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --extra orchestration

COPY simulator ./simulator
COPY streaming ./streaming
COPY detections ./detections
COPY enrichment ./enrichment
COPY orchestration ./orchestration
COPY storage ./storage
COPY notifier ./notifier
COPY transform ./transform
RUN uv sync --frozen --no-dev --extra orchestration \
    && cd transform && dbt parse --profiles-dir .

COPY orchestration/dagster.yaml /opt/dagster/home/dagster.yaml
COPY orchestration/workspace.yaml /opt/dagster/workspace.yaml
