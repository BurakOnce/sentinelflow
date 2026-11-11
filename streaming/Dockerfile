FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless procps \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s "$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")" /opt/java

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

ENV JAVA_HOME=/opt/java \
    TZ=UTC \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    PYSPARK_PYTHON=/opt/venv/bin/python \
    PYSPARK_DRIVER_PYTHON=/opt/venv/bin/python \
    SPARK_HOME=/opt/venv/lib/python3.12/site-packages/pyspark

WORKDIR /opt/sentinelflow

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --extra streaming

ARG HADOOP_AWS_VERSION=3.5.0
RUN <<EOF
set -e
python - <<'PY'
import os
import re
import shutil
from pathlib import Path

import pyspark
from pyspark.sql import SparkSession

packages = [
    f"org.apache.spark:spark-sql-kafka-0-10_2.13:{pyspark.__version__}",
    f"org.apache.hadoop:hadoop-aws:{os.environ['HADOOP_AWS_VERSION']}",
]
SparkSession.builder.master("local[1]").config("spark.jars.packages", ",".join(packages)).config(
    "spark.jars.ivy", "/tmp/ivy"
).getOrCreate().stop()
target = Path(os.environ["SPARK_HOME"]) / "jars"
present = {re.sub(r"-\d[\w.\-]*\.jar$", "", jar.name) for jar in target.glob("*.jar")}
for jar in Path("/tmp/ivy/jars").glob("*.jar"):
    artifact = re.sub(r"-\d[\w.\-]*\.jar$", "", jar.name.split("_", 1)[-1])
    if artifact not in present:
        shutil.copy(jar, target / jar.name.split("_", 1)[-1])
shutil.rmtree("/tmp/ivy")
PY
EOF

COPY simulator ./simulator
COPY streaming ./streaming
COPY detections ./detections
COPY enrichment ./enrichment
COPY orchestration ./orchestration
COPY storage ./storage
COPY notifier ./notifier
RUN uv sync --frozen --no-dev --extra streaming
