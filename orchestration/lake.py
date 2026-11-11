import os
import re
from dataclasses import dataclass
from datetime import date, timedelta

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq
from pyarrow import fs

PARTITION = re.compile(r"^(?P<key>[a-z_]+)=(?P<value>.+)$")


@dataclass(frozen=True, slots=True)
class LakeLocation:
    filesystem: fs.FileSystem
    root: str

    def path(self, *parts: str) -> str:
        return "/".join([self.root.rstrip("/"), *parts])


def s3_location(bucket: str) -> LakeLocation:
    endpoint = os.environ.get("S3_ENDPOINT_URL", os.environ.get("S3_ENDPOINT", "http://minio:9000"))
    scheme, _, host = endpoint.partition("://")
    filesystem = fs.S3FileSystem(
        access_key=os.environ.get("S3_ACCESS_KEY"),
        secret_key=os.environ.get("S3_SECRET_KEY"),
        endpoint_override=host,
        scheme=scheme,
        region="us-east-1",
    )
    return LakeLocation(filesystem, bucket)


def _partitions(location: LakeLocation, dataset: str, key: str) -> dict[str, list[str]]:
    selector = fs.FileSelector(location.path(dataset), allow_not_found=True, recursive=False)
    grouped: dict[str, list[str]] = {}
    for source_dir in location.filesystem.get_file_info(selector):
        if source_dir.type != fs.FileType.Directory:
            continue
        inner = fs.FileSelector(source_dir.path, allow_not_found=True, recursive=False)
        for partition in location.filesystem.get_file_info(inner):
            match = PARTITION.match(partition.base_name)
            if partition.type == fs.FileType.Directory and match and match["key"] == key:
                grouped.setdefault(match["value"], []).append(partition.path)
    return grouped


def compact_day(
    source: LakeLocation, target: LakeLocation, day: date, dataset: str = "events"
) -> dict[str, int]:
    written: dict[str, int] = {}
    for directory in _partitions(source, dataset, "event_date").get(day.isoformat(), []):
        files = [
            info.path
            for info in source.filesystem.get_file_info(fs.FileSelector(directory))
            if info.type == fs.FileType.File and info.path.endswith(".parquet")
        ]
        if not files:
            continue
        table = ds.dataset(files, filesystem=source.filesystem, format="parquet").to_table()
        if "event_id" in table.column_names:
            table = table.filter(pa.array(_first_seen_mask(table.column("event_id").to_pylist())))
            table = table.sort_by("timestamp")
        source_part = directory.split("/")[-2]
        output_dir = target.path(f"{dataset}_daily", source_part, f"event_date={day.isoformat()}")
        target.filesystem.create_dir(output_dir, recursive=True)
        pq.write_table(
            table,
            f"{output_dir}/part-00000.parquet",
            filesystem=target.filesystem,
            compression="zstd",
        )
        written[source_part.removeprefix("source_type=")] = table.num_rows
    return written


def _first_seen_mask(values: list[object]) -> list[bool]:
    seen: set[object] = set()
    mask = []
    for value in values:
        mask.append(value not in seen)
        seen.add(value)
    return mask


def expire_partitions(
    location: LakeLocation, dataset: str, key: str, keep_days: int, today: date
) -> list[str]:
    horizon = today - timedelta(days=keep_days)
    removed = []
    for value, directories in _partitions(location, dataset, key).items():
        try:
            partition_day = date.fromisoformat(value)
        except ValueError:
            continue
        if partition_day < horizon:
            for directory in directories:
                location.filesystem.delete_dir(directory)
                removed.append(directory)
    return sorted(removed)
