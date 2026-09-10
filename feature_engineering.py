#!/usr/bin/env python3
"""
AI-NOC Feature Engineering
===========================

Purpose
-------
Build ML-ready interface-level and device-level feature vectors from the
validated Zabbix pipeline.

Inputs
------
1. transformed_history.jsonl (or --input path)
2. scoped_metrics.json       (or --metadata path)

Outputs
-------
1. interface_features.jsonl
2. device_features.jsonl
3. feature_engineering_audit.json

Design decisions based on previous audits
------------------------------------------
- Use transformed value, not raw counter value, for rate/gauge features.
- Counter decreases/resets are NOT converted into negative rates; they are
  represented as quality/context features (counter_reset_count / flag).
- Interface identity is hostid + ifIndex, never Zabbix interfaceid.
- Feature windows are trailing/past-looking only to avoid future leakage.
- Interface features are primarily built from interface metrics.
- Device features combine device-health metrics plus aggregates over
  interface feature rows.
- Missing metrics are preserved as null and explicitly audited.
- Feature rows are created on a fixed one-minute time grid from observed
  timestamps; a metric contributes only if it has data inside the trailing
  window.

Default windows
---------------
- 5 minutes
- 15 minutes

The script does not train a model. It creates a stable feature contract that
can be ingested into Elasticsearch and later used by anomaly detection.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# ============================================================
# Defaults
# ============================================================

DEFAULT_INPUT = "transformed_history.jsonl"
DEFAULT_METADATA = "scoped_metrics.json"
DEFAULT_INTERFACE_OUTPUT = "interface_features.jsonl"
DEFAULT_DEVICE_OUTPUT = "device_features.jsonl"
DEFAULT_AUDIT_OUTPUT = "feature_engineering_audit.json"

DEFAULT_BUCKET_SEC = 60
DEFAULT_WINDOWS = (300, 900)  # 5m, 15m

EPS = 1e-12

INTERFACE_METRICS = {
    "in_bps",
    "out_bps",
    "in_pps",
    "out_pps",
    "in_error_rate",
    "out_error_rate",
    "in_discard_rate",
    "out_discard_rate",
    "oper_status",
}

DEVICE_METRICS = {
    "cpu_pct",
    "memory_pct",
    "temperature_c",
    "fan_status",
    "psu_status",
    "uptime",
    "icmp_loss_pct",
    "icmp_rtt_sec",
}

# These are contextual/quality signals, not direct anomaly labels.
RESET_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
}


# ============================================================
# Generic helpers
# ============================================================


def safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        x = float(value)
        if math.isfinite(x):
            return x
    except (TypeError, ValueError):
        pass
    return None


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def iso_utc(clock: int) -> str:
    return datetime.fromtimestamp(
        int(clock), tz=timezone.utc
    ).isoformat()


def floor_bucket(clock: int, bucket_sec: int) -> int:
    return int(clock) // bucket_sec * bucket_sec


def mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def std(values: list[float]) -> float | None:
    if len(values) < 2:
        return 0.0 if values else None
    return statistics.pstdev(values)


def min_value(values: list[float]) -> float | None:
    return min(values) if values else None


def max_value(values: list[float]) -> float | None:
    return max(values) if values else None


def last_value(values: list[tuple[int, float]]) -> float | None:
    if not values:
        return None
    return max(values, key=lambda x: x[0])[1]


def first_value(values: list[tuple[int, float]]) -> float | None:
    if not values:
        return None
    return min(values, key=lambda x: x[0])[1]


def ratio(numerator: float | None, denominator: float | None) -> float | None:
    if numerator is None or denominator is None:
        return None
    if abs(denominator) <= EPS:
        return None
    return numerator / denominator


def parse_ifindex(key: str | None) -> int | None:
    """Extract IF-MIB ifIndex from common SNMP Zabbix keys."""
    if not key:
        return None

    key = str(key)
    patterns = (
        r"if(?:HC)?InOctets\.(\d+)",
        r"if(?:HC)?OutOctets\.(\d+)",
        r"ifInUcastPkts\.(\d+)",
        r"ifOutUcastPkts\.(\d+)",
        r"ifInErrors\.(\d+)",
        r"ifOutErrors\.(\d+)",
        r"ifInDiscards\.(\d+)",
        r"ifOutDiscards\.(\d+)",
        r"ifOperStatus\.(\d+)",
        r"ifAdminStatus\.(\d+)",
    )

    for pattern in patterns:
        m = re.search(pattern, key, re.IGNORECASE)
        if m:
            return int(m.group(1))

    # Fallback for interface keys that simply end in .<ifindex>
    m = re.search(r"\.(\d+)\]$", key)
    if m:
        return int(m.group(1))

    return None


def write_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


# ============================================================
# Metadata loading
# ============================================================


def load_scoped_metadata(path: Path) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, int], set[str]], dict[str, set[str]]]:
    """
    Return:
      item_map: itemid -> metric metadata
      expected_interface_metrics: (hostid, ifindex) -> canonical metrics
      expected_device_metrics: hostid -> canonical device metrics

    Supports:
      {"metrics": [...]} or [...]
    """
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        metrics = data
    elif isinstance(data, dict):
        metrics = data.get("metrics", [])
        if not isinstance(metrics, list):
            raise ValueError("scoped_metrics.json 'metrics' must be a list")
    else:
        raise ValueError("Unsupported scoped_metrics.json format")

    item_map: dict[str, dict[str, Any]] = {}
    expected_interface_metrics: dict[tuple[str, int], set[str]] = defaultdict(set)
    expected_device_metrics: dict[str, set[str]] = defaultdict(set)

    duplicate_itemids = 0

    for metric in metrics:
        if not isinstance(metric, dict):
            continue

        itemid = str(metric.get("itemid", "")).strip()
        if not itemid:
            continue

        if itemid in item_map:
            duplicate_itemids += 1
        item_map[itemid] = metric

        hostid = str(metric.get("hostid", "")).strip()
        canonical = metric.get("canonical_metric")
        key = metric.get("key", "")

        if not hostid or not canonical:
            continue

        ifindex = parse_ifindex(key)
        if ifindex is not None and canonical in INTERFACE_METRICS:
            expected_interface_metrics[(hostid, ifindex)].add(canonical)
        elif canonical in DEVICE_METRICS:
            expected_device_metrics[hostid].add(canonical)

    return item_map, expected_interface_metrics, expected_device_metrics


# ============================================================
# Transformed history loader
# ============================================================


def load_transformed_history(path: Path, item_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records: list[dict[str, Any]] = []
    stats = Counter()

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            stats["lines"] += 1

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                stats["parse_errors"] += 1
                continue

            itemid = str(raw.get("itemid", "")).strip()
            metadata = item_map.get(itemid)
            if metadata is None:
                stats["missing_metadata"] += 1
                continue

            clock = safe_int(raw.get("clock"))
            value = safe_float(raw.get("value"))
            raw_value = safe_float(raw.get("raw_value"))

            if clock is None:
                stats["invalid_clock"] += 1
                continue

            canonical = metadata.get("canonical_metric")
            if not canonical:
                stats["missing_canonical"] += 1
                continue

            ifindex = parse_ifindex(metadata.get("key", ""))

            record = {
                "clock": clock,
                "timestamp": raw.get("timestamp") or iso_utc(clock),
                "itemid": itemid,
                "hostid": str(raw.get("hostid") or metadata.get("hostid") or ""),
                "host": raw.get("host") or metadata.get("host", ""),
                "host_name": raw.get("host_name") or metadata.get("host_name") or raw.get("host") or metadata.get("host", ""),
                "device_role": raw.get("device_role") or metadata.get("device_role") or "",
                "canonical_metric": canonical,
                "semantic_type": metadata.get("semantic_type"),
                "transformation": metadata.get("transformation"),
                "key": metadata.get("key", ""),
                "ifindex": ifindex,
                "value": value,
                "raw_value": raw_value,
                "counter_reset": bool(raw.get("counter_reset", False)),
                "duplicate_timestamp": bool(raw.get("duplicate_timestamp", False)),
                "out_of_order": bool(raw.get("out_of_order", False)),
            }

            # We keep only metrics that are meaningful for feature construction.
            if canonical not in INTERFACE_METRICS and canonical not in DEVICE_METRICS:
                stats["unrelated_records"] += 1
                continue

            # A transformed counter reset can have value=null. It is still useful
            # for quality/reset context, so do not drop it entirely.
            if value is None and not record["counter_reset"]:
                stats["null_nonreset_values"] += 1

            records.append(record)
            stats["accepted_records"] += 1

    return records, dict(stats)


# ============================================================
# Indexing and deduplication
# ============================================================


def deduplicate_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Deduplicate exact itemid + clock duplicates.

    The previous audit found zero duplicates, but keeping this guard in the
    feature pipeline makes it robust to future collection runs.
    """
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        grouped[(r["itemid"], r["clock"])].append(r)

    output = []
    duplicate_groups = 0
    duplicate_rows = 0
    conflicting_values = 0

    for key, rows in grouped.items():
        if len(rows) == 1:
            output.append(rows[0])
            continue

        duplicate_groups += 1
        duplicate_rows += len(rows) - 1

        values = {r["value"] for r in rows if r["value"] is not None}
        if len(values) > 1:
            conflicting_values += 1

        # Prefer a row with a non-null value, otherwise the first row.
        chosen = next((r for r in rows if r["value"] is not None), rows[0])
        chosen = dict(chosen)
        chosen["duplicate_timestamp"] = True
        output.append(chosen)

    output.sort(key=lambda r: (r["hostid"], r["ifindex"] if r["ifindex"] is not None else -1, r["clock"]))

    return output, {
        "duplicate_groups": duplicate_groups,
        "duplicate_rows_removed": duplicate_rows,
        "conflicting_duplicate_groups": conflicting_values,
    }


def build_series(records: list[dict[str, Any]]) -> tuple[dict[tuple[str, int], dict[str, list[dict[str, Any]]]], dict[str, list[dict[str, Any]]]]:
    """
    interface_series[(hostid, ifindex)][metric] -> sorted records
    device_series[hostid] -> sorted device-health records
    """
    interfaces: dict[tuple[str, int], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    devices: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for r in records:
        hostid = r["hostid"]
        metric = r["canonical_metric"]
        ifindex = r["ifindex"]

        if ifindex is not None and metric in INTERFACE_METRICS:
            interfaces[(hostid, int(ifindex))][metric].append(r)

        if metric in DEVICE_METRICS:
            devices[hostid].append(r)

    for series_map in interfaces.values():
        for metric in series_map:
            series_map[metric].sort(key=lambda x: x["clock"])

    for hostid in devices:
        devices[hostid].sort(key=lambda x: x["clock"])

    return interfaces, devices


# ============================================================
# Window extraction
# ============================================================



_CLOCK_CACHE: dict[int, list[int]] = {}


def _record_clocks(records: list[dict[str, Any]]) -> list[int]:
    """Return cached sorted clocks for a sorted record series."""
    key = id(records)
    clocks = _CLOCK_CACHE.get(key)
    if clocks is None:
        clocks = [r["clock"] for r in records]
        _CLOCK_CACHE[key] = clocks
    return clocks


def window_records(
    records: list[dict[str, Any]],
    end_clock: int,
    window_sec: int,
) -> list[dict[str, Any]]:
    """
    Return the current trailing window (T-window, T].

    Uses binary search over precomputed timestamps to avoid repeated
    reverse scans when producing many consecutive feature buckets.
    """
    if not records:
        return []

    clocks = _record_clocks(records)
    start = end_clock - window_sec + 1

    left = bisect_left(clocks, start)
    right = bisect_right(clocks, end_clock)

    return records[left:right]


def previous_window_records(
    records: list[dict[str, Any]],
    end_clock: int,
    window_sec: int,
) -> list[dict[str, Any]]:
    """
    Return the immediately preceding equal-duration baseline window.

    For T and window=5m:
        recent   = (T-5m, T]
        baseline = (T-10m, T-5m]

    The windows do not overlap.
    """
    if not records:
        return []

    clocks = _record_clocks(records)

    baseline_end = end_clock - window_sec
    baseline_start = baseline_end - window_sec + 1

    left = bisect_left(clocks, baseline_start)
    right = bisect_right(clocks, baseline_end)

    return records[left:right]


def metric_values(rows: list[dict[str, Any]]) -> list[tuple[int, float]]:
    out = []
    for r in rows:
        v = r.get("value")
        if v is None:
            continue
        out.append((r["clock"], float(v)))
    return out


def last_known_before(
    rows: list[dict[str, Any]],
    end_clock: int,
) -> dict[str, Any] | None:
    for r in reversed(rows):
        if r["clock"] <= end_clock:
            return r
    return None


# ============================================================
# Window statistics
# ============================================================

def aggregate_metric(
    rows: list[dict[str, Any]],
    prefix: str,
) -> dict[str, Any]:
    vals = metric_values(rows)
    numbers = [v for _, v in vals]

    result = {
        f"{prefix}_last": last_value(vals),
        f"{prefix}_mean": mean(numbers),
        f"{prefix}_std": std(numbers),
        f"{prefix}_min": min_value(numbers),
        f"{prefix}_max": max_value(numbers),
        f"{prefix}_count": len(numbers),
        f"{prefix}_range": (
            max(numbers) - min(numbers)
            if numbers
            else None
        ),
    }

    return result


def baseline_features(
    rows: list[dict[str, Any]],
    metric: str,
    suffix: str,
) -> dict[str, Any]:
    vals = metric_values(rows)
    numbers = [v for _, v in vals]

    # Keep the baseline compact. The recent window already carries full
    # last/mean/std/min/max/range statistics; the baseline only needs enough
    # information to establish a comparable historical level and its sample
    # count for behavioral-change features.
    return {
        f"{metric}_baseline_mean_{suffix}": mean(numbers),
        f"{metric}_baseline_std_{suffix}": std(numbers),
        f"{metric}_baseline_count_{suffix}": len(numbers),
    }


def behavior_change(
    recent_mean: float | None,
    baseline_mean: float | None,
    prefix: str,
) -> dict[str, Any]:
    if recent_mean is None or baseline_mean is None:
        return {
            f"{prefix}_change": None,
            f"{prefix}_change_pct": None,
            f"{prefix}_recent_to_baseline_ratio": None,
            f"{prefix}_increase_flag": 0,
            f"{prefix}_decrease_flag": 0,
        }

    change = recent_mean - baseline_mean

    if abs(baseline_mean) > EPS:
        pct = change / abs(baseline_mean)
        ratio_value = recent_mean / baseline_mean
    else:
        pct = None
        ratio_value = None

    return {
        f"{prefix}_change": change,
        f"{prefix}_change_pct": pct,
        f"{prefix}_recent_to_baseline_ratio": ratio_value,
        f"{prefix}_increase_flag": int(change > 0),
        f"{prefix}_decrease_flag": int(change < 0),
    }


def aggregate_derived(
    row: dict[str, Any],
    prefix: str,
    suffix: str,
) -> None:
    """
    Derive totals using recent-window means, not latest-value snapshots.

    This makes behavioral change features much more meaningful.
    """
    in_bps = row.get(f"in_bps_{suffix}_mean")
    out_bps = row.get(f"out_bps_{suffix}_mean")
    in_pps = row.get(f"in_pps_{suffix}_mean")
    out_pps = row.get(f"out_pps_{suffix}_mean")
    in_err = row.get(f"in_error_rate_{suffix}_mean")
    out_err = row.get(f"out_error_rate_{suffix}_mean")
    in_dis = row.get(f"in_discard_rate_{suffix}_mean")
    out_dis = row.get(f"out_discard_rate_{suffix}_mean")

    row[f"traffic_total_bps_{suffix}"] = (
        in_bps + out_bps
        if in_bps is not None and out_bps is not None
        else None
    )

    row[f"packet_total_pps_{suffix}"] = (
        in_pps + out_pps
        if in_pps is not None and out_pps is not None
        else None
    )

    row[f"error_total_rate_{suffix}"] = (
        in_err + out_err
        if in_err is not None and out_err is not None
        else None
    )

    row[f"discard_total_rate_{suffix}"] = (
        in_dis + out_dis
        if in_dis is not None and out_dis is not None
        else None
    )

    row[f"in_out_bps_ratio_{suffix}"] = ratio(
        in_bps,
        out_bps,
    )

    row[f"in_out_pps_ratio_{suffix}"] = ratio(
        in_pps,
        out_pps,
    )


def baseline_derived(
    row: dict[str, Any],
    suffix: str,
) -> None:
    """
    Build previous-window baseline totals from baseline means.
    """
    in_bps = row.get(f"in_bps_baseline_mean_{suffix}")
    out_bps = row.get(f"out_bps_baseline_mean_{suffix}")
    in_pps = row.get(f"in_pps_baseline_mean_{suffix}")
    out_pps = row.get(f"out_pps_baseline_mean_{suffix}")
    in_err = row.get(f"in_error_rate_baseline_mean_{suffix}")
    out_err = row.get(f"out_error_rate_baseline_mean_{suffix}")
    in_dis = row.get(f"in_discard_rate_baseline_mean_{suffix}")
    out_dis = row.get(f"out_discard_rate_baseline_mean_{suffix}")

    row[f"traffic_total_bps_baseline_mean_{suffix}"] = (
        in_bps + out_bps
        if in_bps is not None and out_bps is not None
        else None
    )

    row[f"packet_total_pps_baseline_mean_{suffix}"] = (
        in_pps + out_pps
        if in_pps is not None and out_pps is not None
        else None
    )

    row[f"error_total_rate_baseline_mean_{suffix}"] = (
        in_err + out_err
        if in_err is not None and out_err is not None
        else None
    )

    row[f"discard_total_rate_baseline_mean_{suffix}"] = (
        in_dis + out_dis
        if in_dis is not None and out_dis is not None
        else None
    )


# ============================================================
# Interface features
# ============================================================

def build_interface_features(
    interface_key: tuple[str, int],
    series_map: dict[str, list[dict[str, Any]]],
    expected_metrics: set[str],
    host_info: dict[str, Any],
    bucket_sec: int,
    windows: tuple[int, ...],
) -> list[dict[str, Any]]:
    hostid, ifindex = interface_key

    all_clocks = [
        r["clock"]
        for metric_rows in series_map.values()
        for r in metric_rows
    ]

    if not all_clocks:
        return []

    start_bucket = floor_bucket(min(all_clocks), bucket_sec)
    end_bucket = floor_bucket(max(all_clocks), bucket_sec)

    output = []
    bucket = start_bucket

    while bucket <= end_bucket:
        row: dict[str, Any] = {
            "@timestamp": iso_utc(bucket),
            "timestamp": bucket,
            "hostid": hostid,
            "host": host_info.get("host", ""),
            "host_name": host_info.get("host_name", ""),
            "device_role": host_info.get("device_role", ""),
            "ifindex": ifindex,
            "entity_type": "interface",
        }

        any_data = False

        for window_sec in windows:
            suffix = f"{window_sec // 60}m"

            metric_rows_cache: dict[str, list[dict[str, Any]]] = {}
            baseline_rows_cache: dict[str, list[dict[str, Any]]] = {}

            recent_present = set()
            baseline_present = set()

            # ----------------------------------------------------
            # Raw metric windows
            # ----------------------------------------------------
            for metric in INTERFACE_METRICS:
                source_rows = series_map.get(metric, [])

                recent_rows = window_records(
                    source_rows,
                    bucket,
                    window_sec,
                )

                baseline_rows = previous_window_records(
                    source_rows,
                    bucket,
                    window_sec,
                )

                metric_rows_cache[metric] = recent_rows
                baseline_rows_cache[metric] = baseline_rows

                if recent_rows:
                    recent_present.add(metric)
                    any_data = True

                if baseline_rows:
                    baseline_present.add(metric)

                row.update(
                    aggregate_metric(
                        recent_rows,
                        f"{metric}_{suffix}",
                    )
                )

                row.update(
                    baseline_features(
                        baseline_rows,
                        metric,
                        suffix,
                    )
                )

            # ----------------------------------------------------
            # Reset / counter quality context
            # ----------------------------------------------------
            reset_count = 0
            reset_magnitude = 0.0

            for metric in RESET_METRICS:
                for r in metric_rows_cache.get(metric, []):
                    if not r.get("counter_reset"):
                        continue

                    reset_count += 1

                    prev = safe_float(
                        r.get("previous_raw_value")
                    )
                    curr = safe_float(
                        r.get("raw_value")
                    )

                    if (
                        prev is not None
                        and curr is not None
                        and curr < prev
                    ):
                        reset_magnitude += prev - curr

            row[f"counter_reset_count_{suffix}"] = reset_count
            row[f"counter_reset_flag_{suffix}"] = int(
                reset_count > 0
            )
            row[f"counter_reset_raw_context_sum_{suffix}"] = (
                reset_magnitude
                if reset_count
                else None
            )

            # ----------------------------------------------------
            # Oper status transitions
            # ----------------------------------------------------
            status_rows = metric_rows_cache.get(
                "oper_status",
                [],
            )

            status_values = [
                (
                    r["clock"],
                    safe_float(r.get("value")),
                )
                for r in status_rows
                if safe_float(r.get("value")) is not None
            ]

            status_values.sort()

            status_changes = sum(
                int(cur != prev)
                for (_, prev), (_, cur)
                in zip(
                    status_values,
                    status_values[1:],
                )
            )

            row[f"oper_status_change_count_{suffix}"] = status_changes
            row[f"oper_status_change_flag_{suffix}"] = int(
                status_changes > 0
            )

            # ----------------------------------------------------
            # Derived recent aggregates
            # ----------------------------------------------------
            aggregate_derived(
                row,
                "derived",
                suffix,
            )

            # ----------------------------------------------------
            # Derived previous-window baseline
            # ----------------------------------------------------
            baseline_derived(
                row,
                suffix,
            )

            # ----------------------------------------------------
            # Coverage
            # ----------------------------------------------------
            expected_count = len(expected_metrics)

            row[
                f"metric_presence_count_{suffix}"
            ] = len(recent_present)

            row[
                f"metric_expected_count_{suffix}"
            ] = expected_count

            row[
                f"metric_missing_count_{suffix}"
            ] = max(
                expected_count - len(recent_present),
                0,
            )

            row[
                f"metric_coverage_ratio_{suffix}"
            ] = (
                len(recent_present) / expected_count
                if expected_count
                else None
            )

            row[
                f"baseline_metric_presence_count_{suffix}"
            ] = len(baseline_present)

            row[
                f"baseline_metric_expected_count_{suffix}"
            ] = expected_count

            row[
                f"baseline_metric_missing_count_{suffix}"
            ] = max(
                expected_count - len(baseline_present),
                0,
            )

            row[
                f"baseline_metric_coverage_ratio_{suffix}"
            ] = (
                len(baseline_present) / expected_count
                if expected_count
                else None
            )

        if not any_data:
            bucket += bucket_sec
            continue

        # --------------------------------------------------------
        # Behavioral change:
        # recent mean vs immediately previous equal-duration mean.
        # --------------------------------------------------------
        behavior_metrics = (
            "in_bps",
            "out_bps",
            "in_pps",
            "out_pps",
            "error_total_rate",
            "discard_total_rate",
            "traffic_total_bps",
            "packet_total_pps",
        )

        # First create recent/baseline means for derived metrics.
        for suffix in (
            f"{windows[0] // 60}m",
            f"{windows[-1] // 60}m",
        ):
            # These are derived from mean components.
            # The "baseline mean" fields were already created above.
            pass

        # Individual metrics.
        for window_sec in windows:
            suffix = f"{window_sec // 60}m"

            for metric in (
                "in_bps",
                "out_bps",
                "in_pps",
                "out_pps",
                "in_error_rate",
                "out_error_rate",
                "in_discard_rate",
                "out_discard_rate",
            ):
                recent_mean = row.get(
                    f"{metric}_{suffix}_mean"
                )
                base_mean = row.get(
                    f"{metric}_baseline_mean_{suffix}"
                )

                row.update(
                    behavior_change(
                        recent_mean,
                        base_mean,
                        f"{metric}_behavior_{suffix}",
                    )
                )

            derived_behavior = (
                "traffic_total_bps",
                "packet_total_pps",
                "error_total_rate",
                "discard_total_rate",
            )

            for metric in derived_behavior:
                recent_mean = row.get(
                    f"{metric}_{suffix}"
                )

                base_mean = row.get(
                    f"{metric}_baseline_mean_{suffix}"
                )

                # Preserve an explicit recent/baseline naming scheme.
                row.update(
                    behavior_change(
                        recent_mean,
                        base_mean,
                        f"{metric}_behavior_{suffix}",
                    )
                )

        # --------------------------------------------------------
        # Activity variability
        # --------------------------------------------------------
        in_std = row.get("in_bps_5m_std")
        out_std = row.get("out_bps_5m_std")
        traffic_mean = row.get("traffic_total_bps_5m")

        if (
            in_std is not None
            and out_std is not None
        ):
            row["traffic_variability_5m"] = math.sqrt(
                in_std * in_std
                + out_std * out_std
            )
        else:
            row["traffic_variability_5m"] = None

        row["traffic_cv_5m"] = (
            row["traffic_variability_5m"] / traffic_mean
            if (
                row["traffic_variability_5m"] is not None
                and traffic_mean is not None
                and abs(traffic_mean) > EPS
            )
            else None
        )

        row["oper_status_last"] = row.get(
            "oper_status_5m_last"
        )

        output.append(row)
        bucket += bucket_sec

    return output


# ============================================================
# Device features
# ============================================================

_INTERFACE_TIMESTAMP_CACHE: dict[int, dict[int, list[dict[str, Any]]]] = {}


def aggregate_interface_rows_at_timestamp(
    rows: list[dict[str, Any]],
    timestamp: int,
) -> dict[str, Any]:
    """
    Aggregate already-built interface features for a device bucket.

    A per-host timestamp index avoids rescanning all interface rows for every
    device minute.
    """
    cache_key = id(rows)
    timestamp_index = _INTERFACE_TIMESTAMP_CACHE.get(cache_key)

    if timestamp_index is None:
        timestamp_index = defaultdict(list)
        for r in rows:
            timestamp_index[r["timestamp"]].append(r)
        _INTERFACE_TIMESTAMP_CACHE[cache_key] = timestamp_index

    current = timestamp_index.get(timestamp, [])

    if not current:
        return {
            "interface_count": 0,
            "interfaces_with_oper_down": 0,
            "traffic_total_bps_sum": None,
            "traffic_total_bps_mean": None,
            "traffic_total_bps_max": None,
            "packet_total_pps_sum": None,
            "packet_total_pps_mean": None,
            "packet_total_pps_max": None,
            "error_total_rate_sum": None,
            "error_total_rate_max": None,
            "discard_total_rate_sum": None,
            "discard_total_rate_max": None,
            "interfaces_with_counter_reset": 0,
        }

    def vals(key: str) -> list[float]:
        return [
            float(r[key])
            for r in current
            if safe_float(r.get(key)) is not None
        ]

    traffic = vals("traffic_total_bps_5m")
    packets = vals("packet_total_pps_5m")
    errors = vals("error_total_rate_5m")
    discards = vals("discard_total_rate_5m")

    oper_down = sum(
        1
        for r in current
        if (
            safe_float(r.get("oper_status_last")) is not None
            and safe_float(r.get("oper_status_last")) != 1.0
        )
    )

    resets = sum(
        1
        for r in current
        if r.get("counter_reset_flag_5m") == 1
    )

    return {
        "interface_count": len(current),
        "interfaces_with_oper_down": oper_down,

        "traffic_total_bps_sum": (
            sum(traffic) if traffic else None
        ),
        "traffic_total_bps_mean": mean(traffic),
        "traffic_total_bps_max": max_value(traffic),

        "packet_total_pps_sum": (
            sum(packets) if packets else None
        ),
        "packet_total_pps_mean": mean(packets),
        "packet_total_pps_max": max_value(packets),

        "error_total_rate_sum": (
            sum(errors) if errors else None
        ),
        "error_total_rate_max": max_value(errors),

        "discard_total_rate_sum": (
            sum(discards) if discards else None
        ),
        "discard_total_rate_max": max_value(discards),

        "interfaces_with_counter_reset": resets,
    }


def build_device_features(
    hostid: str,
    device_rows: list[dict[str, Any]],
    interface_rows: list[dict[str, Any]],
    expected_device_metrics: set[str],
    host_info: dict[str, Any],
    bucket_sec: int,
    windows: tuple[int, ...],
) -> list[dict[str, Any]]:
    all_clocks = [
        r["clock"]
        for r in device_rows
    ]

    if interface_rows:
        all_clocks.extend(
            r["timestamp"]
            for r in interface_rows
        )

    if not all_clocks:
        return []

    start_bucket = floor_bucket(
        min(all_clocks),
        bucket_sec,
    )
    end_bucket = floor_bucket(
        max(all_clocks),
        bucket_sec,
    )

    output = []
    bucket = start_bucket

    device_metric_series: dict[
        str,
        list[dict[str, Any]]
    ] = defaultdict(list)

    for r in device_rows:
        device_metric_series[
            r["canonical_metric"]
        ].append(r)

    for metric in device_metric_series:
        device_metric_series[metric].sort(
            key=lambda x: x["clock"]
        )

    behavioral_device_metrics = {
        "cpu_pct",
        "memory_pct",
        "temperature_c",
        "icmp_loss_pct",
        "icmp_rtt_sec",
    }

    while bucket <= end_bucket:

        row: dict[str, Any] = {
            "@timestamp": iso_utc(bucket),
            "timestamp": bucket,
            "hostid": hostid,
            "host": host_info.get("host", ""),
            "host_name": host_info.get(
                "host_name",
                "",
            ),
            "device_role": host_info.get(
                "device_role",
                "",
            ),
            "entity_type": "device",
        }

        any_device_data = False

        for window_sec in windows:

            suffix = f"{window_sec // 60}m"

            present = set()
            baseline_present = set()

            for metric in DEVICE_METRICS:

                source_rows = device_metric_series.get(
                    metric,
                    [],
                )

                recent_rows = window_records(
                    source_rows,
                    bucket,
                    window_sec,
                )

                baseline_rows = previous_window_records(
                    source_rows,
                    bucket,
                    window_sec,
                )

                if recent_rows:
                    present.add(metric)
                    any_device_data = True

                if baseline_rows:
                    baseline_present.add(metric)

                row.update(
                    aggregate_metric(
                        recent_rows,
                        f"{metric}_{suffix}",
                    )
                )

                row.update(
                    baseline_features(
                        baseline_rows,
                        metric,
                        suffix,
                    )
                )

            # Coverage.
            expected_count = len(
                expected_device_metrics
            )

            row[
                f"metric_presence_count_{suffix}"
            ] = len(present)

            row[
                f"metric_expected_count_{suffix}"
            ] = expected_count

            row[
                f"metric_missing_count_{suffix}"
            ] = max(
                expected_count - len(present),
                0,
            )

            row[
                f"metric_coverage_ratio_{suffix}"
            ] = (
                len(present) / expected_count
                if expected_count
                else None
            )

            row[
                f"baseline_metric_presence_count_{suffix}"
            ] = len(baseline_present)

            row[
                f"baseline_metric_expected_count_{suffix}"
            ] = expected_count

            row[
                f"baseline_metric_missing_count_{suffix}"
            ] = max(
                expected_count
                - len(baseline_present),
                0,
            )

            row[
                f"baseline_metric_coverage_ratio_{suffix}"
            ] = (
                len(baseline_present)
                / expected_count
                if expected_count
                else None
            )

            # Uptime-specific handling.
            uptime_first = row.get(
                f"uptime_{suffix}_min"
            )
            uptime_last = row.get(
                f"uptime_{suffix}_last"
            )

            row[
                f"uptime_growth_sec_{suffix}"
            ] = (
                uptime_last - uptime_first
                if (
                    uptime_first is not None
                    and uptime_last is not None
                )
                else None
            )

            row[
                f"uptime_reset_flag_{suffix}"
            ] = int(
                (
                    uptime_first is not None
                    and uptime_last is not None
                    and uptime_last < uptime_first
                )
            )

            # Device health behavioral change.
            for metric in behavioral_device_metrics:

                recent_mean = row.get(
                    f"{metric}_{suffix}_mean"
                )
                base_mean = row.get(
                    f"{metric}_baseline_mean_{suffix}"
                )

                row.update(
                    behavior_change(
                        recent_mean,
                        base_mean,
                        f"{metric}_behavior_{suffix}",
                    )
                )

        # Interface aggregate for exact feature bucket.
        interface_aggregate = (
            aggregate_interface_rows_at_timestamp(
                interface_rows,
                bucket,
            )
        )

        row.update(interface_aggregate)

        for field in (
            "traffic_total_bps_sum",
            "packet_total_pps_sum",
            "error_total_rate_sum",
            "discard_total_rate_sum",
        ):
            row[f"{field}_present"] = int(
                row.get(field) is not None
            )

        if (
            not any_device_data
            and interface_aggregate[
                "interface_count"
            ] == 0
        ):
            bucket += bucket_sec
            continue

        output.append(row)
        bucket += bucket_sec

    return output
# ============================================================
# Main pipeline
# ============================================================


def resolve_default_input(path: str) -> Path:
    p = Path(path)
    if p.exists():
        return p

    # Helpful for the duplicated uploaded filename used during testing.
    alt = Path("transformed_history(2).jsonl")
    if path == DEFAULT_INPUT and alt.exists():
        return alt

    return p


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build AI-NOC interface/device feature vectors."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Transformed history JSONL",
    )
    parser.add_argument(
        "--metadata",
        default=DEFAULT_METADATA,
        help="Scoped metrics JSON",
    )
    parser.add_argument(
        "--interface-output",
        default=DEFAULT_INTERFACE_OUTPUT,
    )
    parser.add_argument(
        "--device-output",
        default=DEFAULT_DEVICE_OUTPUT,
    )
    parser.add_argument(
        "--audit-output",
        default=DEFAULT_AUDIT_OUTPUT,
    )
    parser.add_argument(
        "--bucket-sec",
        type=int,
        default=DEFAULT_BUCKET_SEC,
        help="Feature timestamp grid in seconds; default 60",
    )
    parser.add_argument(
        "--windows",
        default="300,900",
        help="Trailing windows in seconds, e.g. 300,900",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.bucket_sec <= 0:
        raise ValueError("--bucket-sec must be > 0")

    windows = tuple(
        sorted(
            {
                int(x.strip())
                for x in str(args.windows).split(",")
                if x.strip()
            }
        )
    )

    if not windows or any(x <= 0 for x in windows):
        raise ValueError("--windows must contain positive integers")

    input_path = resolve_default_input(args.input)
    metadata_path = Path(args.metadata)

    interface_output = Path(args.interface_output)
    device_output = Path(args.device_output)
    audit_output = Path(args.audit_output)

    print("=" * 72)
    print("AI-NOC FEATURE ENGINEERING")
    print("=" * 72)
    print(f"Input history     : {input_path}")
    print(f"Metadata          : {metadata_path}")
    print(f"Bucket            : {args.bucket_sec}s")
    print(
        "Windows           : "
        + ", ".join(f"{x}s" for x in windows)
    )

    if not input_path.exists():
        raise FileNotFoundError(
            f"History file not found: {input_path}"
        )

    if not metadata_path.exists():
        raise FileNotFoundError(
            f"Metadata file not found: {metadata_path}"
        )

    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------
    print("\n[1/7] Loading scoped metadata...")

    (
        item_map,
        expected_interface_metrics,
        expected_device_metrics,
    ) = load_scoped_metadata(metadata_path)

    print(
        f"Scoped items               : {len(item_map):,}"
    )
    print(
        f"Expected interfaces        : {len(expected_interface_metrics):,}"
    )
    print(
        f"Expected device metric maps: {len(expected_device_metrics):,}"
    )

    # --------------------------------------------------------
    # History
    # --------------------------------------------------------
    print("\n[2/7] Loading transformed history...")

    records, load_stats = load_transformed_history(
        input_path,
        item_map,
    )

    print(
        f"Accepted records           : {len(records):,}"
    )
    print(
        f"Parse errors               : {load_stats.get('parse_errors', 0):,}"
    )
    print(
        f"Missing metadata           : {load_stats.get('missing_metadata', 0):,}"
    )
    print(
        f"Unrelated records skipped : {load_stats.get('unrelated_records', 0):,}"
    )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------
    print("\n[3/7] Deduplicating item timestamps...")

    records, dedup_stats = deduplicate_records(records)

    print(
        f"Duplicate groups           : {dedup_stats['duplicate_groups']:,}"
    )
    print(
        f"Conflicting duplicate sets : {dedup_stats['conflicting_duplicate_groups']:,}"
    )

    # --------------------------------------------------------
    # Build series
    # --------------------------------------------------------
    print("\n[4/7] Building interface/device series...")

    interface_series, device_series = build_series(records)

    print(
        f"Interface entities         : {len(interface_series):,}"
    )
    print(
        f"Device entities            : {len(device_series):,}"
    )

    # Host information.
    host_info: dict[str, dict[str, Any]] = {}
    for r in records:
        host_info.setdefault(
            r["hostid"],
            {
                "host": r.get("host", ""),
                "host_name": r.get("host_name", ""),
                "device_role": r.get("device_role", ""),
            },
        )

    # --------------------------------------------------------
    # Interface feature construction
    # --------------------------------------------------------
    print("\n[5/7] Building interface feature vectors...")

    interface_rows: list[dict[str, Any]] = []

    interface_generation_stats = Counter()

    for key, series_map in sorted(interface_series.items()):
        hostid, ifindex = key
        expected = expected_interface_metrics.get(
            key,
            set(series_map.keys()),
        )

        rows = build_interface_features(
            interface_key=key,
            series_map=series_map,
            expected_metrics=expected,
            host_info=host_info.get(hostid, {}),
            bucket_sec=args.bucket_sec,
            windows=windows,
        )

        interface_rows.extend(rows)
        interface_generation_stats["entities"] += 1
        interface_generation_stats["rows"] += len(rows)

    interface_rows.sort(
        key=lambda r: (
            r["hostid"],
            r["ifindex"],
            r["timestamp"],
        )
    )

    print(
        f"Interface entities built   : {interface_generation_stats['entities']:,}"
    )
    print(
        f"Interface feature rows      : {interface_generation_stats['rows']:,}"
    )

    # Index interface rows by host for device aggregation.
    interface_rows_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in interface_rows:
        interface_rows_by_host[row["hostid"]].append(row)

    # --------------------------------------------------------
    # Device feature construction
    # --------------------------------------------------------
    print("\n[6/7] Building device feature vectors...")

    device_rows: list[dict[str, Any]] = []
    device_generation_stats = Counter()

    all_device_hostids = sorted(
        set(device_series.keys())
        | set(interface_rows_by_host.keys())
    )

    for hostid in all_device_hostids:
        rows = build_device_features(
            hostid=hostid,
            device_rows=device_series.get(hostid, []),
            interface_rows=interface_rows_by_host.get(hostid, []),
            expected_device_metrics=expected_device_metrics.get(
                hostid,
                set(),
            ),
            host_info=host_info.get(hostid, {}),
            bucket_sec=args.bucket_sec,
            windows=windows,
        )

        device_rows.extend(rows)
        device_generation_stats["entities"] += 1
        device_generation_stats["rows"] += len(rows)

    device_rows.sort(
        key=lambda r: (
            r["hostid"],
            r["timestamp"],
        )
    )

    print(
        f"Device entities built       : {device_generation_stats['entities']:,}"
    )
    print(
        f"Device feature rows         : {device_generation_stats['rows']:,}"
    )

    # --------------------------------------------------------
    # Auditing feature coverage
    # --------------------------------------------------------
    print("\n[7/7] Auditing feature coverage...")

    def row_numeric_count(row: dict[str, Any]) -> int:
        count = 0
        identity_fields = {
            "@timestamp",
            "timestamp",
            "hostid",
            "host",
            "host_name",
            "device_role",
            "ifindex",
            "entity_type",
        }

        for key, value in row.items():
            if key in identity_fields:
                continue

            if isinstance(value, bool):
                count += 1
            elif (
                isinstance(value, (int, float))
                and math.isfinite(float(value))
            ):
                count += 1

        return count

    interface_numeric_counts = [
        row_numeric_count(r)
        for r in interface_rows
    ]

    device_numeric_counts = [
        row_numeric_count(r)
        for r in device_rows
    ]

    interface_coverage_5m = [
        safe_float(
            r.get("metric_coverage_ratio_5m")
        )
        for r in interface_rows
        if r.get("metric_coverage_ratio_5m")
        is not None
    ]

    device_coverage_5m = [
        safe_float(
            r.get("metric_coverage_ratio_5m")
        )
        for r in device_rows
        if r.get("metric_coverage_ratio_5m")
        is not None
    ]

    interface_baseline_coverage_5m = [
        safe_float(
            r.get(
                "baseline_metric_coverage_ratio_5m"
            )
        )
        for r in interface_rows
        if r.get(
            "baseline_metric_coverage_ratio_5m"
        ) is not None
    ]

    device_baseline_coverage_5m = [
        safe_float(
            r.get(
                "baseline_metric_coverage_ratio_5m"
            )
        )
        for r in device_rows
        if r.get(
            "baseline_metric_coverage_ratio_5m"
        ) is not None
    ]

    reset_flag_rows = sum(
        1
        for r in interface_rows
        if r.get("counter_reset_flag_5m") == 1
    )

    oper_change_rows = sum(
        1
        for r in interface_rows
        if r.get("oper_status_change_flag_5m") == 1
    )

    interface_feature_names = sorted(
        key
        for key in (
            interface_rows[0].keys()
            if interface_rows
            else []
        )
        if key not in {
            "@timestamp",
            "timestamp",
            "hostid",
            "host",
            "host_name",
            "device_role",
            "ifindex",
            "entity_type",
        }
    )

    device_feature_names = sorted(
        key
        for key in (
            device_rows[0].keys()
            if device_rows
            else []
        )
        if key not in {
            "@timestamp",
            "timestamp",
            "hostid",
            "host",
            "host_name",
            "device_role",
            "entity_type",
        }
    )

    # Warm-up rows are intentionally retained in the feature store,
    # but are explicitly identified for the future ML training quality gate.
    interface_warmup_rows = sum(
        1
        for r in interface_rows
        if (
            r.get(
                "baseline_metric_coverage_ratio_5m"
            )
            in (None, 0)
        )
    )

    device_warmup_rows = sum(
        1
        for r in device_rows
        if (
            r.get(
                "baseline_metric_coverage_ratio_5m"
            )
            in (None, 0)
        )
    )

    audit = {
        "audit": {
            "name": "feature_engineering_audit",
            "version": "2.1",
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },

        "input": {
            "history_file": str(input_path),
            "metadata_file": str(metadata_path),
            "bucket_sec": args.bucket_sec,
            "windows_sec": list(windows),
        },

        "source": {
            "scoped_items": len(item_map),
            "history_records_after_filter": len(
                records
            ),
            "load_stats": load_stats,
            "deduplication": dedup_stats,
        },

        "entities": {
            "interface_entities": len(
                interface_series
            ),
            "device_entities": len(
                all_device_hostids
            ),
        },

        "outputs": {
            "interface_rows": len(
                interface_rows
            ),
            "device_rows": len(
                device_rows
            ),
            "interface_feature_count": len(
                interface_feature_names
            ),
            "device_feature_count": len(
                device_feature_names
            ),
        },

        "coverage": {
            "interface_5m": {
                "rows": len(
                    interface_coverage_5m
                ),
                "mean": mean(
                    interface_coverage_5m
                ),
                "min": min_value(
                    interface_coverage_5m
                ),
                "max": max_value(
                    interface_coverage_5m
                ),
            },

            "device_5m": {
                "rows": len(
                    device_coverage_5m
                ),
                "mean": mean(
                    device_coverage_5m
                ),
                "min": min_value(
                    device_coverage_5m
                ),
                "max": max_value(
                    device_coverage_5m
                ),
            },

            "interface_previous_baseline_5m": {
                "rows": len(
                    interface_baseline_coverage_5m
                ),
                "mean": mean(
                    interface_baseline_coverage_5m
                ),
                "min": min_value(
                    interface_baseline_coverage_5m
                ),
                "max": max_value(
                    interface_baseline_coverage_5m
                ),
                "warmup_rows": interface_warmup_rows,
            },

            "device_previous_baseline_5m": {
                "rows": len(
                    device_baseline_coverage_5m
                ),
                "mean": mean(
                    device_baseline_coverage_5m
                ),
                "min": min_value(
                    device_baseline_coverage_5m
                ),
                "max": max_value(
                    device_baseline_coverage_5m
                ),
                "warmup_rows": device_warmup_rows,
            },
        },

        "quality_signals": {
            "interface_rows_with_counter_reset_5m":
                reset_flag_rows,
            "interface_rows_with_oper_status_change_5m":
                oper_change_rows,
            "interface_warmup_rows_5m":
                interface_warmup_rows,
            "device_warmup_rows_5m":
                device_warmup_rows,
        },

        "feature_contract": {
            "interface_identity":
                "hostid + ifIndex",

            "recent_window":
                "(T-window, T]",

            "previous_window_baseline":
                "(T-2*window, T-window]",

            "behavior_change":
                (
                    "recent-window mean compared with the "
                    "immediately preceding equal-duration "
                    "baseline mean"
                ),

            "behavior_change_fields": [
                "change",
                "change_pct",
                "recent_to_baseline_ratio",
                "increase_flag",
                "decrease_flag",
            ],

            "counter_reset_policy":
                (
                    "Counter resets remain contextual quality "
                    "signals and are not converted into negative "
                    "traffic/error/discard rates."
                ),

            "missing_value_policy":
                (
                    "Missing metrics remain null in the feature "
                    "store and are tracked using metric coverage "
                    "and baseline coverage fields."
                ),

            "warmup_policy":
                (
                    "Rows without previous-window baseline are "
                    "retained for observability but should not "
                    "be used for ML training until a training "
                    "quality gate excludes insufficient-history rows."
                ),

            "future_leakage_policy":
                "Only past-looking windows are used.",
        },

        "feature_quality": {
            "interface_mean_numeric_features":
                mean(
                    [
                        float(x)
                        for x in interface_numeric_counts
                    ]
                ),
            "device_mean_numeric_features":
                mean(
                    [
                        float(x)
                        for x in device_numeric_counts
                    ]
                ),
        },

        "warnings": [],
    }

    if not interface_rows:
        audit["warnings"].append(
            "No interface feature rows were produced."
        )

    if not device_rows:
        audit["warnings"].append(
            "No device feature rows were produced."
        )

    if (
        interface_coverage_5m
        and mean(interface_coverage_5m) < 0.5
    ):
        audit["warnings"].append(
            "Mean interface 5m recent coverage is below 50%."
        )

    if (
        device_coverage_5m
        and mean(device_coverage_5m) < 0.5
    ):
        audit["warnings"].append(
            "Mean device 5m recent coverage is below 50%."
        )

    if interface_warmup_rows:
        audit["warnings"].append(
            (
                "Interface warm-up rows exist without a "
                f"previous 5m baseline: {interface_warmup_rows:,}."
            )
        )

    if device_warmup_rows:
        audit["warnings"].append(
            (
                "Device warm-up rows exist without a "
                f"previous 5m baseline: {device_warmup_rows:,}."
            )
        )

    # --------------------------------------------------------
    # Write outputs
    # --------------------------------------------------------
    print("\nWriting outputs...")

    interface_count = write_jsonl(
        interface_output,
        interface_rows,
    )

    device_count = write_jsonl(
        device_output,
        device_rows,
    )

    audit["output_files"] = {
        "interface_features": str(
            interface_output
        ),
        "device_features": str(
            device_output
        ),
        "audit": str(
            audit_output
        ),
    }

    write_json(
        audit_output,
        audit,
    )

    # --------------------------------------------------------
    # Console summary
    # --------------------------------------------------------
    print()
    print("=" * 72)
    print("FEATURE ENGINEERING COMPLETE")
    print("=" * 72)
    print(
        f"Source records              : {len(records):,}"
    )
    print(
        f"Interface entities          : {len(interface_series):,}"
    )
    print(
        f"Interface feature rows      : {interface_count:,}"
    )
    print(
        f"Device entities             : {len(all_device_hostids):,}"
    )
    print(
        f"Device feature rows         : {device_count:,}"
    )
    print(
        f"Interface feature count     : "
        f"{len(interface_feature_names):,}"
    )
    print(
        f"Device feature count        : "
        f"{len(device_feature_names):,}"
    )
    print(
        "Interface 5m coverage mean  : "
        + (
            f"{mean(interface_coverage_5m):.3f}"
            if interface_coverage_5m
            else "n/a"
        )
    )
    print(
        "Device 5m coverage mean     : "
        + (
            f"{mean(device_coverage_5m):.3f}"
            if device_coverage_5m
            else "n/a"
        )
    )
    print(
        "Interface baseline 5m mean : "
        + (
            f"{mean(interface_baseline_coverage_5m):.3f}"
            if interface_baseline_coverage_5m
            else "n/a"
        )
    )
    print(
        "Device baseline 5m mean    : "
        + (
            f"{mean(device_baseline_coverage_5m):.3f}"
            if device_baseline_coverage_5m
            else "n/a"
        )
    )
    print(
        f"Rows with counter reset 5m : {reset_flag_rows:,}"
    )
    print(
        f"Rows with operStatus change : {oper_change_rows:,}"
    )
    print(
        f"Interface warm-up rows      : {interface_warmup_rows:,}"
    )
    print(
        f"Device warm-up rows         : {device_warmup_rows:,}"
    )
    print()
    print(
        f"Interface output : {interface_output}"
    )
    print(
        f"Device output    : {device_output}"
    )
    print(
        f"Audit output     : {audit_output}"
    )
    print()
    print("STATUS : PASS")
    print("=" * 72)


if __name__ == "__main__":
    main()
