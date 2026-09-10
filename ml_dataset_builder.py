#!/usr/bin/env python3
"""
ml_dataset_builder.py

Build ML-ready training/inference matrices from the two feature-store
outputs produced by feature_engineering.py:

    interface_features.jsonl
    device_features.jsonl

Design goals
------------
- Preserve feature-store records; this script creates ML matrices separately.
- Do not use identifiers/timestamps/device labels as model features.
- Enforce a training quality gate:
    * previous-window baseline must exist
    * minimum recent coverage
    * minimum baseline coverage
    * all selected numeric features must be finite after imputation
- Keep missingness information where available.
- Use robust, deterministic median imputation for numeric features.
- Standardize features for Isolation Forest using a persisted scaler.
  Isolation Forest itself does not require scaling, but using the same
  preprocessing at training and inference avoids train/serve skew and makes
  later model changes easier.
- Split by time, not randomly, to avoid temporal leakage.
- Write JSONL feature-store subsets and CSV matrices.
- Persist the exact feature contract and preprocessing statistics.

Outputs
-------
ml_interface_train.csv
ml_interface_inference.csv
ml_device_train.csv
ml_device_inference.csv

ml_interface_train_meta.json
ml_interface_inference_meta.json
ml_device_train_meta.json
ml_device_inference_meta.json

ml_feature_schema.json
ml_dataset_audit.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------

DEFAULT_INTERFACE_FILE = "interface_features.jsonl"
DEFAULT_DEVICE_FILE = "device_features.jsonl"

DEFAULT_OUTPUT_DIR = "ml_dataset"

DEFAULT_RECENT_COVERAGE = 0.80
DEFAULT_BASELINE_COVERAGE = 0.80

# Training split is chronological.  The latest fraction becomes
# inference/holdout data.
DEFAULT_INFERENCE_FRACTION = 0.20

# Do not select extremely sparse features.
DEFAULT_MIN_FEATURE_PRESENCE = 0.80

# Fields that are metadata / identifiers and must never enter the model.
NON_FEATURE_FIELDS = {
    "@timestamp",
    "timestamp",
    "hostid",
    "host",
    "host_name",
    "device_role",
    "ifindex",
    "entity_type",
    "training_eligible",
    "ml_eligible",
    "feature_row_id",
}

# Quality/control fields are intentionally excluded from the initial
# Isolation Forest matrix.  Their information remains in the feature
# store and audit.
QUALITY_FIELDS = {
    "metric_presence_count_5m",
    "metric_expected_count_5m",
    "metric_missing_count_5m",
    "metric_coverage_ratio_5m",
    "baseline_metric_coverage_ratio_5m",
    "metric_presence_count_15m",
    "metric_expected_count_15m",
    "metric_missing_count_15m",
    "metric_coverage_ratio_15m",
    "counter_reset_count_5m",
    "counter_reset_flag_5m",
    "counter_reset_raw_context_sum_5m",
    "counter_reset_count_15m",
    "counter_reset_flag_15m",
    "counter_reset_raw_context_sum_15m",
    "oper_status_change_count_5m",
    "oper_status_change_flag_5m",
    "oper_status_change_count_15m",
    "oper_status_change_flag_15m",
    "uptime_reset_flag_5m",
    "uptime_reset_flag_15m",
}

# Initial model contract: behavioral/level features with clear network
# meaning.  We deliberately exclude raw metadata and most quality fields.
PREFERRED_BASE_FEATURES = {
    # 5m levels
    "in_bps_5m_mean",
    "out_bps_5m_mean",
    "in_pps_5m_mean",
    "out_pps_5m_mean",
    "in_error_rate_5m_mean",
    "out_error_rate_5m_mean",
    "in_discard_rate_5m_mean",
    "out_discard_rate_5m_mean",
    "traffic_total_bps_5m",
    "packet_total_pps_5m",
    "error_total_rate_5m",
    "discard_total_rate_5m",
    "in_out_bps_ratio_5m",
    "in_out_pps_ratio_5m",
    "traffic_variability_5m",
    "oper_status_last",

    # 15m levels
    "in_bps_15m_mean",
    "out_bps_15m_mean",
    "in_pps_15m_mean",
    "out_pps_15m_mean",
    "in_error_rate_15m_mean",
    "out_error_rate_15m_mean",
    "in_discard_rate_15m_mean",
    "out_discard_rate_15m_mean",
    "traffic_total_bps_15m",
    "packet_total_pps_15m",
    "error_total_rate_15m",
    "discard_total_rate_15m",
    "in_out_bps_ratio_15m",
    "in_out_pps_ratio_15m",

    # Recent-vs-baseline behavior
    "in_bps_behavior_5m_change",
    "in_bps_behavior_5m_change_pct",
    "in_bps_behavior_5m_recent_to_baseline_ratio",
    "out_bps_behavior_5m_change",
    "out_bps_behavior_5m_change_pct",
    "out_bps_behavior_5m_recent_to_baseline_ratio",
    "in_pps_behavior_5m_change",
    "in_pps_behavior_5m_change_pct",
    "in_pps_behavior_5m_recent_to_baseline_ratio",
    "out_pps_behavior_5m_change",
    "out_pps_behavior_5m_change_pct",
    "out_pps_behavior_5m_recent_to_baseline_ratio",
    "error_total_rate_behavior_5m_change",
    "error_total_rate_behavior_5m_change_pct",
    "error_total_rate_behavior_5m_recent_to_baseline_ratio",
    "discard_total_rate_behavior_5m_change",
    "discard_total_rate_behavior_5m_change_pct",
    "discard_total_rate_behavior_5m_recent_to_baseline_ratio",
    "traffic_total_bps_behavior_5m_change",
    "traffic_total_bps_behavior_5m_change_pct",
    "traffic_total_bps_behavior_5m_recent_to_baseline_ratio",
    "packet_total_pps_behavior_5m_change",
    "packet_total_pps_behavior_5m_change_pct",
    "packet_total_pps_behavior_5m_recent_to_baseline_ratio",

    # Device health (device matrix)
    "cpu_pct_5m_mean",
    "memory_pct_5m_mean",
    "temperature_c_5m_mean",
    "icmp_loss_pct_5m_mean",
    "icmp_rtt_sec_5m_mean",
    "uptime_growth_sec_5m",
    "cpu_pct_15m_mean",
    "memory_pct_15m_mean",
    "temperature_c_15m_mean",
    "icmp_loss_pct_15m_mean",
    "icmp_rtt_sec_15m_mean",
    "uptime_growth_sec_15m",
    "interface_count",
    "interfaces_with_oper_down",
    "traffic_total_bps_sum",
    "traffic_total_bps_mean",
    "traffic_total_bps_max",
    "packet_total_pps_sum",
    "packet_total_pps_mean",
    "packet_total_pps_max",
    "error_total_rate_sum",
    "error_total_rate_max",
    "discard_total_rate_sum",
    "discard_total_rate_max",
    "interfaces_with_counter_reset",
}


def finite_float(value: Any) -> float | None:
    try:
        x = float(value)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    errors = 0
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    errors += 1
                    continue
                rows.append(row)
            except json.JSONDecodeError:
                errors += 1
    return rows, errors


def numeric_feature_candidates(rows: list[dict[str, Any]]) -> Counter:
    presence = Counter()
    for row in rows:
        for key, value in row.items():
            if key in NON_FEATURE_FIELDS or key in QUALITY_FIELDS:
                continue
            if isinstance(value, bool):
                continue
            if finite_float(value) is not None:
                presence[key] += 1
    return presence


def choose_features(
    rows: list[dict[str, Any]],
    min_presence: float,
    entity_type: str,
) -> tuple[list[str], dict[str, Any]]:
    presence = numeric_feature_candidates(rows)
    n = len(rows)

    selected = []
    excluded = {}

    for key, count in sorted(presence.items()):
        ratio = count / n if n else 0.0

        if ratio < min_presence:
            excluded[key] = {
                "reason": "below_min_presence",
                "presence": count,
                "presence_ratio": ratio,
            }
            continue

        if key in PREFERRED_BASE_FEATURES:
            selected.append(key)

    # If a feature contract member is not present, note it explicitly.
    missing_contract = sorted(
        key
        for key in PREFERRED_BASE_FEATURES
        if key not in presence
    )

    # Do not force absent features into the matrix.
    selected = sorted(set(selected))

    details = {
        "entity_type": entity_type,
        "rows": n,
        "candidate_numeric_features": len(presence),
        "selected_features": len(selected),
        "min_presence": min_presence,
        "missing_contract_features": missing_contract,
        "excluded_feature_count": len(excluded),
        "presence": {
            key: {
                "count": count,
                "ratio": count / n if n else 0.0,
            }
            for key, count in sorted(presence.items())
        },
        "excluded": excluded,
    }

    return selected, details


def chronological_sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            int(r.get("timestamp", 0) or 0),
            str(r.get("hostid", "")),
            str(r.get("ifindex", "")),
        ),
    )


def quality_gate(
    row: dict[str, Any],
    recent_coverage: float,
    baseline_coverage: float,
) -> tuple[bool, list[str]]:
    reasons = []

    recent = finite_float(
        row.get("metric_coverage_ratio_5m")
    )
    baseline = finite_float(
        row.get("baseline_metric_coverage_ratio_5m")
    )

    if recent is None:
        reasons.append("missing_recent_coverage")
    elif recent < recent_coverage:
        reasons.append("recent_coverage_below_threshold")

    if baseline is None:
        reasons.append("missing_baseline_coverage")
    elif baseline < baseline_coverage:
        reasons.append("baseline_coverage_below_threshold")

    # Explicitly reject warm-up rows where the baseline does not exist.
    baseline_count = finite_float(
        row.get("baseline_metric_coverage_ratio_5m")
    )
    if baseline_count is None or baseline_count <= 0:
        reasons.append("no_previous_window_baseline")

    return not reasons, reasons


def split_timewise(
    rows: list[dict[str, Any]],
    inference_fraction: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not rows:
        return [], []

    inference_fraction = min(max(inference_fraction, 0.05), 0.50)

    cut = int(len(rows) * (1.0 - inference_fraction))

    # Keep both sides non-empty if possible.
    if len(rows) >= 2:
        cut = min(max(cut, 1), len(rows) - 1)

    return rows[:cut], rows[cut:]


def build_imputation_stats(
    rows: list[dict[str, Any]],
    features: list[str],
) -> dict[str, float]:
    stats = {}

    for feature in features:
        values = [
            finite_float(row.get(feature))
            for row in rows
        ]
        values = [v for v in values if v is not None]

        if values:
            stats[feature] = float(statistics.median(values))
        else:
            stats[feature] = 0.0

    return stats


def zscore_parameters(
    rows: list[dict[str, Any]],
    features: list[str],
    medians: dict[str, float],
) -> dict[str, dict[str, float]]:
    params = {}

    for feature in features:
        values = []

        for row in rows:
            value = finite_float(row.get(feature))
            if value is None:
                value = medians[feature]
            values.append(value)

        if not values:
            params[feature] = {
                "mean": 0.0,
                "std": 1.0,
            }
            continue

        mean = statistics.fmean(values)

        if len(values) >= 2:
            std = statistics.pstdev(values)
        else:
            std = 0.0

        if not math.isfinite(std) or std < 1e-12:
            std = 1.0

        params[feature] = {
            "mean": float(mean),
            "std": float(std),
        }

    return params


def transform_rows(
    rows: list[dict[str, Any]],
    features: list[str],
    medians: dict[str, float],
    scaling: dict[str, dict[str, float]],
) -> list[list[float]]:
    matrix = []

    for row in rows:
        vector = []

        for feature in features:
            value = finite_float(row.get(feature))

            if value is None:
                value = medians[feature]

            mean = scaling[feature]["mean"]
            std = scaling[feature]["std"]

            transformed = (value - mean) / std

            if not math.isfinite(transformed):
                transformed = 0.0

            vector.append(float(transformed))

        matrix.append(vector)

    return matrix


def write_csv(
    path: Path,
    rows: list[list[float]],
    features: list[str],
) -> None:
    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.writer(f)
        writer.writerow(features)
        for row in rows:
            writer.writerow(
                [
                    f"{value:.12g}"
                    for value in row
                ]
            )


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False,
        )


def write_metadata(
    path: Path,
    entity_type: str,
    split_name: str,
    source_rows: list[dict[str, Any]],
    eligible_rows: list[dict[str, Any]],
    features: list[str],
    medians: dict[str, float],
    scaling: dict[str, dict[str, float]],
) -> None:
    timestamps = [
        int(row["timestamp"])
        for row in eligible_rows
        if row.get("timestamp") is not None
    ]

    meta = {
        "entity_type": entity_type,
        "split": split_name,
        "row_count": len(eligible_rows),
        "source_row_count": len(source_rows),
        "features": features,
        "feature_count": len(features),
        "timestamp_range": {
            "min": min(timestamps) if timestamps else None,
            "max": max(timestamps) if timestamps else None,
        },
        "imputation": {
            "method": "median",
            "medians": medians,
        },
        "scaling": {
            "method": "zscore",
            "parameters": scaling,
        },
        "excluded_fields": sorted(
            NON_FEATURE_FIELDS | QUALITY_FIELDS
        ),
    }

    write_json(path, meta)


def build_entity_dataset(
    input_path: Path,
    entity_type: str,
    out_dir: Path,
    recent_coverage: float,
    baseline_coverage: float,
    inference_fraction: float,
    min_presence: float,
) -> dict[str, Any]:
    rows, parse_errors = load_jsonl(input_path)
    rows = chronological_sort(rows)

    # Quality gate.
    eligible = []
    excluded_counts = Counter()

    for row in rows:
        ok, reasons = quality_gate(
            row,
            recent_coverage=recent_coverage,
            baseline_coverage=baseline_coverage,
        )

        if ok:
            row_copy = dict(row)
            row_copy["training_eligible"] = 1
            eligible.append(row_copy)
        else:
            row_copy = dict(row)
            row_copy["training_eligible"] = 0
            for reason in reasons:
                excluded_counts[reason] += 1

    # Feature selection happens after quality gate to avoid selecting
    # features based on warm-up/insufficient-history rows.
    features, selection = choose_features(
        eligible,
        min_presence=min_presence,
        entity_type=entity_type,
    )

    train_rows, inference_rows = split_timewise(
        eligible,
        inference_fraction=inference_fraction,
    )

    # IMPORTANT:
    # Imputation/scaling statistics are fit ONLY on train rows.
    # This avoids leakage from the future holdout/inference period.
    medians = build_imputation_stats(
        train_rows,
        features,
    )

    scaling = zscore_parameters(
        train_rows,
        features,
        medians,
    )

    train_matrix = transform_rows(
        train_rows,
        features,
        medians,
        scaling,
    )

    inference_matrix = transform_rows(
        inference_rows,
        features,
        medians,
        scaling,
    )

    prefix = "interface" if entity_type == "interface" else "device"

    train_csv = out_dir / f"ml_{prefix}_train.csv"
    inference_csv = out_dir / f"ml_{prefix}_inference.csv"

    train_meta = out_dir / f"ml_{prefix}_train_meta.json"
    inference_meta = out_dir / f"ml_{prefix}_inference_meta.json"

    write_csv(
        train_csv,
        train_matrix,
        features,
    )

    write_csv(
        inference_csv,
        inference_matrix,
        features,
    )

    write_metadata(
        train_meta,
        entity_type,
        "train",
        eligible,
        train_rows,
        features,
        medians,
        scaling,
    )

    write_metadata(
        inference_meta,
        entity_type,
        "inference",
        eligible,
        inference_rows,
        features,
        medians,
        scaling,
    )

    return {
        "input_file": str(input_path),
        "entity_type": entity_type,
        "source_rows": len(rows),
        "eligible_rows": len(eligible),
        "excluded_rows": len(rows) - len(eligible),
        "parse_errors": parse_errors,
        "training_rows": len(train_rows),
        "inference_rows": len(inference_rows),
        "feature_count": len(features),
        "features": features,
        "quality_gate": {
            "recent_coverage_min": recent_coverage,
            "baseline_coverage_min": baseline_coverage,
            "excluded_reason_counts": dict(excluded_counts),
        },
        "feature_selection": selection,
        "outputs": {
            "train_csv": str(train_csv),
            "inference_csv": str(inference_csv),
            "train_meta": str(train_meta),
            "inference_meta": str(inference_meta),
        },
        "preprocessing": {
            "imputation": "median",
            "scaling": "zscore",
            "fit_on": "training_rows_only",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build ML-ready training/inference matrices from "
            "interface_features.jsonl and device_features.jsonl."
        )
    )

    parser.add_argument(
        "--interface-input",
        default=DEFAULT_INTERFACE_FILE,
    )

    parser.add_argument(
        "--device-input",
        default=DEFAULT_DEVICE_FILE,
    )

    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
    )

    parser.add_argument(
        "--recent-coverage",
        type=float,
        default=DEFAULT_RECENT_COVERAGE,
    )

    parser.add_argument(
        "--baseline-coverage",
        type=float,
        default=DEFAULT_BASELINE_COVERAGE,
    )

    parser.add_argument(
        "--inference-fraction",
        type=float,
        default=DEFAULT_INFERENCE_FRACTION,
    )

    parser.add_argument(
        "--min-feature-presence",
        type=float,
        default=DEFAULT_MIN_FEATURE_PRESENCE,
    )

    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 76)
    print("ML DATASET BUILDER")
    print("=" * 76)

    print()
    print("Configuration")
    print("-" * 76)
    print(
        f"Recent coverage minimum   : "
        f"{args.recent_coverage:.2f}"
    )
    print(
        f"Baseline coverage minimum : "
        f"{args.baseline_coverage:.2f}"
    )
    print(
        f"Inference fraction        : "
        f"{args.inference_fraction:.2f}"
    )
    print(
        f"Feature presence minimum  : "
        f"{args.min_feature_presence:.2f}"
    )
    print(
        "Split strategy             : chronological"
    )
    print(
        "Imputation                : median fit on train"
    )
    print(
        "Scaling                   : z-score fit on train"
    )

    print()
    print("Building interface dataset...")
    interface_result = build_entity_dataset(
        input_path=Path(args.interface_input),
        entity_type="interface",
        out_dir=out_dir,
        recent_coverage=args.recent_coverage,
        baseline_coverage=args.baseline_coverage,
        inference_fraction=args.inference_fraction,
        min_presence=args.min_feature_presence,
    )

    print(
        f"  Source rows     : "
        f"{interface_result['source_rows']:,}"
    )
    print(
        f"  Eligible rows   : "
        f"{interface_result['eligible_rows']:,}"
    )
    print(
        f"  Train rows      : "
        f"{interface_result['training_rows']:,}"
    )
    print(
        f"  Inference rows  : "
        f"{interface_result['inference_rows']:,}"
    )
    print(
        f"  Features        : "
        f"{interface_result['feature_count']:,}"
    )

    print()
    print("Building device dataset...")
    device_result = build_entity_dataset(
        input_path=Path(args.device_input),
        entity_type="device",
        out_dir=out_dir,
        recent_coverage=args.recent_coverage,
        baseline_coverage=args.baseline_coverage,
        inference_fraction=args.inference_fraction,
        min_presence=args.min_feature_presence,
    )

    print(
        f"  Source rows     : "
        f"{device_result['source_rows']:,}"
    )
    print(
        f"  Eligible rows   : "
        f"{device_result['eligible_rows']:,}"
    )
    print(
        f"  Train rows      : "
        f"{device_result['training_rows']:,}"
    )
    print(
        f"  Inference rows  : "
        f"{device_result['inference_rows']:,}"
    )
    print(
        f"  Features        : "
        f"{device_result['feature_count']:,}"
    )

    # ------------------------------------------------------------------
    # Global schema
    # ------------------------------------------------------------------

    schema = {
        "version": "1.0",
        "purpose": (
            "ML-ready numeric matrices for Isolation Forest."
        ),
        "entity_models": {
            "interface": {
                "input_feature_store": DEFAULT_INTERFACE_FILE,
                "features": interface_result["features"],
            },
            "device": {
                "input_feature_store": DEFAULT_DEVICE_FILE,
                "features": device_result["features"],
            },
        },
        "quality_gate": {
            "recent_coverage_min": args.recent_coverage,
            "baseline_coverage_min": args.baseline_coverage,
            "warmup_rows_excluded_from_training": True,
        },
        "preprocessing": {
            "missing_values": {
                "method": "median",
                "fit_scope": "training_rows_only",
            },
            "scaling": {
                "method": "zscore",
                "fit_scope": "training_rows_only",
            },
        },
        "leakage_policy": {
            "time_split": "chronological",
            "future_rows_used_for_fit": False,
            "identifiers_as_features": False,
        },
        "counter_reset_policy": (
            "Counter reset signals remain contextual features in "
            "the feature store; they are not converted into negative "
            "traffic/error/discard rates."
        ),
    }

    schema_path = out_dir / "ml_feature_schema.json"
    write_json(
        schema_path,
        schema,
    )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    audit = {
        "builder": {
            "script": "ml_dataset_builder.py",
            "version": "1.0",
        },
        "configuration": {
            "recent_coverage_min": args.recent_coverage,
            "baseline_coverage_min": args.baseline_coverage,
            "inference_fraction": args.inference_fraction,
            "min_feature_presence": args.min_feature_presence,
        },
        "interface": interface_result,
        "device": device_result,
        "global": {
            "status": "PASS",
            "notes": [
                (
                    "Training preprocessing statistics are fit only "
                    "on chronological training rows."
                ),
                (
                    "Warm-up/insufficient-history rows are retained "
                    "in the original feature store but excluded from "
                    "the ML matrix."
                ),
                (
                    "The interface and device models are kept separate "
                    "because their feature semantics differ."
                ),
            ],
        },
        "outputs": {
            "feature_schema": str(schema_path),
        },
    }

    audit_path = out_dir / "ml_dataset_audit.json"
    write_json(
        audit_path,
        audit,
    )

    print()
    print("=" * 76)
    print("OUTPUT")
    print("=" * 76)
    print(f"Directory : {out_dir.resolve()}")
    print(f"Schema    : {schema_path}")
    print(f"Audit     : {audit_path}")
    print()
    print("Status : PASS")
    print("=" * 76)


if __name__ == "__main__":
    main()
