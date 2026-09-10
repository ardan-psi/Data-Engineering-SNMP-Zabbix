"""
Raw Cross-Metric Audit
======================

Tujuan:
    Memvalidasi semantic transformation counter berdasarkan RAW Zabbix history.

Prinsip:
    - raw_history.jsonl adalah source of truth
    - semantic_metrics.json memberikan metadata item
    - host + ifIndex digunakan sebagai identity interface
    - TIDAK menggunakan Zabbix interfaceid sebagai interface identity
    - Tidak menganggap counter decrease sebagai anomaly
    - Tidak mengubah transformer
    - Hanya melakukan validasi final sebelum feature engineering

Audit:
    1. Load semantic metrics
    2. Load raw history
    3. Map item -> semantic metadata
    4. Parse hostid + ifIndex
    5. Group raw counters per host/interface/metric
    6. Detect raw counter decreases
    7. Correlate dengan cumulative counters lain
    8. Check operStatus
    9. Check timestamp clustering
    10. Produce final recommendation

Output:
    raw_cross_metric_audit.json
"""

from __future__ import annotations

import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

SEMANTIC_FILE = BASE_DIR / "semantic_metrics.json"
RAW_HISTORY_FILE = BASE_DIR / "raw_history.jsonl"
OUTPUT_FILE = BASE_DIR / "raw_cross_metric_audit.json"

# Correlation window.
#
# Kita gunakan window kecil agar tidak menghubungkan
# event yang sebenarnya tidak berhubungan.
CORRELATION_WINDOW_SEC = 5

# Counter yang menjadi fokus audit.
DISCARD_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
}

# Counter cumulative lain yang relevan.
RELATED_COUNTER_METRICS = {
    "in_bps",
    "out_bps",
    "in_error_rate",
    "out_error_rate",
    "in_pps",
    "out_pps",
    "interface_counter",
}

# Oper status bukan counter.
OPER_STATUS_METRIC = "oper_status"


# ============================================================
# HELPERS
# ============================================================

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"[WARN] Invalid JSON at line {line_number}: {exc}"
                )


def safe_float(value: Any) -> float | None:
    try:
        value = float(value)

        if not math.isfinite(value):
            return None

        return value

    except (TypeError, ValueError):
        return None


def parse_ifindex(key: str | None) -> int | None:
    """
    Parse standard IF-MIB ifIndex from Zabbix key.

    Examples:

        net.if.in[ifHCInOctets.34]
        net.if.out.discards[ifOutDiscards.5]
        net.if.in.errors[ifInErrors.33]

    Returns:
        34
        5
        33
    """

    if not key:
        return None

    match = re.search(r"\.(\d+)\]$", key)

    if not match:
        return None

    return int(match.group(1))


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    index = (len(values) - 1) * p
    lower = math.floor(index)
    upper = math.ceil(index)

    if lower == upper:
        return values[lower]

    weight = index - lower

    return values[lower] * (1 - weight) + values[upper] * weight


# ============================================================
# LOAD SEMANTIC METADATA
# ============================================================

print("=" * 72)
print("RAW CROSS-METRIC AUDIT")
print("=" * 72)

print("\nLoading semantic metrics...")

semantic_data = load_json(SEMANTIC_FILE)

if isinstance(semantic_data, list):
    semantic_metrics = semantic_data

elif isinstance(semantic_data, dict):
    if "metrics" in semantic_data:
        semantic_metrics = semantic_data["metrics"]
    else:
        raise ValueError(
            "semantic_metrics.json is an object but does not contain 'metrics'"
        )

else:
    raise ValueError("Unsupported semantic_metrics.json structure")


item_map: dict[str, dict[str, Any]] = {}

duplicate_itemids = 0

for metric in semantic_metrics:
    itemid = str(metric.get("itemid", "")).strip()

    if not itemid:
        continue

    if itemid in item_map:
        duplicate_itemids += 1

    item_map[itemid] = metric


print(f"Semantic metrics : {len(semantic_metrics):,}")
print(f"Item map         : {len(item_map):,}")
print(f"Duplicate itemid : {duplicate_itemids:,}")


# ============================================================
# LOAD RAW HISTORY
# ============================================================

print("\nLoading raw history...")

raw_records: list[dict[str, Any]] = []

missing_semantic = 0
invalid_raw_records = 0

for record in load_jsonl(RAW_HISTORY_FILE):

    itemid = str(record.get("itemid", "")).strip()

    if not itemid:
        invalid_raw_records += 1
        continue

    metadata = item_map.get(itemid)

    if metadata is None:
        missing_semantic += 1
        continue

    value = safe_float(record.get("value"))

    if value is None:
        continue

    clock = record.get("clock")

    try:
        clock = int(clock)
    except (TypeError, ValueError):
        invalid_raw_records += 1
        continue

    semantic_type = metadata.get("semantic_type")
    canonical_metric = metadata.get("canonical_metric")

    hostid = str(
        record.get("hostid")
        or metadata.get("hostid")
        or ""
    ).strip()

    host = (
        record.get("host")
        or metadata.get("host")
        or ""
    )

    host_name = (
        record.get("host_name")
        or metadata.get("host_name")
        or host
    )

    key = (
        metadata.get("key")
        or record.get("key")
        or ""
    )

    ifindex = parse_ifindex(key)

    raw_records.append(
        {
            "itemid": itemid,
            "hostid": hostid,
            "host": host,
            "host_name": host_name,
            "clock": clock,
            "value": value,
            "canonical_metric": canonical_metric,
            "semantic_type": semantic_type,
            "key": key,
            "ifindex": ifindex,
            "device_role": (
                record.get("device_role")
                or metadata.get("device_role")
                or ""
            ),
        }
    )


print(f"Raw records       : {len(raw_records):,}")
print(f"Missing semantic  : {missing_semantic:,}")
print(f"Invalid records   : {invalid_raw_records:,}")


# ============================================================
# FILTER RELEVANT METRICS
# ============================================================

relevant_metrics = (
    DISCARD_METRICS
    | RELATED_COUNTER_METRICS
    | {OPER_STATUS_METRIC}
)

relevant_records = [
    r
    for r in raw_records
    if r["canonical_metric"] in relevant_metrics
]


print(f"Relevant records  : {len(relevant_records):,}")


# ============================================================
# BUILD INDEX
# ============================================================

print("\nBuilding raw interface/metric index...")

# Key:
#   (hostid, ifindex, canonical_metric)
#
# Value:
#   sorted raw samples
#
interface_metric: dict[
    tuple[str, int, str],
    list[dict[str, Any]]
] = defaultdict(list)


for record in relevant_records:

    hostid = record["hostid"]
    ifindex = record["ifindex"]
    metric = record["canonical_metric"]

    if not hostid:
        continue

    if ifindex is None:
        continue

    interface_metric[
        (hostid, ifindex, metric)
    ].append(record)


for key in interface_metric:
    interface_metric[key].sort(
        key=lambda x: x["clock"]
    )


interfaces = sorted(
    {
        (hostid, ifindex)
        for hostid, ifindex, metric
        in interface_metric
    }
)


print(f"Interfaces        : {len(interfaces):,}")


# ============================================================
# RAW COUNTER DECREASE DETECTION
# ============================================================

print("\nDetecting raw discard counter decreases...")

reset_events: list[dict[str, Any]] = []


for (hostid, ifindex, metric), samples in interface_metric.items():

    if metric not in DISCARD_METRICS:
        continue

    previous = None

    for current in samples:

        if previous is None:
            previous = current
            continue

        previous_clock = previous["clock"]
        current_clock = current["clock"]

        # Ignore duplicate timestamps.
        if current_clock == previous_clock:
            previous = current
            continue

        # Ignore out-of-order records.
        if current_clock < previous_clock:
            previous = current
            continue

        previous_value = previous["value"]
        current_value = current["value"]

        if current_value < previous_value:

            delta = current_value - previous_value

            decrease_ratio = None

            if previous_value != 0:
                decrease_ratio = (
                    abs(delta) / abs(previous_value)
                )

            reset_events.append(
                {
                    "hostid": hostid,
                    "host": current["host"],
                    "host_name": current["host_name"],
                    "device_role": current["device_role"],
                    "ifindex": ifindex,
                    "canonical_metric": metric,
                    "itemid": current["itemid"],
                    "clock": current_clock,
                    "timestamp": current.get("timestamp"),
                    "previous_clock": previous_clock,
                    "previous_value": previous_value,
                    "current_value": current_value,
                    "delta": delta,
                    "decrease_ratio": decrease_ratio,
                }
            )

        previous = current


print(f"Discard decreases : {len(reset_events):,}")


# ============================================================
# CORRELATION HELPERS
# ============================================================

def get_samples_near(
    hostid: str,
    ifindex: int,
    metric: str,
    center_clock: int,
    window: int = CORRELATION_WINDOW_SEC,
):
    samples = interface_metric.get(
        (hostid, ifindex, metric),
        [],
    )

    result = []

    for sample in samples:

        distance = abs(
            sample["clock"] - center_clock
        )

        if distance <= window:
            result.append(
                (
                    distance,
                    sample,
                )
            )

    result.sort(key=lambda x: x[0])

    return result


# ============================================================
# CROSS-METRIC RAW ANALYSIS
# ============================================================

print("\nCorrelating raw counters...")

classification_counter = Counter()
confidence_counter = Counter()

cross_metric_decrease_counter = Counter()
cross_metric_event_counter = Counter()

oper_status_change_count = 0

host_counter = Counter()
interface_counter = Counter()

event_results: list[dict[str, Any]] = []


for event in reset_events:

    hostid = event["hostid"]
    ifindex = event["ifindex"]
    clock = event["clock"]

    correlated = {}

    multiple_counter_decrease = False
    discard_only = True

    related_decreases = []

    # --------------------------------------------------------
    # Check OTHER raw cumulative counters
    # --------------------------------------------------------

    for metric in RELATED_COUNTER_METRICS:

        samples = interface_metric.get(
            (hostid, ifindex, metric),
            [],
        )

        if not samples:
            continue

        # Find sample at or before event.
        previous = None
        current = None

        for sample in samples:

            if sample["clock"] <= clock:
                previous = sample
                continue

            if sample["clock"] > clock:
                current = sample
                break

        # Need both sides.
        if previous is None or current is None:
            continue

        delta_time = (
            current["clock"]
            - previous["clock"]
        )

        if delta_time <= 0:
            continue

        delta = (
            current["value"]
            - previous["value"]
        )

        correlated[metric] = {
            "previous_value": previous["value"],
            "current_value": current["value"],
            "delta": delta,
            "previous_clock": previous["clock"],
            "current_clock": current["clock"],
            "delta_time_sec": delta_time,
        }

        cross_metric_event_counter[metric] += 1

        if delta < 0:

            multiple_counter_decrease = True
            discard_only = False

            related_decreases.append(metric)

            cross_metric_decrease_counter[metric] += 1

    # --------------------------------------------------------
    # Check operStatus
    # --------------------------------------------------------

    oper_status_samples = get_samples_near(
        hostid,
        ifindex,
        OPER_STATUS_METRIC,
        clock,
        window=CORRELATION_WINDOW_SEC,
    )

    oper_status_change = False

    if len(oper_status_samples) >= 2:

        values = [
            sample["value"]
            for _, sample in oper_status_samples
        ]

        if len(set(values)) > 1:
            oper_status_change = True

    if oper_status_change:
        oper_status_change_count += 1

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if oper_status_change:

        classification = "interface_status_event"
        confidence = "high"

    elif multiple_counter_decrease:

        classification = "multiple_raw_counter_decrease"
        confidence = "high"

    else:

        classification = "discard_counter_only"
        confidence = "medium"

    classification_counter[classification] += 1
    confidence_counter[confidence] += 1

    host_counter[event["host_name"]] += 1

    interface_counter[
        (
            event["host_name"],
            event["ifindex"],
        )
    ] += 1

    event_results.append(
        {
            **event,
            "classification": classification,
            "confidence": confidence,
            "multiple_counter_decrease": (
                multiple_counter_decrease
            ),
            "discard_only": discard_only,
            "related_counter_decreases": (
                related_decreases
            ),
            "correlated_raw_metrics": correlated,
            "oper_status_change": oper_status_change,
        }
    )


# ============================================================
# TIMESTAMP CLUSTER ANALYSIS
# ============================================================

print("\nAnalyzing timestamp clustering...")

events_by_timestamp: dict[
    int,
    list[dict[str, Any]]
] = defaultdict(list)


for event in reset_events:
    events_by_timestamp[
        event["clock"]
    ].append(event)


same_timestamp_events = 0
multi_interface_clusters = 0

timestamp_cluster_details = []


for clock, events in events_by_timestamp.items():

    unique_interfaces = {
        (
            event["hostid"],
            event["ifindex"],
        )
        for event in events
    }

    if len(events) > 1:

        same_timestamp_events += len(events)

    if len(unique_interfaces) >= 2:

        multi_interface_clusters += 1

        timestamp_cluster_details.append(
            {
                "clock": clock,
                "timestamp": events[0].get("timestamp"),
                "events": len(events),
                "interfaces": len(unique_interfaces),
                "hosts": len(
                    {
                        event["hostid"]
                        for event in events
                    }
                ),
            }
        )


timestamp_cluster_details.sort(
    key=lambda x: x["events"],
    reverse=True,
)


# ============================================================
# RESET MAGNITUDE STATISTICS
# ============================================================

magnitudes = [
    abs(event["delta"])
    for event in reset_events
]

ratios = [
    event["decrease_ratio"]
    for event in reset_events
    if event["decrease_ratio"] is not None
]


magnitude_stats = {}

if magnitudes:

    magnitude_stats = {
        "count": len(magnitudes),
        "min": min(magnitudes),
        "max": max(magnitudes),
        "mean": statistics.mean(magnitudes),
        "median": statistics.median(magnitudes),
        "p95": percentile(magnitudes, 0.95),
        "p99": percentile(magnitudes, 0.99),
    }


ratio_stats = {}

if ratios:

    ratio_stats = {
        "count": len(ratios),
        "min": min(ratios),
        "max": max(ratios),
        "mean": statistics.mean(ratios),
        "median": statistics.median(ratios),
        "p95": percentile(ratios, 0.95),
        "p99": percentile(ratios, 0.99),
    }


# ============================================================
# FINAL CLASSIFICATION
# ============================================================

total_events = len(reset_events)

multiple_counter = classification_counter[
    "multiple_raw_counter_decrease"
]

discard_only = classification_counter[
    "discard_counter_only"
]

interface_events = classification_counter[
    "interface_status_event"
]


if total_events == 0:

    overall_classification = "no_raw_counter_decrease"

elif interface_events > 0:

    overall_classification = (
        "counter_decrease_with_interface_events"
    )

elif multiple_counter > 0:

    overall_classification = (
        "multiple_raw_counter_behavior"
    )

else:

    overall_classification = (
        "discard_counter_only_behavior"
    )


# ============================================================
# FEATURE ENGINEERING READINESS
# ============================================================

#
# Important:
#
# We do NOT require zero reset/decrease events.
#
# We only require:
#
#   - no invalid records
#   - semantic mapping exists
#   - raw values numeric
#   - transformation logic can handle decreases
#   - no evidence that transformer must be changed
#

fatal_issues = []

warnings = []


if duplicate_itemids:
    fatal_issues.append(
        f"Duplicate itemids: {duplicate_itemids}"
    )


if missing_semantic:
    fatal_issues.append(
        f"Raw records missing semantic metadata: "
        f"{missing_semantic}"
    )


if invalid_raw_records:
    fatal_issues.append(
        f"Invalid raw records: "
        f"{invalid_raw_records}"
    )


if total_events > 0:

    warnings.append(
        f"Raw discard counter decreases detected: "
        f"{total_events}"
    )


if multiple_counter > 0:

    warnings.append(
        f"Multiple raw counters decreased on the same "
        f"interface around discard decrease events: "
        f"{multiple_counter}"
    )


if interface_events > 0:

    warnings.append(
        f"Discard decreases correlated with operStatus "
        f"changes: {interface_events}"
    )


if fatal_issues:

    status = "FAIL"
    feature_engineering_ready = False

else:

    status = "PASS WITH WARNINGS"
    feature_engineering_ready = True


# ============================================================
# REPORT
# ============================================================

report = {

    "audit": {
        "name": "raw_cross_metric_audit",
        "version": "1.0",
        "correlation_window_sec": (
            CORRELATION_WINDOW_SEC
        ),
    },

    "input": {
        "semantic_file": str(
            SEMANTIC_FILE
        ),
        "raw_history_file": str(
            RAW_HISTORY_FILE
        ),
    },

    "coverage": {
        "semantic_metrics": len(
            semantic_metrics
        ),
        "item_map": len(
            item_map
        ),
        "raw_records": len(
            raw_records
        ),
        "relevant_records": len(
            relevant_records
        ),
        "missing_semantic": missing_semantic,
        "invalid_raw_records": invalid_raw_records,
        "duplicate_itemids": duplicate_itemids,
        "interfaces": len(
            interfaces
        ),
    },

    "reset_events": {
        "total": total_events,

        "by_canonical_metric": dict(
            Counter(
                event["canonical_metric"]
                for event in reset_events
            )
        ),

        "by_device_role": dict(
            Counter(
                event["device_role"]
                for event in reset_events
            )
        ),

        "by_host": dict(
            host_counter
        ),

        "unique_hosts": len(
            host_counter
        ),

        "unique_interfaces": len(
            interface_counter
        ),
    },

    "classification": {
        "counts": dict(
            classification_counter
        ),

        "confidence": dict(
            confidence_counter
        ),

        "overall": overall_classification,
    },

    "cross_metric": {

        "raw_counter_decreases": dict(
            cross_metric_decrease_counter
        ),

        "raw_metric_events_checked": dict(
            cross_metric_event_counter
        ),

        "oper_status_changes": (
            oper_status_change_count
        ),
    },

    "temporal_clustering": {

        "exact_timestamp_event_count": (
            same_timestamp_events
        ),

        "exact_timestamp_event_percentage": (
            (
                same_timestamp_events
                / total_events
                * 100
            )
            if total_events
            else 0
        ),

        "multi_interface_cluster_count": (
            multi_interface_clusters
        ),

        "largest_clusters": (
            timestamp_cluster_details[:20]
        ),
    },

    "statistics": {
        "decrease_magnitude": magnitude_stats,
        "decrease_ratio": ratio_stats,
    },

    "feature_engineering": {

        "ready": feature_engineering_ready,

        "decision": (
            "Proceed to feature engineering"
            if feature_engineering_ready
            else "Do not proceed; fix fatal audit issues"
        ),

        "recommended_handling": {
            "counter_increase": (
                "delta / actual_delta_time_sec"
            ),
            "counter_decrease": (
                "value=null and counter_reset=true"
            ),
            "duplicate_timestamp": (
                "ignore for delta calculation"
            ),
            "out_of_order": (
                "ignore for delta calculation"
            ),
            "do_not_treat_counter_reset_as_anomaly": True,
        },
    },

    "issues": {
        "fatal": fatal_issues,
        "warnings": warnings,
    },

    "status": status,

    "event_details": event_results,
}


# ============================================================
# WRITE OUTPUT
# ============================================================

with OUTPUT_FILE.open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        report,
        f,
        indent=2,
        ensure_ascii=False,
    )


# ============================================================
# CONSOLE OUTPUT
# ============================================================

print("\n" + "=" * 72)
print("SUMMARY")
print("=" * 72)

print(
    f"\nRaw records                  : "
    f"{len(raw_records):,}"
)

print(
    f"Relevant records             : "
    f"{len(relevant_records):,}"
)

print(
    f"Discard decrease events      : "
    f"{total_events:,}"
)

print("\nBy canonical metric:")

for metric, count in sorted(
    Counter(
        event["canonical_metric"]
        for event in reset_events
    ).items()
):

    print(
        f"  {metric:<30}: {count:>5}"
    )


print("\nClassification:")

for classification, count in (
    classification_counter.most_common()
):

    percentage = (
        count / total_events * 100
        if total_events
        else 0
    )

    print(
        f"  {classification:<40}: "
        f"{count:>5} ({percentage:>6.2f}%)"
    )


print("\nRaw cross-metric decreases:")

if cross_metric_decrease_counter:

    for metric, count in (
        cross_metric_decrease_counter.most_common()
    ):

        percentage = (
            count / total_events * 100
            if total_events
            else 0
        )

        print(
            f"  {metric:<30}: "
            f"{count:>5} ({percentage:>6.2f}%)"
        )

else:

    print("  None")


print(
    f"\nOperStatus changes near event : "
    f"{oper_status_change_count}"
)

print(
    f"\nExact timestamp events       : "
    f"{same_timestamp_events:,}"
)

if total_events:

    print(
        f"Exact timestamp percentage   : "
        f"{same_timestamp_events / total_events * 100:.2f}%"
    )

print(
    f"Multi-interface clusters      : "
    f"{multi_interface_clusters:,}"
)


print("\nTop affected hosts:")

for host, count in host_counter.most_common(10):

    print(
        f"  {host:<40}: {count:>5}"
    )


print("\nDecrease magnitude:")

if magnitude_stats:

    for key, value in magnitude_stats.items():

        print(
            f"  {key:<10}: {value}"
        )


print("\nOverall classification:")
print(
    f"  {overall_classification}"
)

print("\nFeature engineering:")
print(
    f"  Ready : {feature_engineering_ready}"
)

print("\nFatal issues:")

if fatal_issues:

    for issue in fatal_issues:
        print(f"  - {issue}")

else:

    print("  None")


print("\nWarnings:")

if warnings:

    for warning in warnings:
        print(f"  - {warning}")

else:

    print("  None")


print(
    f"\nOutput written to: "
    f"{OUTPUT_FILE}"
)

print(
    f"\nSTATUS : {status}"
)

print("=" * 72)