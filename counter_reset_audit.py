#!/usr/bin/env python3

import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = Path("transformed_history.jsonl")
OUTPUT_FILE = Path("counter_reset_audit.json")

# Counter decrease/reset is NOT treated as fatal.
# It is classified as a warning/expected event.
TREAT_COUNTER_RESET_AS_ERROR = False

# Maximum number of detailed events stored in the JSON report.
MAX_DETAIL_EVENTS = 1000


# ============================================================
# HELPERS
# ============================================================

def safe_float(value):
    """
    Convert a value to float safely.

    Returns:
        float | None
    """
    if value is None:
        return None

    try:
        result = float(value)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(result):
        return None

    return result


def parse_timestamp(value):
    """
    Parse ISO timestamp.

    Returns:
        datetime | None
    """
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def increment(counter, key):
    """
    Small helper for Counter/dict-like objects.
    """
    counter[key] += 1


def percentile(values, percentile):
    """
    Calculate percentile without requiring numpy.

    percentile:
        0 <= percentile <= 100
    """
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    rank = (len(values) - 1) * (percentile / 100.0)

    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))

    if lower == upper:
        return values[lower]

    weight = rank - lower

    return values[lower] * (1 - weight) + values[upper] * weight


def round_or_none(value, digits=6):
    if value is None:
        return None

    return round(value, digits)


# ============================================================
# LOAD TRANSFORMED HISTORY
# ============================================================

def load_transformed_history(path):
    records = []
    parse_errors = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                records.append(record)

            except json.JSONDecodeError as exc:
                parse_errors.append(
                    {
                        "line": line_number,
                        "error": str(exc),
                    }
                )

    return records, parse_errors


# ============================================================
# FIND COUNTER RESET EVENTS
# ============================================================

def audit_counter_resets(records):

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    total_counter_records = 0
    first_samples = 0
    increase_events = 0
    decrease_events = 0
    unchanged_events = 0

    counter_reset_true = 0

    invalid_reset_records = 0

    # --------------------------------------------------------
    # Group statistics
    # --------------------------------------------------------

    by_canonical_metric = Counter()
    by_device_role = Counter()
    by_host = Counter()
    by_item = Counter()

    # Number of reset events per item
    reset_count_by_item = Counter()

    # Number of reset events per host
    reset_count_by_host = Counter()

    # --------------------------------------------------------
    # Reset magnitude statistics
    # --------------------------------------------------------

    reset_delta_values = []
    reset_previous_values = []
    reset_current_values = []
    reset_delta_times = []

    # --------------------------------------------------------
    # Detailed events
    # --------------------------------------------------------

    reset_events = []

    # --------------------------------------------------------
    # Process only counter records
    # --------------------------------------------------------

    for record in records:

        semantic_type = record.get("semantic_type")

        if semantic_type != "counter":
            continue

        total_counter_records += 1

        itemid = str(record.get("itemid", ""))
        hostid = str(record.get("hostid", ""))

        host = record.get("host")
        host_name = record.get("host_name")

        device_role = record.get("device_role")

        canonical_metric = record.get("canonical_metric")

        timestamp = record.get("timestamp")
        clock = record.get("clock")

        raw_value = safe_float(record.get("raw_value"))
        previous_raw_value = safe_float(
            record.get("previous_raw_value")
        )

        delta_value = safe_float(
            record.get("delta_value")
        )

        delta_time_sec = safe_float(
            record.get("delta_time_sec")
        )

        transformed_value = safe_float(
            record.get("value")
        )

        counter_reset = bool(
            record.get("counter_reset", False)
        )

        # ----------------------------------------------------
        # First counter sample
        # ----------------------------------------------------

        if previous_raw_value is None:

            first_samples += 1

            continue

        # ----------------------------------------------------
        # Missing raw value
        # ----------------------------------------------------

        if raw_value is None:
            invalid_reset_records += 1
            continue

        # ----------------------------------------------------
        # Increase
        # ----------------------------------------------------

        if raw_value > previous_raw_value:

            increase_events += 1

            continue

        # ----------------------------------------------------
        # Unchanged
        # ----------------------------------------------------

        if raw_value == previous_raw_value:

            unchanged_events += 1

            continue

        # ----------------------------------------------------
        # Decrease / reset
        # ----------------------------------------------------

        if raw_value < previous_raw_value:

            decrease_events += 1

            # -----------------------------------------------
            # Validate transformer reset flag
            # -----------------------------------------------

            if not counter_reset:
                invalid_reset_records += 1

            # -----------------------------------------------
            # Validate delta
            # -----------------------------------------------

            expected_delta = raw_value - previous_raw_value

            if delta_value is None:
                invalid_reset_records += 1

            else:

                if not math.isclose(
                    delta_value,
                    expected_delta,
                    rel_tol=1e-9,
                    abs_tol=1e-9,
                ):
                    invalid_reset_records += 1

            # -----------------------------------------------
            # Reset should not produce a rate
            # -----------------------------------------------

            if transformed_value is not None:
                invalid_reset_records += 1

            # -----------------------------------------------
            # Statistics
            # -----------------------------------------------

            by_canonical_metric[canonical_metric] += 1

            by_device_role[device_role] += 1

            by_host[host_name or host or hostid] += 1

            item_label = (
                f"{host_name or host or hostid}"
                f" | itemid={itemid}"
                f" | {canonical_metric}"
            )

            by_item[item_label] += 1

            reset_count_by_item[itemid] += 1

            reset_count_by_host[
                host_name or host or hostid
            ] += 1

            reset_delta_values.append(
                abs(expected_delta)
            )

            reset_previous_values.append(
                previous_raw_value
            )

            reset_current_values.append(
                raw_value
            )

            if delta_time_sec is not None:
                reset_delta_times.append(
                    delta_time_sec
                )

            # -----------------------------------------------
            # Detailed event
            # -----------------------------------------------

            if len(reset_events) < MAX_DETAIL_EVENTS:

                reset_events.append(
                    {
                        "timestamp": timestamp,
                        "clock": clock,

                        "itemid": itemid,
                        "hostid": hostid,

                        "host": host,
                        "host_name": host_name,

                        "device_role": device_role,

                        "canonical_metric": canonical_metric,

                        "previous_raw_value":
                            previous_raw_value,

                        "raw_value":
                            raw_value,

                        "delta_value":
                            expected_delta,

                        "delta_time_sec":
                            delta_time_sec,

                        "transformed_value":
                            transformed_value,

                        "counter_reset":
                            counter_reset,

                        "classification":
                            "warning",

                        "reason":
                            "counter decreased compared "
                            "with previous sample",
                    }
                )

    # ========================================================
    # Statistics
    # ========================================================

    reset_magnitude_stats = {}

    if reset_delta_values:

        reset_magnitude_stats = {
            "count": len(reset_delta_values),
            "min": min(reset_delta_values),
            "max": max(reset_delta_values),
            "mean": statistics.mean(reset_delta_values),
            "median": statistics.median(reset_delta_values),
            "p95": percentile(
                reset_delta_values,
                95,
            ),
            "p99": percentile(
                reset_delta_values,
                99,
            ),
        }

    reset_previous_stats = {}

    if reset_previous_values:

        reset_previous_stats = {
            "min": min(reset_previous_values),
            "max": max(reset_previous_values),
            "mean": statistics.mean(
                reset_previous_values
            ),
            "median": statistics.median(
                reset_previous_values
            ),
        }

    reset_current_stats = {}

    if reset_current_values:

        reset_current_stats = {
            "min": min(reset_current_values),
            "max": max(reset_current_values),
            "mean": statistics.mean(
                reset_current_values
            ),
            "median": statistics.median(
                reset_current_values
            ),
        }

    reset_delta_time_stats = {}

    if reset_delta_times:

        reset_delta_time_stats = {
            "min": min(reset_delta_times),
            "max": max(reset_delta_times),
            "mean": statistics.mean(
                reset_delta_times
            ),
            "median": statistics.median(
                reset_delta_times
            ),
        }

    # ========================================================
    # Final classification
    # ========================================================

    fatal_errors = invalid_reset_records

    warnings = decrease_events

    if TREAT_COUNTER_RESET_AS_ERROR:

        fatal_errors += decrease_events

        status = (
            "FAIL"
            if fatal_errors > 0
            else "PASS"
        )

    else:

        if fatal_errors > 0:
            status = "FAIL"

        elif warnings > 0:
            status = "PASS WITH WARNINGS"

        else:
            status = "PASS"

    # ========================================================
    # Result
    # ========================================================

    result = {
        "audit": "counter_reset_audit",

        "input_file": str(INPUT_FILE),

        "configuration": {
            "treat_counter_reset_as_error":
                TREAT_COUNTER_RESET_AS_ERROR,

            "max_detail_events":
                MAX_DETAIL_EVENTS,
        },

        "summary": {
            "total_counter_records":
                total_counter_records,

            "first_samples":
                first_samples,

            "increases":
                increase_events,

            "decreases_resets":
                decrease_events,

            "unchanged":
                unchanged_events,

            "counter_reset_flagged":
                counter_reset_true,

            "invalid_reset_records":
                invalid_reset_records,
        },

        "statistics": {
            "reset_magnitude":
                reset_magnitude_stats,

            "previous_raw_value":
                reset_previous_stats,

            "current_raw_value":
                reset_current_stats,

            "delta_time_sec":
                reset_delta_time_stats,
        },

        "by_canonical_metric":
            dict(by_canonical_metric),

        "by_device_role":
            dict(by_device_role),

        "by_host":
            dict(
                by_host.most_common()
            ),

        "by_item":
            dict(
                by_item.most_common()
            ),

        "top_items": [
            {
                "itemid": itemid,
                "reset_count": count,
            }
            for itemid, count
            in reset_count_by_item.most_common()
        ],

        "top_hosts": [
            {
                "host": host,
                "reset_count": count,
            }
            for host, count
            in reset_count_by_host.most_common()
        ],

        "reset_events":
            reset_events,

        "classification": {
            "counter_decreases_are":
                "warnings",

            "fatal_errors":
                fatal_errors,

            "warnings":
                warnings,

            "status":
                status,
        },
    }

    return result


# ============================================================
# PRINT REPORT
# ============================================================

def print_report(result):

    summary = result["summary"]
    classification = result["classification"]

    print()
    print("=" * 70)
    print("COUNTER RESET AUDIT")
    print("=" * 70)

    print()
    print("Counter records")
    print("-" * 70)

    print(
        f"Total counter records : "
        f"{summary['total_counter_records']}"
    )

    print(
        f"First samples         : "
        f"{summary['first_samples']}"
    )

    print(
        f"Increases             : "
        f"{summary['increases']}"
    )

    print(
        f"Decreases / resets    : "
        f"{summary['decreases_resets']}"
    )

    print(
        f"Unchanged             : "
        f"{summary['unchanged']}"
    )

    print()
    print("Reset validation")
    print("-" * 70)

    print(
        f"Invalid reset records : "
        f"{summary['invalid_reset_records']}"
    )

    print()
    print("By canonical metric")
    print("-" * 70)

    for metric, count in sorted(
        result["by_canonical_metric"].items(),
        key=lambda x: (-x[1], x[0]),
    ):
        print(
            f"{metric:<25} : {count}"
        )

    print()
    print("By device role")
    print("-" * 70)

    for role, count in sorted(
        result["by_device_role"].items(),
        key=lambda x: (-x[1], x[0]),
    ):
        print(
            f"{role:<25} : {count}"
        )

    print()
    print("Top affected hosts")
    print("-" * 70)

    for entry in result["top_hosts"][:20]:

        print(
            f"{entry['host']:<35} "
            f": {entry['reset_count']}"
        )

    print()
    print("Top affected items")
    print("-" * 70)

    for entry in result["top_items"][:20]:

        print(
            f"{entry['itemid']:<15} "
            f": {entry['reset_count']}"
        )

    print()
    print("Reset magnitude statistics")
    print("-" * 70)

    stats = result["statistics"]["reset_magnitude"]

    if stats:

        print(
            f"Count  : {stats['count']}"
        )

        print(
            f"Min    : {stats['min']}"
        )

        print(
            f"Max    : {stats['max']}"
        )

        print(
            f"Mean   : {stats['mean']}"
        )

        print(
            f"Median : {stats['median']}"
        )

        print(
            f"P95    : {stats['p95']}"
        )

        print(
            f"P99    : {stats['p99']}"
        )

    else:

        print("No counter reset events.")

    print()
    print("=" * 70)
    print("FINAL RESULT")
    print("=" * 70)

    print(
        f"Fatal errors : "
        f"{classification['fatal_errors']}"
    )

    print(
        f"Warnings     : "
        f"{classification['warnings']}"
    )

    print(
        f"Status       : "
        f"{classification['status']}"
    )

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    print("=" * 70)
    print("LOADING TRANSFORMED HISTORY")
    print("=" * 70)

    records, parse_errors = load_transformed_history(
        INPUT_FILE
    )

    print(
        f"Records      : {len(records)}"
    )

    print(
        f"Parse errors : {len(parse_errors)}"
    )

    if parse_errors:

        print()
        print("First parse errors:")

        for error in parse_errors[:10]:

            print(
                f"  line {error['line']}: "
                f"{error['error']}"
            )

    # --------------------------------------------------------
    # Audit
    # --------------------------------------------------------

    result = audit_counter_resets(
        records
    )

    # --------------------------------------------------------
    # Print
    # --------------------------------------------------------

    print_report(
        result
    )

    # --------------------------------------------------------
    # Write JSON report
    # --------------------------------------------------------

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(
        f"Audit written to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()