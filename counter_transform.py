import json
from collections import Counter, defaultdict
from pathlib import Path


INPUT_FILE = Path("raw_history.jsonl")
OUTPUT_FILE = Path("transformed_history.jsonl")
AUDIT_FILE = Path("counter_transform_audit.json")


def load_jsonl(path: Path):
    """Load JSON Lines file."""
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_number}: {exc}"
                ) from exc


def safe_float(value):
    """Convert numeric value to float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value):
    """Convert value to int if possible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_history(path: Path):
    """
    Load history and group records by itemid.

    Only numeric records are kept because counter transformation
    requires numeric values.
    """
    grouped = defaultdict(list)

    total_records = 0
    numeric_records = 0
    skipped_records = 0

    for record in load_jsonl(path):
        total_records += 1

        itemid = str(record.get("itemid", ""))
        clock = safe_int(record.get("clock"))
        value = safe_float(record.get("value"))

        if not itemid or clock is None or value is None:
            skipped_records += 1
            continue

        grouped[itemid].append(record)
        numeric_records += 1

    return grouped, {
        "total_records": total_records,
        "numeric_records": numeric_records,
        "skipped_records": skipped_records,
    }


def transform_item(records, stats):
    """
    Transform one item's history.

    Counter:
        rate = delta_value / actual_delta_time

    Gauge/rate/state:
        value is passed through unchanged.

    Counter decrease:
        value = None
        counter_reset = True

    Duplicate/out-of-order timestamps are not used for delta calculation.
    """

    records = sorted(
        records,
        key=lambda r: (
            safe_int(r.get("clock")) or 0,
        ),
    )

    output = []

    previous_clock = None
    previous_value = None

    seen_clocks = set()

    for record in records:
        itemid = str(record.get("itemid"))
        clock = safe_int(record.get("clock"))
        raw_value = safe_float(record.get("value"))

        semantic_type = record.get("semantic_type", "unknown")
        canonical_metric = record.get("canonical_metric")

        transformed = dict(record)

        # Metadata describing transformation
        transformed["raw_value"] = raw_value
        transformed["previous_raw_value"] = None
        transformed["delta_time_sec"] = None
        transformed["delta_value"] = None
        transformed["counter_reset"] = False
        transformed["duplicate_timestamp"] = False
        transformed["out_of_order"] = False

        # ---------------------------------------------------------
        # Non-counter metrics
        # ---------------------------------------------------------
        if semantic_type != "counter":
            transformed["value"] = raw_value
            transformed["transformation_applied"] = "direct"

            output.append(transformed)

            stats["direct_records"] += 1

            # Keep previous values for informational purposes,
            # but they are NOT used for transformation.
            previous_clock = clock
            previous_value = raw_value

            continue

        # ---------------------------------------------------------
        # Counter metrics
        # ---------------------------------------------------------

        # First sample of this item
        if previous_clock is None or previous_value is None:
            transformed["value"] = None
            transformed["transformation_applied"] = "counter_first_sample"

            output.append(transformed)

            stats["counter_first_samples"] += 1

            previous_clock = clock
            previous_value = raw_value

            seen_clocks.add(clock)

            continue

        transformed["previous_raw_value"] = previous_value

        # ---------------------------------------------------------
        # Duplicate timestamp
        # ---------------------------------------------------------
        if clock == previous_clock:
            transformed["value"] = None
            transformed["duplicate_timestamp"] = True
            transformed["transformation_applied"] = "duplicate_timestamp"

            output.append(transformed)

            stats["duplicate_timestamps"] += 1

            # Do not update previous sample.
            continue

        # ---------------------------------------------------------
        # Out-of-order timestamp
        # ---------------------------------------------------------
        if clock < previous_clock:
            transformed["value"] = None
            transformed["out_of_order"] = True
            transformed["transformation_applied"] = "out_of_order"

            output.append(transformed)

            stats["out_of_order_records"] += 1

            # Do not update previous sample.
            continue

        # ---------------------------------------------------------
        # Calculate actual sampling interval
        # ---------------------------------------------------------
        delta_time = clock - previous_clock

        transformed["delta_time_sec"] = delta_time

        if delta_time <= 0:
            transformed["value"] = None
            transformed["transformation_applied"] = "invalid_delta_time"

            output.append(transformed)

            stats["invalid_delta_time"] += 1

            continue

        # ---------------------------------------------------------
        # Calculate counter delta
        # ---------------------------------------------------------
        delta_value = raw_value - previous_value

        transformed["delta_value"] = delta_value

        # ---------------------------------------------------------
        # Counter decrease / reset
        # ---------------------------------------------------------
        if delta_value < 0:
            transformed["value"] = None
            transformed["counter_reset"] = True
            transformed["transformation_applied"] = "counter_reset"

            output.append(transformed)

            stats["counter_decreases"] += 1

            stats["counter_decrease_by_metric"][
                canonical_metric or "unknown"
            ] += 1

            # Important:
            # The current value becomes the new baseline.
            previous_clock = clock
            previous_value = raw_value

            continue

        # ---------------------------------------------------------
        # Normal counter
        # ---------------------------------------------------------
        rate = delta_value / delta_time

        transformed["value"] = rate
        transformed["transformation_applied"] = "delta_rate"

        output.append(transformed)

        stats["counter_transformed"] += 1

        previous_clock = clock
        previous_value = raw_value

        seen_clocks.add(clock)

    return output


def main():
    print("=" * 70)
    print("Counter Transformation")
    print("=" * 70)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    print(f"Input  : {INPUT_FILE}")
    print(f"Output : {OUTPUT_FILE}")
    print(f"Audit  : {AUDIT_FILE}")
    print()

    # -------------------------------------------------------------
    # Load raw history
    # -------------------------------------------------------------
    grouped, load_stats = load_history(INPUT_FILE)

    print(f"Total raw records      : {load_stats['total_records']:,}")
    print(f"Numeric records        : {load_stats['numeric_records']:,}")
    print(f"Skipped records        : {load_stats['skipped_records']:,}")
    print(f"Unique items           : {len(grouped):,}")
    print()

    # -------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------
    stats = {
        "direct_records": 0,
        "counter_first_samples": 0,
        "counter_transformed": 0,
        "counter_decreases": 0,
        "duplicate_timestamps": 0,
        "out_of_order_records": 0,
        "invalid_delta_time": 0,
        "counter_decrease_by_metric": Counter(),
    }

    # -------------------------------------------------------------
    # Transform
    # -------------------------------------------------------------
    total_output = 0

    with OUTPUT_FILE.open("w", encoding="utf-8") as out:
        for itemid, records in grouped.items():
            transformed_records = transform_item(records, stats)

            for record in transformed_records:
                out.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

                total_output += 1

    # -------------------------------------------------------------
    # Audit
    # -------------------------------------------------------------
    audit = {
        "input_file": str(INPUT_FILE),
        "output_file": str(OUTPUT_FILE),

        "input": {
            "total_records": load_stats["total_records"],
            "numeric_records": load_stats["numeric_records"],
            "skipped_records": load_stats["skipped_records"],
            "unique_items": len(grouped),
        },

        "output": {
            "total_records": total_output,
        },

        "transformation": {
            "direct_records": stats["direct_records"],
            "counter_first_samples": stats["counter_first_samples"],
            "counter_transformed": stats["counter_transformed"],
            "counter_decreases": stats["counter_decreases"],
            "duplicate_timestamps": stats["duplicate_timestamps"],
            "out_of_order_records": stats["out_of_order_records"],
            "invalid_delta_time": stats["invalid_delta_time"],
        },

        "counter_decrease_by_metric": dict(
            stats["counter_decrease_by_metric"]
        ),

        "rules": {
            "counter_formula": "delta_value / actual_delta_time_sec",
            "counter_increase": "transform to rate",
            "counter_decrease": (
                "value=null and counter_reset=true; "
                "current sample becomes new baseline"
            ),
            "duplicate_timestamp": (
                "do not calculate delta; "
                "do not update previous sample"
            ),
            "out_of_order": (
                "do not calculate delta; "
                "do not update previous sample"
            ),
            "gauge_rate_state": "pass through raw value",
            "raw_history_immutable": True,
        },
    }

    with AUDIT_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            audit,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # -------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------
    print("=" * 70)
    print("Transformation completed")
    print("=" * 70)

    print(f"Output records         : {total_output:,}")
    print(f"Direct records         : {stats['direct_records']:,}")
    print(f"Counter first samples  : {stats['counter_first_samples']:,}")
    print(f"Counter transformed    : {stats['counter_transformed']:,}")
    print(f"Counter decreases      : {stats['counter_decreases']:,}")
    print(f"Duplicate timestamps   : {stats['duplicate_timestamps']:,}")
    print(f"Out-of-order records   : {stats['out_of_order_records']:,}")
    print(f"Invalid delta time     : {stats['invalid_delta_time']:,}")

    print()
    print("Counter decreases by canonical metric:")

    for metric, count in sorted(
        stats["counter_decrease_by_metric"].items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"  {metric:<25} {count:,}")

    print()
    print(f"Created: {OUTPUT_FILE}")
    print(f"Created: {AUDIT_FILE}")


if __name__ == "__main__":
    main()
