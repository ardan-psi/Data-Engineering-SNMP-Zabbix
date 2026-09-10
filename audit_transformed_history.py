import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


RAW_FILE = Path("raw_history.jsonl")
TRANSFORMED_FILE = Path("transformed_history.jsonl")
OUTPUT_FILE = Path("transformed_history_audit.json")


# ============================================================
# Helpers
# ============================================================

def load_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                yield line_number, json.loads(line)
            except json.JSONDecodeError as exc:
                yield line_number, {
                    "__parse_error__": str(exc)
                }


def is_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def same_number(a, b, tolerance=1e-9):
    if not is_number(a) or not is_number(b):
        return False

    return math.isclose(
        float(a),
        float(b),
        rel_tol=tolerance,
        abs_tol=tolerance,
    )


def key_for_record(record):
    return str(record.get("itemid"))


# ============================================================
# Load raw history
# ============================================================

print("=" * 70)
print("LOADING RAW HISTORY")
print("=" * 70)

raw_records = []
raw_parse_errors = []

for line_number, record in load_jsonl(RAW_FILE):

    if "__parse_error__" in record:
        raw_parse_errors.append({
            "line": line_number,
            "error": record["__parse_error__"],
        })
        continue

    raw_records.append(record)


print(f"Raw records        : {len(raw_records)}")
print(f"Raw parse errors   : {len(raw_parse_errors)}")


# ============================================================
# Load transformed history
# ============================================================

print()
print("=" * 70)
print("LOADING TRANSFORMED HISTORY")
print("=" * 70)

transformed_records = []
transformed_parse_errors = []

for line_number, record in load_jsonl(TRANSFORMED_FILE):

    if "__parse_error__" in record:
        transformed_parse_errors.append({
            "line": line_number,
            "error": record["__parse_error__"],
        })
        continue

    transformed_records.append(record)


print(
    f"Transformed records : "
    f"{len(transformed_records)}"
)

print(
    f"Transformed parse errors : "
    f"{len(transformed_parse_errors)}"
)


# ============================================================
# Basic counters
# ============================================================

issues = []

issue_counts = Counter()
severity_counts = Counter()

semantic_counts = Counter()
transformation_counts = Counter()
canonical_counts = Counter()

counter_stats = Counter()
direct_stats = Counter()

counter_decreases = []
counter_resets = []

duplicate_timestamps = []
out_of_order = []

invalid_delta_time = []

negative_rates = []
non_finite_values = []

formula_mismatches = []

raw_value_mismatches = []

metadata_mismatches = []

missing_fields = []

# Distribution per canonical metric
value_distribution = defaultdict(list)


def add_issue(
    issue_type,
    severity,
    record,
    message,
    **extra,
):
    issue = {
        "issue_type": issue_type,
        "severity": severity,
        "itemid": record.get("itemid"),
        "clock": record.get("clock"),
        "semantic_type": record.get(
            "semantic_type"
        ),
        "transformation": record.get(
            "transformation"
        ),
        "canonical_metric": record.get(
            "canonical_metric"
        ),
        "message": message,
    }

    issue.update(extra)

    issues.append(issue)

    issue_counts[issue_type] += 1
    severity_counts[severity] += 1


# ============================================================
# Build raw lookup
# ============================================================

print()
print("=" * 70)
print("BUILDING RAW LOOKUP")
print("=" * 70)

raw_lookup = defaultdict(list)

for record in raw_records:

    itemid = record.get("itemid")

    if itemid is None:
        continue

    raw_lookup[str(itemid)].append(record)


# ============================================================
# Audit 1:
# Record count / identity
# ============================================================

print()
print("=" * 70)
print("AUDIT 1 - RECORD INTEGRITY")
print("=" * 70)

if len(raw_records) != len(transformed_records):

    add_issue(
        "record_count_mismatch",
        "critical",
        {},
        (
            "Raw and transformed record counts "
            "are different."
        ),
        raw_count=len(raw_records),
        transformed_count=len(
            transformed_records
        ),
    )

print(
    f"Raw records        : {len(raw_records)}"
)

print(
    f"Transformed records: "
    f"{len(transformed_records)}"
)


# ============================================================
# Audit 2:
# Required fields
# ============================================================

print()
print("=" * 70)
print("AUDIT 2 - REQUIRED FIELDS")
print("=" * 70)

required_fields = [
    "itemid",
    "clock",
    "value",
    "semantic_type",
    "transformation",
    "canonical_metric",
]

for index, record in enumerate(
    transformed_records,
    1,
):

    for field in required_fields:

        if field not in record:

            missing_fields.append({
                "record_index": index,
                "itemid": record.get(
                    "itemid"
                ),
                "field": field,
            })

            add_issue(
                "missing_field",
                "high",
                record,
                f"Required field '{field}' is missing.",
                field=field,
            )


print(
    f"Missing fields: "
    f"{len(missing_fields)}"
)


# ============================================================
# Audit 3:
# Semantic / transformation consistency
# ============================================================

print()
print("=" * 70)
print("AUDIT 3 - SEMANTIC CONSISTENCY")
print("=" * 70)

EXPECTED_TRANSFORMATION = {
    "counter": "delta_rate",
    "gauge": "direct",
    "rate": "direct",
    "state": "direct",
}


for record in transformed_records:

    semantic_type = record.get(
        "semantic_type"
    )

    transformation = record.get(
        "transformation"
    )

    semantic_counts[
        str(semantic_type)
    ] += 1

    transformation_counts[
        str(transformation)
    ] += 1

    canonical = record.get(
        "canonical_metric"
    )

    if canonical:
        canonical_counts[
            canonical
        ] += 1

    expected = EXPECTED_TRANSFORMATION.get(
        semantic_type
    )

    if expected is not None:

        if transformation != expected:

            add_issue(
                "wrong_transformation",
                "critical",
                record,
                (
                    f"Semantic type '{semantic_type}' "
                    f"requires transformation "
                    f"'{expected}', but got "
                    f"'{transformation}'."
                ),
                expected=expected,
                actual=transformation,
            )


# ============================================================
# Build transformed groups
# ============================================================

transformed_by_item = defaultdict(list)

for record in transformed_records:

    itemid = record.get("itemid")

    if itemid is None:
        continue

    transformed_by_item[
        str(itemid)
    ].append(record)


# ============================================================
# Audit 4:
# Timestamp ordering
# ============================================================

print()
print("=" * 70)
print("AUDIT 4 - TIMESTAMP ORDER")
print("=" * 70)

for itemid, records in transformed_by_item.items():

    previous_clock = None

    for record in records:

        clock = record.get("clock")

        if not isinstance(clock, int):
            try:
                clock = int(clock)
            except (
                TypeError,
                ValueError,
            ):
                add_issue(
                    "invalid_clock",
                    "high",
                    record,
                    "Clock is not a valid integer.",
                )

                continue

        if previous_clock is not None:

            if clock == previous_clock:

                duplicate_timestamps.append(
                    {
                        "itemid": itemid,
                        "clock": clock,
                    }
                )

                add_issue(
                    "duplicate_timestamp",
                    "high",
                    record,
                    (
                        "Duplicate timestamp detected "
                        "for the same item."
                    ),
                )

            elif clock < previous_clock:

                out_of_order.append(
                    {
                        "itemid": itemid,
                        "clock": clock,
                        "previous_clock": previous_clock,
                    }
                )

                add_issue(
                    "out_of_order",
                    "high",
                    record,
                    (
                        "Record timestamp is older "
                        "than the previous record."
                    ),
                    previous_clock=previous_clock,
                )

        previous_clock = clock


print(
    f"Duplicate timestamps: "
    f"{len(duplicate_timestamps)}"
)

print(
    f"Out-of-order records: "
    f"{len(out_of_order)}"
)


# ============================================================
# Audit 5:
# Counter transformation
# ============================================================

print()
print("=" * 70)
print("AUDIT 5 - COUNTER TRANSFORMATION")
print("=" * 70)


for itemid, records in transformed_by_item.items():

    previous_raw_value = None
    previous_clock = None
    first_counter = True

    for record in records:

        semantic_type = record.get(
            "semantic_type"
        )

        if semantic_type != "counter":
            continue

        raw_value = record.get(
            "raw_value"
        )

        value = record.get(
            "value"
        )

        delta_value = record.get(
            "delta_value"
        )

        delta_time = record.get(
            "delta_time_sec"
        )

        counter_reset = bool(
            record.get(
                "counter_reset",
                False,
            )
        )

        counter_stats[
            "total"
        ] += 1

        # ----------------------------------------------------
        # First counter sample
        # ----------------------------------------------------

        if previous_clock is None:

            counter_stats[
                "first_samples"
            ] += 1

            if value is not None:

                add_issue(
                    "first_counter_sample_has_value",
                    "high",
                    record,
                    (
                        "First counter sample should "
                        "normally have value=null "
                        "because no previous sample "
                        "exists."
                    ),
                )

            if delta_value is not None:

                add_issue(
                    "first_counter_sample_has_delta",
                    "high",
                    record,
                    (
                        "First counter sample should "
                        "not have delta_value."
                    ),
                )

            first_counter = False

            previous_raw_value = raw_value
            previous_clock = record.get(
                "clock"
            )

            continue

        current_clock = record.get(
            "clock"
        )

        # ----------------------------------------------------
        # Timestamp validation
        # ----------------------------------------------------

        if current_clock is None:

            previous_raw_value = raw_value
            previous_clock = None

            continue

        delta_t = (
            current_clock
            - previous_clock
        )

        if delta_t <= 0:

            invalid_delta_time.append(
                {
                    "itemid": itemid,
                    "clock": current_clock,
                    "previous_clock": previous_clock,
                    "delta_time_sec": delta_t,
                }
            )

            add_issue(
                "invalid_delta_time",
                "high",
                record,
                (
                    "Counter delta time must "
                    "be greater than zero."
                ),
                delta_time_sec=delta_t,
            )

            previous_raw_value = raw_value
            previous_clock = current_clock

            continue

        # ----------------------------------------------------
        # Raw value numeric
        # ----------------------------------------------------

        if not is_number(raw_value):

            add_issue(
                "non_numeric_counter_raw_value",
                "high",
                record,
                (
                    "Counter raw_value is not "
                    "numeric."
                ),
            )

            previous_raw_value = raw_value
            previous_clock = current_clock

            continue

        if not is_number(
            previous_raw_value
        ):

            previous_raw_value = raw_value
            previous_clock = current_clock

            continue

        # ----------------------------------------------------
        # Counter decrease
        # ----------------------------------------------------

        if raw_value < previous_raw_value:

            counter_stats[
                "decreases"
            ] += 1

            counter_decreases.append(
                {
                    "itemid": itemid,
                    "clock": current_clock,
                    "previous_clock": previous_clock,
                    "previous_raw_value": previous_raw_value,
                    "raw_value": raw_value,
                    "delta_value": delta_value,
                    "value": value,
                    "counter_reset": counter_reset,
                    "canonical_metric": record.get(
                        "canonical_metric"
                    ),
                }
            )

            # A decrease must be represented
            # as counter reset.
            if not counter_reset:

                add_issue(
                    "decrease_without_reset_flag",
                    "critical",
                    record,
                    (
                        "Counter decreased but "
                        "counter_reset is false."
                    ),
                    previous_raw_value=previous_raw_value,
                )

            # Reset should not produce rate.
            if value is not None:

                add_issue(
                    "reset_has_rate_value",
                    "critical",
                    record,
                    (
                        "Counter reset sample should "
                        "have value=null."
                    ),
                    previous_raw_value=previous_raw_value,
                )

            # Reset should not have a delta.
            if delta_value is not None:

                add_issue(
                    "reset_has_delta_value",
                    "high",
                    record,
                    (
                        "Counter reset sample should "
                        "have delta_value=null."
                    ),
                    previous_raw_value=previous_raw_value,
                )

        # ----------------------------------------------------
        # Counter increase
        # ----------------------------------------------------

        elif raw_value > previous_raw_value:

            counter_stats[
                "increases"
            ] += 1

            expected_delta = (
                raw_value
                - previous_raw_value
            )

            if not same_number(
                delta_value,
                expected_delta,
            ):

                formula_mismatches.append(
                    {
                        "itemid": itemid,
                        "clock": current_clock,
                        "previous_raw_value": previous_raw_value,
                        "raw_value": raw_value,
                        "expected_delta": expected_delta,
                        "actual_delta": delta_value,
                    }
                )

                add_issue(
                    "delta_value_mismatch",
                    "critical",
                    record,
                    (
                        "delta_value does not match "
                        "raw_value - previous_raw_value."
                    ),
                    expected_delta=expected_delta,
                    actual_delta=delta_value,
                )

            # delta_time must match actual clocks
            stored_delta_time = record.get(
                "delta_time_sec"
            )

            if stored_delta_time != delta_t:

                add_issue(
                    "delta_time_mismatch",
                    "critical",
                    record,
                    (
                        "Stored delta_time_sec does "
                        "not match actual clock difference."
                    ),
                    expected_delta_time=delta_t,
                    actual_delta_time=stored_delta_time,
                )

            # Rate formula
            if (
                is_number(delta_value)
                and is_number(stored_delta_time)
                and stored_delta_time > 0
            ):

                expected_rate = (
                    delta_value
                    / stored_delta_time
                )

                if not same_number(
                    value,
                    expected_rate,
                ):

                    formula_mismatches.append(
                        {
                            "itemid": itemid,
                            "clock": current_clock,
                            "expected_rate": expected_rate,
                            "actual_value": value,
                        }
                    )

                    add_issue(
                        "rate_formula_mismatch",
                        "critical",
                        record,
                        (
                            "Counter rate does not "
                            "match delta_value / "
                            "delta_time_sec."
                        ),
                        expected_rate=expected_rate,
                        actual_value=value,
                    )

            # Counter increase should not be reset.
            if counter_reset:

                add_issue(
                    "increase_marked_as_reset",
                    "high",
                    record,
                    (
                        "Counter increased but "
                        "counter_reset is true."
                    ),
                )

            # Normal increase should have rate.
            if value is None:

                add_issue(
                    "increase_missing_rate",
                    "critical",
                    record,
                    (
                        "Counter increased but "
                        "transformed value is null."
                    ),
                )

        # ----------------------------------------------------
        # Counter unchanged
        # ----------------------------------------------------

        else:

            counter_stats[
                "unchanged"
            ] += 1

            expected_delta = 0

            if not same_number(
                delta_value,
                expected_delta,
            ):

                add_issue(
                    "unchanged_delta_mismatch",
                    "high",
                    record,
                    (
                        "Counter did not change but "
                        "delta_value is not zero."
                    ),
                    expected_delta=0,
                    actual_delta=delta_value,
                )

            if is_number(value):

                expected_rate = 0.0

                if not same_number(
                    value,
                    expected_rate,
                ):

                    add_issue(
                        "unchanged_rate_mismatch",
                        "high",
                        record,
                        (
                            "Counter did not change but "
                            "rate is not zero."
                        ),
                        expected_rate=0.0,
                        actual_value=value,
                    )

            if counter_reset:

                add_issue(
                    "unchanged_marked_as_reset",
                    "high",
                    record,
                    (
                        "Counter did not change but "
                        "counter_reset is true."
                    ),
                )

        # ----------------------------------------------------
        # Negative transformed rate
        # ----------------------------------------------------

        if is_number(value):

            if value < 0:

                negative_rates.append(
                    {
                        "itemid": itemid,
                        "clock": current_clock,
                        "value": value,
                    }
                )

                add_issue(
                    "negative_rate",
                    "critical",
                    record,
                    (
                        "Transformed counter rate "
                        "is negative."
                    ),
                )

        previous_raw_value = raw_value
        previous_clock = current_clock


print(
    f"Counter records      : "
    f"{counter_stats['total']}"
)

print(
    f"First samples        : "
    f"{counter_stats['first_samples']}"
)

print(
    f"Increases            : "
    f"{counter_stats['increases']}"
)

print(
    f"Decreases / resets   : "
    f"{counter_stats['decreases']}"
)

print(
    f"Unchanged            : "
    f"{counter_stats['unchanged']}"
)

print(
    f"Formula mismatches   : "
    f"{len(formula_mismatches)}"
)

print(
    f"Negative rates       : "
    f"{len(negative_rates)}"
)


# ============================================================
# Audit 6:
# Direct metrics
# ============================================================

print()
print("=" * 70)
print("AUDIT 6 - DIRECT METRICS")
print("=" * 70)


for record in transformed_records:

    if record.get("transformation") != "direct":
        continue

    direct_stats[
        "total"
    ] += 1

    semantic_type = record.get(
        "semantic_type"
    )

    if semantic_type in {
        "gauge",
        "rate",
        "state",
    }:

        direct_stats[
            "expected_semantic"
        ] += 1

    # Direct metrics should preserve
    # raw value.

    raw_value = record.get(
        "raw_value"
    )

    value = record.get(
        "value"
    )

    if raw_value is None:

        continue

    if is_number(raw_value) and is_number(value):

        if not same_number(
            raw_value,
            value,
        ):

            raw_value_mismatches.append(
                {
                    "itemid": record.get(
                        "itemid"
                    ),
                    "clock": record.get(
                        "clock"
                    ),
                    "raw_value": raw_value,
                    "value": value,
                }
            )

            add_issue(
                "direct_value_mismatch",
                "critical",
                record,
                (
                    "Direct transformation should "
                    "preserve raw_value."
                ),
                raw_value=raw_value,
                value=value,
            )

    elif raw_value != value:

        raw_value_mismatches.append(
            {
                "itemid": record.get(
                    "itemid"
                ),
                "clock": record.get(
                    "clock"
                ),
                "raw_value": raw_value,
                "value": value,
            }
        )

        add_issue(
            "direct_value_mismatch",
            "critical",
            record,
            (
                "Direct transformation should "
                "preserve raw_value."
            ),
            raw_value=raw_value,
            value=value,
        )


print(
    f"Direct records      : "
    f"{direct_stats['total']}"
)

print(
    f"Expected semantic   : "
    f"{direct_stats['expected_semantic']}"
)

print(
    f"Value mismatches    : "
    f"{len(raw_value_mismatches)}"
)


# ============================================================
# Audit 7:
# Numeric validity
# ============================================================

print()
print("=" * 70)
print("AUDIT 7 - NUMERIC VALIDITY")
print("=" * 70)


for record in transformed_records:

    value = record.get(
        "value"
    )

    # Null is valid for:
    # counter first sample
    # counter reset
    if value is None:
        continue

    if not is_number(value):

        non_finite_values.append(
            {
                "itemid": record.get(
                    "itemid"
                ),
                "clock": record.get(
                    "clock"
                ),
                "value": value,
            }
        )

        add_issue(
            "non_finite_value",
            "critical",
            record,
            (
                "Transformed value is not "
                "a finite numeric value."
            ),
        )

        continue

    canonical = record.get(
        "canonical_metric"
    )

    if canonical:
        value_distribution[
            canonical
        ].append(
            float(value)
        )


print(
    f"Non-finite values: "
    f"{len(non_finite_values)}"
)


# ============================================================
# Audit 8:
# Raw value preservation
# ============================================================

print()
print("=" * 70)
print("AUDIT 8 - RAW VALUE PRESERVATION")
print("=" * 70)


raw_index = defaultdict(list)

for record in raw_records:

    itemid = record.get("itemid")
    clock = record.get("clock")

    if itemid is None or clock is None:
        continue

    raw_index[
        (
            str(itemid),
            int(clock),
        )
    ].append(record)


matched_raw_records = 0

for record in transformed_records:

    itemid = record.get(
        "itemid"
    )

    clock = record.get(
        "clock"
    )

    if itemid is None or clock is None:
        continue

    key = (
        str(itemid),
        int(clock),
    )

    candidates = raw_index.get(
        key,
        [],
    )

    if not candidates:

        add_issue(
            "missing_raw_record",
            "critical",
            record,
            (
                "Transformed record has no "
                "corresponding raw record."
            ),
        )

        continue

    matched_raw_records += 1

    # Usually there should be exactly one raw
    # record for an item/timestamp.
    if len(candidates) > 1:

        add_issue(
            "multiple_raw_records",
            "high",
            record,
            (
                "Multiple raw records found for "
                "the same item/timestamp."
            ),
            count=len(candidates),
        )

    raw = candidates[0]

    raw_value = raw.get(
        "value"
    )

    transformed_raw_value = record.get(
        "raw_value"
    )

    if is_number(raw_value) and is_number(
        transformed_raw_value
    ):

        if not same_number(
            raw_value,
            transformed_raw_value,
        ):

            add_issue(
                "raw_value_mismatch",
                "critical",
                record,
                (
                    "transformed raw_value does "
                    "not match raw_history value."
                ),
                raw_value=raw_value,
                transformed_raw_value=(
                    transformed_raw_value
                ),
            )

    elif raw_value != transformed_raw_value:

        add_issue(
            "raw_value_mismatch",
            "critical",
            record,
            (
                "transformed raw_value does "
                "not match raw_history value."
            ),
            raw_value=raw_value,
            transformed_raw_value=(
                transformed_raw_value
            ),
        )


print(
    f"Raw records matched: "
    f"{matched_raw_records}"
)


# ============================================================
# Distribution statistics
# ============================================================

distribution = {}

for canonical, values in sorted(
    value_distribution.items()
):

    if not values:
        continue

    distribution[canonical] = {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
    }


# ============================================================
# Counter decrease summary
# ============================================================

decrease_by_metric = Counter(
    item.get(
        "canonical_metric"
    )
    for item in counter_decreases
)

reset_by_metric = Counter(
    item.get(
        "canonical_metric"
    )
    for item in counter_resets
)


# ============================================================
# Build audit report
# ============================================================

audit = {

    "files": {
        "raw": str(RAW_FILE),
        "transformed": str(
            TRANSFORMED_FILE
        ),
    },

    "input": {
        "raw_records": len(
            raw_records
        ),
        "raw_parse_errors": len(
            raw_parse_errors
        ),
    },

    "output": {
        "transformed_records": len(
            transformed_records
        ),
        "transformed_parse_errors": len(
            transformed_parse_errors
        ),
    },

    "semantic_types": dict(
        sorted(
            semantic_counts.items()
        )
    ),

    "transformations": dict(
        sorted(
            transformation_counts.items()
        )
    ),

    "canonical_metrics": dict(
        sorted(
            canonical_counts.items()
        )
    ),

    "counter_audit": {
        "total": counter_stats[
            "total"
        ],
        "first_samples": counter_stats[
            "first_samples"
        ],
        "increases": counter_stats[
            "increases"
        ],
        "decreases": counter_stats[
            "decreases"
        ],
        "unchanged": counter_stats[
            "unchanged"
        ],
        "formula_mismatches": len(
            formula_mismatches
        ),
        "negative_rates": len(
            negative_rates
        ),
        "decrease_by_metric": dict(
            sorted(
                decrease_by_metric.items()
            )
        ),
    },

    "direct_audit": {
        "total": direct_stats[
            "total"
        ],
        "expected_semantic": direct_stats[
            "expected_semantic"
        ],
        "value_mismatches": len(
            raw_value_mismatches
        ),
    },

    "timestamp_audit": {
        "duplicate_timestamps": len(
            duplicate_timestamps
        ),
        "out_of_order": len(
            out_of_order
        ),
        "invalid_delta_time": len(
            invalid_delta_time
        ),
    },

    "raw_value_audit": {
        "matched_raw_records": matched_raw_records,
        "raw_value_mismatches": len(
            [
                issue
                for issue in issues
                if issue["issue_type"]
                == "raw_value_mismatch"
            ]
        ),
    },

    "numeric_audit": {
        "non_finite_values": len(
            non_finite_values
        ),
    },

    "value_distribution": distribution,

    "issues": {
        "total": len(issues),
        "by_type": dict(
            sorted(
                issue_counts.items()
            )
        ),
        "by_severity": dict(
            sorted(
                severity_counts.items()
            )
        ),
    },

    "details": {
        "formula_mismatches": formula_mismatches[
            :100
        ],
        "counter_decreases": counter_decreases[
            :100
        ],
        "duplicate_timestamps": duplicate_timestamps[
            :100
        ],
        "out_of_order": out_of_order[
            :100
        ],
        "invalid_delta_time": invalid_delta_time[
            :100
        ],
        "negative_rates": negative_rates[
            :100
        ],
        "non_finite_values": non_finite_values[
            :100
        ],
        "raw_value_mismatches": raw_value_mismatches[
            :100
        ],
        "missing_fields": missing_fields[
            :100
        ],
    },

    "validation": {
        "passed": len(issues) == 0,
        "total_issues": len(
            issues
        ),
    },
}


# ============================================================
# Write audit
# ============================================================

with OUTPUT_FILE.open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        audit,
        f,
        indent=2,
        ensure_ascii=False,
    )


# ============================================================
# Console report
# ============================================================

print()
print("=" * 70)
print("TRANSFORMED HISTORY AUDIT")
print("=" * 70)

print(
    f"Raw records          : "
    f"{len(raw_records)}"
)

print(
    f"Transformed records  : "
    f"{len(transformed_records)}"
)

print(
    f"Record count match   : "
    f"{len(raw_records) == len(transformed_records)}"
)

print()
print("Semantic types:")

for key, value in sorted(
    semantic_counts.items()
):

    print(
        f"  {key:15s}: "
        f"{value}"
    )

print()
print("Transformations:")

for key, value in sorted(
    transformation_counts.items()
):

    print(
        f"  {key:15s}: "
        f"{value}"
    )

print()
print("Counter audit:")

print(
    f"  total              : "
    f"{counter_stats['total']}"
)

print(
    f"  first samples      : "
    f"{counter_stats['first_samples']}"
)

print(
    f"  increases          : "
    f"{counter_stats['increases']}"
)

print(
    f"  decreases/resets   : "
    f"{counter_stats['decreases']}"
)

print(
    f"  unchanged          : "
    f"{counter_stats['unchanged']}"
)

print(
    f"  formula mismatches : "
    f"{len(formula_mismatches)}"
)

print(
    f"  negative rates     : "
    f"{len(negative_rates)}"
)

print()
print("Timestamp audit:")

print(
    f"  duplicate          : "
    f"{len(duplicate_timestamps)}"
)

print(
    f"  out-of-order       : "
    f"{len(out_of_order)}"
)

print(
    f"  invalid delta time : "
    f"{len(invalid_delta_time)}"
)

print()
print("Direct audit:")

print(
    f"  direct records     : "
    f"{direct_stats['total']}"
)

print(
    f"  value mismatches    : "
    f"{len(raw_value_mismatches)}"
)

print()
print("Numeric audit:")

print(
    f"  non-finite values  : "
    f"{len(non_finite_values)}"
)

print()
print("Raw preservation:")

print(
    f"  matched raw        : "
    f"{matched_raw_records}"
)

print(
    f"  raw mismatches     : "
    f"{len([i for i in issues if i['issue_type'] == 'raw_value_mismatch'])}"
)

print()
print("FINAL RESULT")

print(
    f"  Total issues       : "
    f"{len(issues)}"
)

print(
    f"  Status             : "
    f"{'PASS' if len(issues) == 0 else 'FAIL'}"
)

print()
print(
    "Audit written to:",
    OUTPUT_FILE
)