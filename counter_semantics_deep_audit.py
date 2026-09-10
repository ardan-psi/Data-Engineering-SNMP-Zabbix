import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

TRANSFORMED_HISTORY_FILE = "transformed_history.jsonl"
SEMANTIC_METRICS_FILE = "semantic_metrics.json"
OUTPUT_FILE = "counter_semantics_deep_audit.json"

# Number of samples inspected before/after every reset
CONTEXT_SAMPLES = 10

# Time window around reset for related metrics
CORRELATION_WINDOW_SEC = 300

# Number of post-reset samples used to determine
# whether the counter restarts and increases monotonically.
POST_RESET_MONOTONIC_SAMPLES = 5

# A decrease is considered "small" when the previous value
# is not much larger than the current value.
#
# Example:
# 10 -> 9
# 8  -> 6
#
# These may represent ordinary counter behavior/noise
# rather than a real reset.
MIN_RESET_RATIO = 0.50

# A post-reset value is considered "low" if it is small
# relative to the previous counter value.
LOW_VALUE_RATIO = 0.10

# Absolute threshold for a low counter.
#
# This is intentionally conservative because the observed
# reset magnitudes are small (1..19).
LOW_ABSOLUTE_VALUE = 20


# ============================================================
# HELPERS
# ============================================================

IFINDEX_PATTERNS = [
    r"if(?:In|Out)(?:Octets|Errors|Discards)\.(\d+)",
    r"if(?:In|Out)(?:UcastPkts|NUcastPkts|MulticastPkts|BroadcastPkts)\.(\d+)",
    r"ifOperStatus\.(\d+)",
    r"ifAdminStatus\.(\d+)",
    r"ifSpeed\.(\d+)",
    r"ifHCInOctets\.(\d+)",
    r"ifHCOutOctets\.(\d+)",
]


RELATED_METRICS = {
    "in_bps",
    "out_bps",
    "in_pps",
    "out_pps",
    "in_error_rate",
    "out_error_rate",
    "in_discard_rate",
    "out_discard_rate",
    "oper_status",
    "icmp_loss_pct",
    "icmp_rtt_sec",
    "uptime",
}


def safe_float(value):
    """
    Convert value to float safely.
    """
    try:
        result = float(value)

        if not math.isfinite(result):
            return None

        return result

    except (TypeError, ValueError):
        return None


def parse_ifindex(key):
    """
    Extract SNMP ifIndex from Zabbix item key/name.

    Examples:

        ifOutDiscards.34 -> 34
        ifInErrors.5     -> 5
        ifOperStatus.12  -> 12
    """

    if not key:
        return None

    key = str(key)

    for pattern in IFINDEX_PATTERNS:
        match = re.search(pattern, key)

        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None

    return None


def percentile(values, p):
    """
    Simple percentile implementation.
    """
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    index = (len(values) - 1) * p
    lower = int(math.floor(index))
    upper = int(math.ceil(index))

    if lower == upper:
        return values[lower]

    weight = index - lower

    return values[lower] * (1 - weight) + values[upper] * weight


# ============================================================
# LOAD SEMANTIC METRICS
# ============================================================

def load_semantic_metrics(path):
    """
    Supports both formats:

    [
        {...},
        {...}
    ]

    and:

    {
        "metrics": [
            {...}
        ]
    }
    """

    print("[1/6] Loading semantic metrics")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        metrics = data
        source_format = "list"

    elif isinstance(data, dict):
        metrics = data.get("metrics", [])

        source_format = "object"

    else:
        raise ValueError(
            "Unsupported semantic_metrics.json format"
        )

    item_map = {}

    invalid_records = 0
    duplicate_itemid = 0

    for metric in metrics:

        if not isinstance(metric, dict):
            invalid_records += 1
            continue

        itemid = str(metric.get("itemid", "")).strip()

        if not itemid:
            invalid_records += 1
            continue

        if itemid in item_map:
            duplicate_itemid += 1

        item_map[itemid] = metric

    print(f"Source format    : {source_format}")
    print(f"Semantic metrics : {len(metrics)}")
    print(f"Item map         : {len(item_map)}")
    print(f"Invalid records  : {invalid_records}")
    print(f"Duplicate itemid : {duplicate_itemid}")
    print()

    return item_map


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history(path):
    """
    Load transformed history.

    Returns:

        records

    indexed by:

        itemid
        hostid
        interface
        canonical_metric
    """

    print("[2/6] Loading transformed history")

    records = []

    parse_errors = 0

    with open(path, "r", encoding="utf-8") as f:

        for line_number, line in enumerate(f, 1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError:
                parse_errors += 1
                continue

            records.append(record)

    print(f"Records      : {len(records)}")
    print(f"Parse errors : {parse_errors}")
    print()

    return records, parse_errors


# ============================================================
# ENRICH HISTORY WITH SEMANTIC INFORMATION
# ============================================================

def enrich_records(records, semantic_map):
    """
    Attach:

        canonical_metric
        semantic_type
        transformation
        key
        ifIndex
    """

    enriched = []

    missing_semantic = 0

    for record in records:

        itemid = str(record.get("itemid", ""))

        semantic = semantic_map.get(itemid)

        if semantic is None:
            missing_semantic += 1
            continue

        key = semantic.get("key", "")

        enriched_record = dict(record)

        enriched_record["key"] = key

        enriched_record["canonical_metric"] = semantic.get(
            "canonical_metric"
        )

        enriched_record["semantic_type"] = semantic.get(
            "semantic_type"
        )

        enriched_record["transformation"] = semantic.get(
            "transformation"
        )

        enriched_record["ifIndex"] = parse_ifindex(key)

        enriched.append(enriched_record)

    print(f"Missing semantic : {missing_semantic}")
    print(f"Enriched records  : {len(enriched)}")
    print()

    return enriched


# ============================================================
# INDEX RECORDS
# ============================================================

def build_indexes(records):
    """
    Build indexes required for deep correlation.
    """

    print("[3/6] Building indexes")

    # itemid -> records
    item_index = defaultdict(list)

    # hostid -> records
    host_index = defaultdict(list)

    # (hostid, ifIndex) -> records
    interface_index = defaultdict(list)

    # (hostid, canonical_metric) -> records
    host_metric_index = defaultdict(list)

    # (hostid, ifIndex, canonical_metric) -> records
    interface_metric_index = defaultdict(list)

    for record in records:

        itemid = str(record.get("itemid", ""))
        hostid = str(record.get("hostid", ""))

        ifindex = record.get("ifIndex")

        canonical = record.get(
            "canonical_metric"
        )

        item_index[itemid].append(record)

        host_index[hostid].append(record)

        if ifindex is not None:

            interface_index[
                (hostid, ifindex)
            ].append(record)

            interface_metric_index[
                (
                    hostid,
                    ifindex,
                    canonical,
                )
            ].append(record)

        host_metric_index[
            (
                hostid,
                canonical,
            )
        ].append(record)

    # Sort every index by timestamp
    for index in (
        item_index,
        host_index,
        interface_index,
        host_metric_index,
        interface_metric_index,
    ):

        for key in index:
            index[key].sort(
                key=lambda x: int(
                    x.get("clock", 0)
                )
            )

    print(f"Items indexed       : {len(item_index)}")
    print(f"Hosts indexed       : {len(host_index)}")
    print(f"Interfaces indexed  : {len(interface_index)}")
    print()

    return {
        "item": item_index,
        "host": host_index,
        "interface": interface_index,
        "host_metric": host_metric_index,
        "interface_metric": interface_metric_index,
    }


# ============================================================
# FIND RESET EVENTS
# ============================================================

def find_reset_events(records):
    """
    Find counter decrease events.

    Important:

        current_raw < previous_raw

    only for:

        semantic_type == counter
        transformation == delta_rate

    Duplicate timestamps and out-of-order records are ignored.
    """

    print("[4/6] Finding counter reset events")

    item_records = defaultdict(list)

    for record in records:

        if record.get("semantic_type") != "counter":
            continue

        if record.get("transformation") != "delta_rate":
            continue

        itemid = str(record.get("itemid", ""))

        item_records[itemid].append(record)

    resets = []

    for itemid, history in item_records.items():

        history.sort(
            key=lambda x: int(
                x.get("clock", 0)
            )
        )

        previous = None

        for record in history:

            clock = int(
                record.get("clock", 0)
            )

            raw_value = safe_float(
                record.get("raw_value")
            )

            if raw_value is None:
                continue

            if previous is None:
                previous = record
                continue

            previous_clock = int(
                previous.get("clock", 0)
            )

            previous_raw = safe_float(
                previous.get("raw_value")
            )

            # Ignore duplicate timestamp
            if clock == previous_clock:
                continue

            # Ignore out-of-order timestamp
            if clock < previous_clock:
                continue

            if previous_raw is None:
                previous = record
                continue

            if raw_value < previous_raw:

                reset = {
                    "itemid": itemid,
                    "hostid": str(
                        record.get("hostid", "")
                    ),
                    "host": record.get("host"),
                    "host_name": record.get(
                        "host_name"
                    ),
                    "device_role": record.get(
                        "device_role"
                    ),
                    "canonical_metric": record.get(
                        "canonical_metric"
                    ),
                    "semantic_type": record.get(
                        "semantic_type"
                    ),
                    "transformation": record.get(
                        "transformation"
                    ),
                    "key": record.get("key"),
                    "ifIndex": record.get(
                        "ifIndex"
                    ),
                    "reset_clock": clock,
                    "reset_timestamp": record.get(
                        "timestamp"
                    ),
                    "previous_clock": previous_clock,
                    "previous_timestamp": previous.get(
                        "timestamp"
                    ),
                    "previous_raw_value": previous_raw,
                    "current_raw_value": raw_value,
                    "decrease": previous_raw - raw_value,
                    "delta_time_sec": (
                        clock - previous_clock
                    ),
                }

                resets.append(reset)

            previous = record

    print(f"Reset events : {len(resets)}")
    print()

    return resets


# ============================================================
# BINARY SEARCH HELPERS
# ============================================================

def get_window(records, center_clock, window_sec):
    """
    Return records within:

        center_clock +/- window_sec
    """

    result = []

    start = center_clock - window_sec
    end = center_clock + window_sec

    for record in records:

        clock = int(
            record.get("clock", 0)
        )

        if start <= clock <= end:
            result.append(record)

    return result


def get_context(records, center_clock, count):
    """
    Return:

        previous N records
        next N records

    around center_clock.
    """

    before = []
    after = []

    for record in records:

        clock = int(
            record.get("clock", 0)
        )

        if clock < center_clock:
            before.append(record)

        elif clock > center_clock:
            after.append(record)

    before = before[-count:]

    after = after[:count]

    return before, after


# ============================================================
# COUNTER BEHAVIOR ANALYSIS
# ============================================================

def analyze_counter_behavior(
    reset,
    item_records,
):
    """
    Determine whether a decrease looks like a real
    counter reset.

    Checks:

        - decrease ratio
        - current value
        - post-reset low value
        - post-reset monotonic increase
        - number of post-reset increases
        - number of post-reset decreases
    """

    reset_clock = reset["reset_clock"]

    current_value = reset[
        "current_raw_value"
    ]

    previous_value = reset[
        "previous_raw_value"
    ]

    decrease = reset[
        "decrease"
    ]

    if previous_value > 0:

        decrease_ratio = (
            decrease / previous_value
        )

    else:
        decrease_ratio = None

    before, after = get_context(
        item_records,
        reset_clock,
        CONTEXT_SAMPLES,
    )

    post_values = []

    for record in after:

        raw_value = safe_float(
            record.get("raw_value")
        )

        if raw_value is not None:
            post_values.append(raw_value)

    # --------------------------------------------------------
    # Post reset monotonic behavior
    # --------------------------------------------------------

    monotonic_increases = 0
    monotonic_decreases = 0
    unchanged = 0

    for previous, current in zip(
        post_values,
        post_values[1:],
    ):

        if current > previous:
            monotonic_increases += 1

        elif current < previous:
            monotonic_decreases += 1

        else:
            unchanged += 1

    # --------------------------------------------------------
    # Determine whether counter restarts low
    # --------------------------------------------------------

    low_absolute = (
        current_value <= LOW_ABSOLUTE_VALUE
    )

    low_relative = False

    if previous_value > 0:

        low_relative = (
            current_value
            <= previous_value * LOW_VALUE_RATIO
        )

    low_after_reset = (
        low_absolute
        or low_relative
    )

    enough_post_samples = (
        len(post_values)
        >= POST_RESET_MONOTONIC_SAMPLES
    )

    post_reset_monotonic = False

    if enough_post_samples:

        required_increases = (
            POST_RESET_MONOTONIC_SAMPLES - 1
        )

        post_reset_monotonic = (
            monotonic_increases
            >= required_increases
            and monotonic_decreases == 0
        )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if (
        low_after_reset
        and post_reset_monotonic
        and (
            decrease_ratio is None
            or decrease_ratio >= MIN_RESET_RATIO
        )
    ):

        classification = (
            "likely_true_counter_reset"
        )

    elif (
        decrease_ratio is not None
        and decrease_ratio < MIN_RESET_RATIO
    ):

        classification = (
            "minor_counter_decrease"
        )

    elif (
        low_after_reset
        and enough_post_samples
        and monotonic_increases > 0
    ):

        classification = (
            "possible_counter_reset"
        )

    else:

        classification = (
            "counter_behavior_uncertain"
        )

    return {
        "before_samples": [
            {
                "clock": r.get("clock"),
                "timestamp": r.get(
                    "timestamp"
                ),
                "raw_value": r.get(
                    "raw_value"
                ),
            }
            for r in before
        ],
        "after_samples": [
            {
                "clock": r.get("clock"),
                "timestamp": r.get(
                    "timestamp"
                ),
                "raw_value": r.get(
                    "raw_value"
                ),
            }
            for r in after
        ],
        "decrease_ratio": decrease_ratio,
        "low_absolute": low_absolute,
        "low_relative": low_relative,
        "low_after_reset": low_after_reset,
        "post_values": post_values,
        "post_reset_monotonic": (
            post_reset_monotonic
        ),
        "post_monotonic_increases": (
            monotonic_increases
        ),
        "post_monotonic_decreases": (
            monotonic_decreases
        ),
        "post_unchanged": unchanged,
        "post_sample_count": len(
            post_values
        ),
        "classification": classification,
    }


# ============================================================
# RELATED METRIC CORRELATION
# ============================================================

def correlate_related_metrics(
    reset,
    indexes,
):
    """
    Correlate reset with:

        same interface:
            traffic
            packets
            errors
            discards
            oper_status

        same host:
            uptime
            ICMP
            CPU
            memory
            etc.
    """

    hostid = str(
        reset["hostid"]
    )

    ifindex = reset.get(
        "ifIndex"
    )

    reset_clock = reset[
        "reset_clock"
    ]

    result = {
        "same_interface": {},
        "same_host": {},
    }

    # ========================================================
    # SAME INTERFACE
    # ========================================================

    if ifindex is not None:

        interface_records = indexes[
            "interface"
        ].get(
            (
                hostid,
                ifindex,
            ),
            [],
        )

        window = get_window(
            interface_records,
            reset_clock,
            CORRELATION_WINDOW_SEC,
        )

        by_metric = defaultdict(list)

        for record in window:

            canonical = record.get(
                "canonical_metric"
            )

            if canonical in RELATED_METRICS:

                by_metric[
                    canonical
                ].append(record)

        for metric, metric_records in by_metric.items():

            values = []

            for record in metric_records:

                value = safe_float(
                    record.get("value")
                )

                raw_value = safe_float(
                    record.get("raw_value")
                )

                values.append(
                    {
                        "clock": record.get(
                            "clock"
                        ),
                        "timestamp": record.get(
                            "timestamp"
                        ),
                        "value": value,
                        "raw_value": raw_value,
                    }
                )

            result[
                "same_interface"
            ][metric] = values

    # ========================================================
    # SAME HOST
    # ========================================================

    host_records = indexes[
        "host"
    ].get(
        hostid,
        [],
    )

    host_window = get_window(
        host_records,
        reset_clock,
        CORRELATION_WINDOW_SEC,
    )

    host_by_metric = defaultdict(list)

    for record in host_window:

        canonical = record.get(
            "canonical_metric"
        )

        if canonical in RELATED_METRICS:

            host_by_metric[
                canonical
            ].append(record)

    for metric, metric_records in host_by_metric.items():

        values = []

        for record in metric_records:

            value = safe_float(
                record.get("value")
            )

            raw_value = safe_float(
                record.get("raw_value")
            )

            values.append(
                {
                    "clock": record.get(
                        "clock"
                    ),
                    "timestamp": record.get(
                        "timestamp"
                    ),
                    "value": value,
                    "raw_value": raw_value,
                }
            )

        result[
            "same_host"
        ][metric] = values

    return result


# ============================================================
# OPER STATUS ANALYSIS
# ============================================================

def detect_oper_status_change(
    reset,
    correlation,
):
    """
    Detect whether oper_status changed around reset.

    This is specifically used to determine whether
    the reset coincides with interface flap.
    """

    records = correlation[
        "same_interface"
    ].get(
        "oper_status",
        [],
    )

    if not records:
        return {
            "detected": False,
            "changes": [],
        }

    values = []

    for record in records:

        value = safe_float(
            record.get("value")
        )

        if value is None:
            continue

        values.append(
            (
                int(record["clock"]),
                value,
            )
        )

    values.sort()

    changes = []

    previous = None

    for clock, value in values:

        if previous is not None:

            previous_clock, previous_value = previous

            if value != previous_value:

                changes.append(
                    {
                        "from": previous_value,
                        "to": value,
                        "from_clock": previous_clock,
                        "to_clock": clock,
                        "delta_time_sec": (
                            clock
                            - previous_clock
                        ),
                    }
                )

        previous = (
            clock,
            value,
        )

    return {
        "detected": len(changes) > 0,
        "changes": changes,
    }


# ============================================================
# UPTIME ANALYSIS
# ============================================================

def detect_uptime_decrease(
    correlation,
):
    """
    Detect host uptime decrease around reset.
    """

    records = correlation[
        "same_host"
    ].get(
        "uptime",
        [],
    )

    if not records:

        return {
            "detected": False,
            "decreases": [],
        }

    values = []

    for record in records:

        value = safe_float(
            record.get("value")
        )

        if value is None:
            value = safe_float(
                record.get("raw_value")
            )

        if value is None:
            continue

        values.append(
            (
                int(record["clock"]),
                value,
            )
        )

    values.sort()

    decreases = []

    previous = None

    for clock, value in values:

        if previous is not None:

            previous_clock, previous_value = previous

            if value < previous_value:

                decreases.append(
                    {
                        "from": previous_value,
                        "to": value,
                        "from_clock": previous_clock,
                        "to_clock": clock,
                    }
                )

        previous = (
            clock,
            value,
        )

    return {
        "detected": len(decreases) > 0,
        "decreases": decreases,
    }


# ============================================================
# RESET PERIODICITY
# ============================================================

def analyze_reset_periodicity(
    resets
):
    """
    Determine whether the same item/interface experiences
    repeated resets.

    This is important because repeated small decreases
    can indicate a counter implementation/problem rather
    than a one-time operational reset.
    """

    item_counts = Counter()

    interface_counts = Counter()

    host_counts = Counter()

    for reset in resets:

        itemid = str(
            reset["itemid"]
        )

        hostid = str(
            reset["hostid"]
        )

        ifindex = reset.get(
            "ifIndex"
        )

        item_counts[itemid] += 1

        host_counts[hostid] += 1

        if ifindex is not None:

            interface_counts[
                (
                    hostid,
                    ifindex,
                )
            ] += 1

    return {
        "by_item": dict(
            item_counts.most_common()
        ),
        "by_interface": {
            f"{hostid}:{ifindex}": count
            for (
                hostid,
                ifindex,
            ), count in interface_counts.most_common()
        },
        "by_host": dict(
            host_counts.most_common()
        ),
    }


# ============================================================
# RESET INTERVAL ANALYSIS
# ============================================================

def analyze_reset_intervals(
    resets
):
    """
    Calculate intervals between resets for the same item.
    """

    item_times = defaultdict(list)

    for reset in resets:

        itemid = str(
            reset["itemid"]
        )

        clock = int(
            reset["reset_clock"]
        )

        item_times[
            itemid
        ].append(clock)

    interval_stats = {}

    for itemid, clocks in item_times.items():

        clocks.sort()

        intervals = []

        for previous, current in zip(
            clocks,
            clocks[1:],
        ):

            interval = (
                current - previous
            )

            if interval > 0:
                intervals.append(
                    interval
                )

        if intervals:

            interval_stats[itemid] = {
                "count": len(intervals),
                "min_sec": min(intervals),
                "max_sec": max(intervals),
                "mean_sec": (
                    statistics.mean(
                        intervals
                    )
                ),
                "median_sec": (
                    statistics.median(
                        intervals
                    )
                ),
            }

    return interval_stats


# ============================================================
# SINGLE RESET DEEP ANALYSIS
# ============================================================

def analyze_reset(
    reset,
    indexes,
):
    """
    Full analysis of one reset.
    """

    itemid = str(
        reset["itemid"]
    )

    item_records = indexes[
        "item"
    ].get(
        itemid,
        [],
    )

    behavior = analyze_counter_behavior(
        reset,
        item_records,
    )

    correlation = correlate_related_metrics(
        reset,
        indexes,
    )

    oper_status = detect_oper_status_change(
        reset,
        correlation,
    )

    uptime = detect_uptime_decrease(
        correlation,
    )

    return {
        **reset,

        "counter_behavior": behavior,

        "correlation": correlation,

        "oper_status_analysis": oper_status,

        "uptime_analysis": uptime,
    }


# ============================================================
# SUMMARY
# ============================================================

def build_summary(
    analyses,
):
    """
    Build aggregate statistics.
    """

    classification_counts = Counter()

    metric_counts = Counter()

    role_counts = Counter()

    host_counts = Counter()

    ifindex_counts = Counter()

    decrease_values = []

    decrease_ratios = []

    true_reset_candidates = 0

    possible_reset_candidates = 0

    minor_decreases = 0

    uncertain = 0

    oper_status_events = 0

    uptime_events = 0

    for analysis in analyses:

        classification = analysis[
            "counter_behavior"
        ][
            "classification"
        ]

        classification_counts[
            classification
        ] += 1

        metric_counts[
            analysis["canonical_metric"]
        ] += 1

        role_counts[
            analysis["device_role"]
        ] += 1

        host_counts[
            analysis["host_name"]
            or analysis["host"]
        ] += 1

        if analysis["ifIndex"] is not None:

            ifindex_counts[
                (
                    analysis["hostid"],
                    analysis["ifIndex"],
                )
            ] += 1

        decrease = analysis[
            "decrease"
        ]

        decrease_values.append(
            decrease
        )

        ratio = analysis[
            "counter_behavior"
        ][
            "decrease_ratio"
        ]

        if ratio is not None:
            decrease_ratios.append(
                ratio
            )

        if (
            classification
            == "likely_true_counter_reset"
        ):
            true_reset_candidates += 1

        elif (
            classification
            == "possible_counter_reset"
        ):
            possible_reset_candidates += 1

        elif (
            classification
            == "minor_counter_decrease"
        ):
            minor_decreases += 1

        else:
            uncertain += 1

        if analysis[
            "oper_status_analysis"
        ][
            "detected"
        ]:

            oper_status_events += 1

        if analysis[
            "uptime_analysis"
        ][
            "detected"
        ]:

            uptime_events += 1

    return {
        "total_reset_events": len(
            analyses
        ),

        "by_classification": dict(
            classification_counts
        ),

        "by_canonical_metric": dict(
            metric_counts
        ),

        "by_device_role": dict(
            role_counts
        ),

        "top_hosts": dict(
            host_counts.most_common(20)
        ),

        "top_interfaces": {
            f"{hostid}:{ifindex}": count
            for (
                hostid,
                ifindex,
            ), count in ifindex_counts.most_common(20)
        },

        "reset_magnitude": {
            "count": len(
                decrease_values
            ),
            "min": min(
                decrease_values
            )
            if decrease_values
            else None,
            "max": max(
                decrease_values
            )
            if decrease_values
            else None,
            "mean": statistics.mean(
                decrease_values
            )
            if decrease_values
            else None,
            "median": statistics.median(
                decrease_values
            )
            if decrease_values
            else None,
            "p95": percentile(
                decrease_values,
                0.95,
            ),
            "p99": percentile(
                decrease_values,
                0.99,
            ),
        },

        "decrease_ratio": {
            "count": len(
                decrease_ratios
            ),
            "min": min(
                decrease_ratios
            )
            if decrease_ratios
            else None,
            "max": max(
                decrease_ratios
            )
            if decrease_ratios
            else None,
            "mean": statistics.mean(
                decrease_ratios
            )
            if decrease_ratios
            else None,
            "median": statistics.median(
                decrease_ratios
            )
            if decrease_ratios
            else None,
        },

        "correlation": {
            "oper_status_change": (
                oper_status_events
            ),
            "uptime_decrease": (
                uptime_events
            ),
        },

        "classification_counts": {
            "likely_true_counter_reset": (
                true_reset_candidates
            ),
            "possible_counter_reset": (
                possible_reset_candidates
            ),
            "minor_counter_decrease": (
                minor_decreases
            ),
            "counter_behavior_uncertain": (
                uncertain
            ),
        },
    }


# ============================================================
# PRINT DETAILED RESET TABLE
# ============================================================

def print_reset_table(
    analyses
):
    """
    Print compact table of all 231 resets.
    """

    print()
    print("=" * 110)
    print("RESET EVENTS")
    print("=" * 110)

    header = (
        f"{'#':>3} "
        f"{'Host':<25} "
        f"{'Metric':<20} "
        f"{'ifIndex':>7} "
        f"{'Before':>10} "
        f"{'After':>10} "
        f"{'Dec':>7} "
        f"{'Class':<30}"
    )

    print(header)
    print("-" * 110)

    for index, analysis in enumerate(
        analyses,
        1,
    ):

        host = (
            analysis["host_name"]
            or analysis["host"]
            or "-"
        )

        host = str(host)[:25]

        metric = str(
            analysis["canonical_metric"]
        )[:20]

        ifindex = (
            str(analysis["ifIndex"])
            if analysis["ifIndex"] is not None
            else "-"
        )

        classification = analysis[
            "counter_behavior"
        ][
            "classification"
        ]

        print(
            f"{index:>3} "
            f"{host:<25} "
            f"{metric:<20} "
            f"{ifindex:>7} "
            f"{analysis['previous_raw_value']:>10.2f} "
            f"{analysis['current_raw_value']:>10.2f} "
            f"{analysis['decrease']:>7.2f} "
            f"{classification:<30}"
        )


# ============================================================
# PRINT SAMPLE CONTEXT
# ============================================================

def print_interesting_resets(
    analyses
):
    """
    Print detailed examples.

    We select the first 20 resets that look most interesting.
    """

    interesting = []

    for analysis in analyses:

        behavior = analysis[
            "counter_behavior"
        ]

        if (
            behavior["classification"]
            == "likely_true_counter_reset"
        ):

            interesting.append(
                analysis
            )

    if not interesting:
        return

    print()
    print("=" * 110)
    print("INTERESTING RESET EXAMPLES")
    print("=" * 110)

    for index, analysis in enumerate(
        interesting[:20],
        1,
    ):

        print()
        print(
            f"[{index}] "
            f"{analysis['host_name']}"
            f" | {analysis['canonical_metric']}"
            f" | ifIndex={analysis['ifIndex']}"
            f" | itemid={analysis['itemid']}"
        )

        print(
            f"    Reset: "
            f"{analysis['previous_raw_value']}"
            f" -> "
            f"{analysis['current_raw_value']}"
            f" "
            f"(decrease="
            f"{analysis['decrease']})"
        )

        print(
            f"    Ratio: "
            f"{analysis['counter_behavior']['decrease_ratio']}"
        )

        print(
            f"    Classification: "
            f"{analysis['counter_behavior']['classification']}"
        )

        print(
            "    Post-reset values:"
        )

        post_values = analysis[
            "counter_behavior"
        ][
            "post_values"
        ]

        print(
            "      "
            + " -> ".join(
                str(v)
                for v in post_values
            )
        )

        print(
            f"    Monotonic increase: "
            f"{analysis['counter_behavior']['post_reset_monotonic']}"
        )

        print(
            f"    Oper status change: "
            f"{analysis['oper_status_analysis']['detected']}"
        )

        print(
            f"    Uptime decrease: "
            f"{analysis['uptime_analysis']['detected']}"
        )


# ============================================================
# FINAL REPORT
# ============================================================

def build_report(
    records,
    resets,
    analyses,
    indexes,
    parse_errors,
    semantic_count,
):
    """
    Build complete JSON report.
    """

    summary = build_summary(
        analyses
    )

    periodicity = analyze_reset_periodicity(
        resets
    )

    reset_intervals = analyze_reset_intervals(
        resets
    )

    report = {
        "audit": {
            "name": "counter_semantics_deep_audit",
            "version": "1.0",
            "purpose": (
                "Deep semantic analysis of counter "
                "decrease/reset events."
            ),
            "source_history": (
                TRANSFORMED_HISTORY_FILE
            ),
            "source_semantic": (
                SEMANTIC_METRICS_FILE
            ),
        },

        "configuration": {
            "context_samples": (
                CONTEXT_SAMPLES
            ),
            "correlation_window_sec": (
                CORRELATION_WINDOW_SEC
            ),
            "post_reset_monotonic_samples": (
                POST_RESET_MONOTONIC_SAMPLES
            ),
            "min_reset_ratio": (
                MIN_RESET_RATIO
            ),
            "low_value_ratio": (
                LOW_VALUE_RATIO
            ),
            "low_absolute_value": (
                LOW_ABSOLUTE_VALUE
            ),
        },

        "input": {
            "history_records": len(
                records
            ),
            "semantic_metrics": (
                semantic_count
            ),
            "parse_errors": (
                parse_errors
            ),
        },

        "reset_detection": {
            "reset_events": len(
                resets
            ),
        },

        "summary": summary,

        "periodicity": periodicity,

        "reset_intervals": reset_intervals,

        "events": analyses,
    }

    return report


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("COUNTER SEMANTICS DEEP AUDIT")
    print("=" * 80)
    print()

    # --------------------------------------------------------
    # Validate files
    # --------------------------------------------------------

    if not Path(
        TRANSFORMED_HISTORY_FILE
    ).exists():

        raise FileNotFoundError(
            f"File not found: "
            f"{TRANSFORMED_HISTORY_FILE}"
        )

    if not Path(
        SEMANTIC_METRICS_FILE
    ).exists():

        raise FileNotFoundError(
            f"File not found: "
            f"{SEMANTIC_METRICS_FILE}"
        )

    # --------------------------------------------------------
    # Load semantic metrics
    # --------------------------------------------------------

    semantic_map = load_semantic_metrics(
        SEMANTIC_METRICS_FILE
    )

    # --------------------------------------------------------
    # Load history
    # --------------------------------------------------------

    records, parse_errors = load_history(
        TRANSFORMED_HISTORY_FILE
    )

    # --------------------------------------------------------
    # Enrich
    # --------------------------------------------------------

    records = enrich_records(
        records,
        semantic_map,
    )

    # --------------------------------------------------------
    # Index
    # --------------------------------------------------------

    indexes = build_indexes(
        records
    )

    # --------------------------------------------------------
    # Detect resets
    # --------------------------------------------------------

    resets = find_reset_events(
        records
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # We expect the known 231 reset events.
    #
    # If the number changes, the script does NOT silently
    # assume it is correct.
    # --------------------------------------------------------

    if len(resets) != 231:

        print()
        print(
            "WARNING:"
        )

        print(
            f"Expected 231 reset events, "
            f"but detected {len(resets)}."
        )

        print(
            "The audit will continue using "
            "the detected reset events."
        )

        print()

    # --------------------------------------------------------
    # Deep analysis
    # --------------------------------------------------------

    print(
        "[5/6] Performing deep reset analysis"
    )

    analyses = []

    total = len(resets)

    for index, reset in enumerate(
        resets,
        1,
    ):

        analysis = analyze_reset(
            reset,
            indexes,
        )

        analyses.append(
            analysis
        )

        if (
            index == 1
            or index % 25 == 0
            or index == total
        ):

            print(
                f"Processed "
                f"{index}/{total}"
            )

    print()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "[6/6] Building final audit report"
    )

    report = build_report(
        records=records,
        resets=resets,
        analyses=analyses,
        indexes=indexes,
        parse_errors=parse_errors,
        semantic_count=len(
            semantic_map
        ),
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # --------------------------------------------------------
    # Console report
    # --------------------------------------------------------

    summary = report[
        "summary"
    ]

    print()
    print("=" * 80)
    print("COUNTER SEMANTICS DEEP AUDIT")
    print("=" * 80)

    print()

    print(
        f"History records : "
        f"{len(records):,}"
    )

    print(
        f"Reset events    : "
        f"{len(resets):,}"
    )

    print()

    print(
        "By canonical metric:"
    )

    for metric, count in sorted(
        summary[
            "by_canonical_metric"
        ].items()
    ):

        print(
            f"  {metric:<30} : "
            f"{count:,}"
        )

    print()

    print(
        "By classification:"
    )

    for classification, count in sorted(
        summary[
            "by_classification"
        ].items()
    ):

        print(
            f"  {classification:<40} : "
            f"{count:,}"
        )

    print()

    print(
        "By device role:"
    )

    for role, count in sorted(
        summary[
            "by_device_role"
        ].items()
    ):

        print(
            f"  {role:<30} : "
            f"{count:,}"
        )

    print()

    magnitude = summary[
        "reset_magnitude"
    ]

    print(
        "Reset magnitude:"
    )

    print(
        f"  Count  : "
        f"{magnitude['count']}"
    )

    print(
        f"  Min    : "
        f"{magnitude['min']}"
    )

    print(
        f"  Max    : "
        f"{magnitude['max']}"
    )

    print(
        f"  Mean   : "
        f"{magnitude['mean']}"
    )

    print(
        f"  Median : "
        f"{magnitude['median']}"
    )

    print(
        f"  P95    : "
        f"{magnitude['p95']}"
    )

    print(
        f"  P99    : "
        f"{magnitude['p99']}"
    )

    print()

    ratio = summary[
        "decrease_ratio"
    ]

    print(
        "Decrease ratio:"
    )

    print(
        f"  Mean   : "
        f"{ratio['mean']}"
    )

    print(
        f"  Median : "
        f"{ratio['median']}"
    )

    print(
        f"  Min    : "
        f"{ratio['min']}"
    )

    print(
        f"  Max    : "
        f"{ratio['max']}"
    )

    print()

    correlation = summary[
        "correlation"
    ]

    print(
        "Correlation:"
    )

    print(
        f"  Oper status change : "
        f"{correlation['oper_status_change']}"
    )

    print(
        f"  Uptime decrease    : "
        f"{correlation['uptime_decrease']}"
    )

    print()

    print(
        "Top affected hosts:"
    )

    for host, count in summary[
        "top_hosts"
    ].items():

        print(
            f"  {host:<35} : "
            f"{count}"
        )

    print()

    print(
        "Top affected interfaces:"
    )

    for interface, count in summary[
        "top_interfaces"
    ].items():

        print(
            f"  {interface:<25} : "
            f"{count}"
        )

    print()

    print(
        "Output:"
    )

    print(
        f"  {OUTPUT_FILE}"
    )

    print()

    # --------------------------------------------------------
    # Interesting examples
    # --------------------------------------------------------

    print_interesting_resets(
        analyses
    )

    print()

    print("=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)
    print()


if __name__ == "__main__":
    main()