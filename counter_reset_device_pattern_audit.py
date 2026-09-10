import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

SEMANTIC_FILE = "semantic_metrics.json"
TRANSFORMED_FILE = "transformed_history.jsonl"
OUTPUT_FILE = "counter_reset_device_pattern_audit.json"

# How close timestamps must be to be considered correlated.
CORRELATION_WINDOW_SEC = 5

# Number of records before/after a reset to inspect.
CONTEXT_SAMPLES = 5

# Only these metrics are treated as interface cumulative counters.
TARGET_RESET_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
}

# Related cumulative interface counters.
RELATED_COUNTER_METRICS = {
    "in_bps",
    "out_bps",
    "in_error_rate",
    "out_error_rate",
    "in_discard_rate",
    "out_discard_rate",
    "interface_counter",
}

# Packet/rate metrics.
RELATED_RATE_METRICS = {
    "in_pps",
    "out_pps",
    "rate",
}

# Interface state.
RELATED_STATE_METRICS = {
    "oper_status",
}

# Host-level health.
HOST_HEALTH_METRICS = {
    "uptime",
    "cpu_pct",
    "memory_pct",
    "temperature_c",
    "fan_status",
    "psu_status",
    "icmp_loss_pct",
    "icmp_rtt_sec",
}


# ============================================================
# HELPERS
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_float(value):
    try:
        if value is None:
            return None

        x = float(value)

        if not math.isfinite(x):
            return None

        return x

    except (TypeError, ValueError):
        return None


def parse_ifindex(key):
    """
    Extract IF-MIB ifIndex from standard Zabbix SNMP interface keys.

    Examples:

        net.if.in[ifHCInOctets.34]
        net.if.out[ifHCOutOctets.34]
        net.if.in.errors[ifInErrors.34]
        net.if.out.discards[ifOutDiscards.34]
        net.if.status[ifOperStatus.34]

    Returns:
        int or None
    """

    if not key:
        return None

    patterns = [
        r"\bif(?:HC)?InOctets\.(\d+)\b",
        r"\bif(?:HC)?OutOctets\.(\d+)\b",

        r"\bifInUcastPkts\.(\d+)\b",
        r"\bifOutUcastPkts\.(\d+)\b",

        r"\bifInErrors\.(\d+)\b",
        r"\bifOutErrors\.(\d+)\b",

        r"\bifInDiscards\.(\d+)\b",
        r"\bifOutDiscards\.(\d+)\b",

        r"\bifOperStatus\.(\d+)\b",
        r"\bifAdminStatus\.(\d+)\b",

        r"\bifInUnknownProtos\.(\d+)\b",
        r"\bifInMulticastPkts\.(\d+)\b",
        r"\bifInBroadcastPkts\.(\d+)\b",
        r"\bifOutMulticastPkts\.(\d+)\b",
        r"\bifOutBroadcastPkts\.(\d+)\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, key)

        if match:
            return int(match.group(1))

    return None


def iso_timestamp(clock):
    return datetime.fromtimestamp(
        clock
    ).astimezone().isoformat()


def safe_ratio(a, b):
    if b is None or b == 0:
        return None

    return abs(a) / abs(b)


# ============================================================
# LOAD SEMANTIC METRICS
# ============================================================

def load_semantic_metrics(path):
    data = load_json(path)

    if isinstance(data, list):
        metrics = data
        source_format = "list"

    elif isinstance(data, dict):
        metrics = data.get("metrics", [])

        if not isinstance(metrics, list):
            raise ValueError(
                "semantic_metrics.json contains 'metrics' "
                "but it is not a list"
            )

        source_format = "object"

    else:
        raise ValueError(
            "Unsupported semantic_metrics.json format"
        )

    item_map = {}
    invalid = 0
    duplicate_itemids = 0

    for metric in metrics:

        if not isinstance(metric, dict):
            invalid += 1
            continue

        itemid = str(metric.get("itemid", "")).strip()

        if not itemid:
            invalid += 1
            continue

        if itemid in item_map:
            duplicate_itemids += 1

        item_map[itemid] = metric

    print(f"Source format    : {source_format}")
    print(f"Semantic metrics : {len(metrics)}")
    print(f"Item map         : {len(item_map)}")
    print(f"Invalid records  : {invalid}")
    print(f"Duplicate itemid : {duplicate_itemids}")

    return item_map


# ============================================================
# LOAD TRANSFORMED HISTORY
# ============================================================

def load_history(path, item_map):

    records = []

    parse_errors = 0
    missing_semantic = 0

    with open(path, "r", encoding="utf-8") as f:

        for line_no, line in enumerate(f, 1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError:
                parse_errors += 1
                continue

            itemid = str(record.get("itemid", ""))

            semantic = item_map.get(itemid)

            if semantic is None:
                missing_semantic += 1
                continue

            record["_key"] = semantic.get("key", "")
            record["_canonical_metric"] = semantic.get(
                "canonical_metric"
            )
            record["_semantic_type"] = semantic.get(
                "semantic_type"
            )
            record["_transformation"] = semantic.get(
                "transformation"
            )
            record["_ifindex"] = parse_ifindex(
                semantic.get("key", "")
            )

            records.append(record)

    print(f"Records          : {len(records)}")
    print(f"Parse errors     : {parse_errors}")
    print(f"Missing semantic : {missing_semantic}")

    return records


# ============================================================
# BUILD INDEXES
# ============================================================

def build_indexes(records):

    by_item = defaultdict(list)

    by_interface = defaultdict(list)

    by_host = defaultdict(list)

    by_interface_metric = defaultdict(list)

    by_host_metric = defaultdict(list)

    for record in records:

        itemid = str(record.get("itemid"))

        hostid = str(record.get("hostid"))

        ifindex = record.get("_ifindex")

        metric = record.get("_canonical_metric")

        clock = record.get("clock")

        if clock is None:
            continue

        by_item[itemid].append(record)

        by_host[hostid].append(record)

        if ifindex is not None:
            interface_key = (
                hostid,
                int(ifindex),
            )

            by_interface[interface_key].append(record)

            by_interface_metric[
                (
                    hostid,
                    int(ifindex),
                    metric,
                )
            ].append(record)

        by_host_metric[
            (
                hostid,
                metric,
            )
        ].append(record)

    # Sort everything chronologically.

    for collection in (
        by_item,
        by_interface,
        by_host,
        by_interface_metric,
        by_host_metric,
    ):

        for key in collection:
            collection[key].sort(
                key=lambda x: x.get("clock", 0)
            )

    print(f"Items indexed       : {len(by_item)}")
    print(f"Hosts indexed       : {len(by_host)}")
    print(f"Interfaces indexed  : {len(by_interface)}")
    print(f"Interface metrics   : {len(by_interface_metric)}")

    return {
        "by_item": by_item,
        "by_interface": by_interface,
        "by_host": by_host,
        "by_interface_metric": by_interface_metric,
        "by_host_metric": by_host_metric,
    }


# ============================================================
# FIND COUNTER RESET EVENTS
# ============================================================

def find_counter_resets(records):

    resets = []

    # Important:
    # Compare consecutive samples belonging to the SAME item.
    # Never compare samples across different interfaces/items.

    by_item = defaultdict(list)

    for record in records:

        semantic_type = record.get("_semantic_type")
        transformation = record.get("_transformation")
        metric = record.get("_canonical_metric")

        if semantic_type != "counter":
            continue

        if transformation != "delta_rate":
            continue

        if metric not in TARGET_RESET_METRICS:
            continue

        by_item[str(record.get("itemid"))].append(record)

    for itemid, samples in by_item.items():

        samples.sort(
            key=lambda x: x.get("clock", 0)
        )

        previous = None

        for current in samples:

            current_clock = current.get("clock")
            current_raw = parse_float(
                current.get("raw_value")
            )

            if current_clock is None or current_raw is None:
                continue

            if previous is None:
                previous = current
                continue

            previous_clock = previous.get("clock")
            previous_raw = parse_float(
                previous.get("raw_value")
            )

            if (
                previous_clock is None
                or previous_raw is None
            ):
                previous = current
                continue

            # Duplicate timestamp.
            if current_clock == previous_clock:
                previous = current
                continue

            # Out of order.
            if current_clock < previous_clock:
                previous = current
                continue

            # Counter decrease.
            if current_raw < previous_raw:

                resets.append({
                    "itemid": itemid,
                    "hostid": str(
                        current.get("hostid")
                    ),
                    "host": current.get("host"),
                    "host_name": current.get(
                        "host_name"
                    ),
                    "device_role": current.get(
                        "device_role"
                    ),

                    "ifindex": current.get(
                        "_ifindex"
                    ),

                    "canonical_metric": current.get(
                        "_canonical_metric"
                    ),

                    "key": current.get(
                        "_key"
                    ),

                    "clock": current_clock,
                    "timestamp": current.get(
                        "timestamp"
                    ),

                    "previous_clock": previous_clock,
                    "previous_timestamp": previous.get(
                        "timestamp"
                    ),

                    "previous_raw_value": previous_raw,
                    "raw_value": current_raw,

                    "decrease": (
                        previous_raw - current_raw
                    ),

                    "decrease_ratio": (
                        (
                            previous_raw - current_raw
                        )
                        / previous_raw
                        if previous_raw != 0
                        else None
                    ),
                })

            previous = current

    return resets


# ============================================================
# FIND NEAREST SAMPLE
# ============================================================

def nearest_sample(samples, target_clock, window):

    best = None
    best_delta = None

    for record in samples:

        clock = record.get("clock")

        if clock is None:
            continue

        delta = abs(clock - target_clock)

        if delta > window:
            continue

        if best is None or delta < best_delta:

            best = record
            best_delta = delta

    return best


# ============================================================
# COUNTER STATE ANALYSIS
# ============================================================

def analyze_counter_state(
    samples,
    reset_clock,
):

    before = []
    after = []

    for record in samples:

        clock = record.get("clock")

        if clock is None:
            continue

        if clock < reset_clock:
            before.append(record)

        elif clock > reset_clock:
            after.append(record)

    before = before[-CONTEXT_SAMPLES:]
    after = after[:CONTEXT_SAMPLES]

    return before, after


def extract_sequence(samples):

    sequence = []

    for record in samples:

        value = parse_float(
            record.get("raw_value")
        )

        if value is None:
            continue

        sequence.append({
            "timestamp": record.get(
                "timestamp"
            ),
            "clock": record.get("clock"),
            "raw_value": value,
        })

    return sequence


# ============================================================
# CHECK MONOTONICITY
# ============================================================

def is_monotonic_increase(samples):

    values = []

    for record in samples:

        value = parse_float(
            record.get("raw_value")
        )

        if value is None:
            continue

        values.append(value)

    if len(values) < 2:
        return False

    for previous, current in zip(
        values,
        values[1:]
    ):

        if current < previous:
            return False

    return True


# ============================================================
# DEVICE-WIDE PATTERN ANALYSIS
# ============================================================

def analyze_device_pattern(
    reset,
    indexes,
):

    hostid = reset["hostid"]
    ifindex = reset["ifindex"]
    reset_clock = reset["clock"]

    interface_key = (
        hostid,
        ifindex,
    )

    # --------------------------------------------------------
    # Same interface
    # --------------------------------------------------------

    same_interface = indexes[
        "by_interface"
    ].get(interface_key, [])

    before_interface, after_interface = (
        analyze_counter_state(
            same_interface,
            reset_clock,
        )
    )

    related_interface_metrics = {}

    for metric in sorted(
        RELATED_COUNTER_METRICS
        | RELATED_RATE_METRICS
        | RELATED_STATE_METRICS
    ):

        samples = indexes[
            "by_interface_metric"
        ].get(
            (
                hostid,
                ifindex,
                metric,
            ),
            [],
        )

        nearest = nearest_sample(
            samples,
            reset_clock,
            CORRELATION_WINDOW_SEC,
        )

        if nearest is not None:

            related_interface_metrics[
                metric
            ] = {
                "itemid": nearest.get(
                    "itemid"
                ),
                "timestamp": nearest.get(
                    "timestamp"
                ),
                "clock": nearest.get(
                    "clock"
                ),
                "value": nearest.get(
                    "value"
                ),
                "raw_value": nearest.get(
                    "raw_value"
                ),
            }

    # --------------------------------------------------------
    # Same host
    # --------------------------------------------------------

    host_records = indexes[
        "by_host"
    ].get(hostid, [])

    same_timestamp_records = []

    nearby_records = []

    for record in host_records:

        clock = record.get("clock")

        if clock is None:
            continue

        delta = abs(
            clock - reset_clock
        )

        if delta == 0:

            same_timestamp_records.append(
                record
            )

        if delta <= CORRELATION_WINDOW_SEC:

            nearby_records.append(
                record
            )

    # --------------------------------------------------------
    # Count what happened at same timestamp.
    # --------------------------------------------------------

    metric_counts = Counter()

    interface_counts = Counter()

    for record in same_timestamp_records:

        metric = record.get(
            "_canonical_metric"
        )

        if metric:
            metric_counts[metric] += 1

        record_ifindex = record.get(
            "_ifindex"
        )

        if record_ifindex is not None:
            interface_counts[
                int(record_ifindex)
            ] += 1

    # --------------------------------------------------------
    # Detect same-interface counter decreases
    # in related metrics.
    # --------------------------------------------------------

    related_counter_decreases = []

    for metric in RELATED_COUNTER_METRICS:

        samples = indexes[
            "by_interface_metric"
        ].get(
            (
                hostid,
                ifindex,
                metric,
            ),
            [],
        )

        if len(samples) < 2:
            continue

        # Find samples surrounding reset.
        previous = None

        for sample in samples:

            clock = sample.get("clock")

            if clock is None:
                continue

            if clock > reset_clock + CORRELATION_WINDOW_SEC:
                break

            if (
                clock <= reset_clock
                and previous is not None
            ):

                prev_value = parse_float(
                    previous.get(
                        "raw_value"
                    )
                )

                curr_value = parse_float(
                    sample.get(
                        "raw_value"
                    )
                )

                if (
                    prev_value is not None
                    and curr_value is not None
                    and curr_value < prev_value
                ):

                    related_counter_decreases.append({
                        "canonical_metric": metric,
                        "previous_value": prev_value,
                        "current_value": curr_value,
                        "decrease": (
                            prev_value - curr_value
                        ),
                        "timestamp": sample.get(
                            "timestamp"
                        ),
                    })

            previous = sample

    # --------------------------------------------------------
    # Oper status changes.
    # --------------------------------------------------------

    oper_status_changes = []

    oper_samples = indexes[
        "by_interface_metric"
    ].get(
        (
            hostid,
            ifindex,
            "oper_status",
        ),
        [],
    )

    previous = None

    for sample in oper_samples:

        clock = sample.get("clock")

        if clock is None:
            continue

        if (
            clock < reset_clock
            - CORRELATION_WINDOW_SEC
        ):
            previous = sample
            continue

        if (
            clock
            > reset_clock
            + CORRELATION_WINDOW_SEC
        ):
            break

        if previous is not None:

            prev_value = parse_float(
                previous.get("value")
            )

            curr_value = parse_float(
                sample.get("value")
            )

            if (
                prev_value is not None
                and curr_value is not None
                and prev_value != curr_value
            ):

                oper_status_changes.append({
                    "timestamp": sample.get(
                        "timestamp"
                    ),
                    "previous": prev_value,
                    "current": curr_value,
                })

        previous = sample

    # --------------------------------------------------------
    # Device-wide reset count near timestamp.
    # --------------------------------------------------------

    discard_resets = 0
    other_counter_decreases = 0

    affected_interfaces = set()

    for record in nearby_records:

        metric = record.get(
            "_canonical_metric"
        )

        ifindex2 = record.get(
            "_ifindex"
        )

        # We cannot call a record a reset merely
        # because it is near another reset.
        #
        # Therefore only use explicit transformed
        # counter_reset=true or value=None after
        # transformation as supporting evidence.
        if record.get("counter_reset") is True:

            if metric in TARGET_RESET_METRICS:

                discard_resets += 1

            else:

                other_counter_decreases += 1

            if ifindex2 is not None:
                affected_interfaces.add(
                    int(ifindex2)
                )

    # --------------------------------------------------------
    # Device-wide coverage.
    # --------------------------------------------------------

    interface_count = len(
        affected_interfaces
    )

    # Add interfaces from same timestamp.
    for ifidx in interface_counts:
        affected_interfaces.add(
            int(ifidx)
        )

    # --------------------------------------------------------
    # Pattern classification.
    # --------------------------------------------------------

    related_decrease_count = len(
        related_counter_decreases
    )

    oper_status_count = len(
        oper_status_changes
    )

    same_timestamp_interface_count = len(
        interface_counts
    )

    # Important classification logic.
    #
    # Strong evidence of a device-wide counter
    # phenomenon if:
    #
    # - multiple interfaces are affected
    # - discard counters are the dominant changing metric
    # - no operStatus change
    #
    # This avoids calling it a network outage.

    if (
        same_timestamp_interface_count >= 3
        and related_decrease_count == 0
        and oper_status_count == 0
    ):

        classification = (
            "device_wide_discard_counter_behavior"
        )

        confidence = "high"

        reason = (
            "Multiple interfaces on the same device "
            "show synchronized discard-counter "
            "decreases while related interface counters "
            "and operStatus do not show corresponding "
            "decreases/state changes."
        )

    elif (
        same_timestamp_interface_count >= 3
        and related_decrease_count > 0
        and oper_status_count == 0
    ):

        classification = (
            "device_wide_multiple_counter_behavior"
        )

        confidence = "medium"

        reason = (
            "Multiple interfaces show synchronized "
            "counter decreases and at least one related "
            "counter also decreases."
        )

    elif oper_status_count > 0:

        classification = (
            "possible_interface_event"
        )

        confidence = "medium"

        reason = (
            "Counter decrease occurs near an "
            "operational status transition."
        )

    else:

        classification = (
            "isolated_counter_behavior"
        )

        confidence = "low"

        reason = (
            "No strong device-wide correlation was "
            "found around the counter decrease."
        )

    return {

        "interface": {
            "hostid": hostid,
            "ifindex": ifindex,
        },

        "same_timestamp": {
            "record_count": len(
                same_timestamp_records
            ),
            "interface_count": (
                same_timestamp_interface_count
            ),
            "metric_counts": dict(
                metric_counts
            ),
        },

        "nearby": {
            "record_count": len(
                nearby_records
            ),
            "affected_interface_count": (
                len(affected_interfaces)
            ),
        },

        "related_interface_metrics":
            related_interface_metrics,

        "related_counter_decreases":
            related_counter_decreases,

        "oper_status_changes":
            oper_status_changes,

        "device_wide": {
            "discard_resets_nearby":
                discard_resets,

            "other_counter_decreases_nearby":
                other_counter_decreases,

            "affected_interfaces":
                sorted(
                    affected_interfaces
                ),
        },

        "context": {
            "before": extract_sequence(
                before_interface
            ),

            "after": extract_sequence(
                after_interface
            ),

            "post_reset_monotonic":
                is_monotonic_increase(
                    after_interface
                ),
        },

        "classification": classification,
        "confidence": confidence,
        "reason": reason,
    }


# ============================================================
# RESET PERIODICITY
# ============================================================

def analyze_periodicity(resets):

    by_host = defaultdict(list)

    for reset in resets:

        by_host[
            reset["hostid"]
        ].append(
            reset["clock"]
        )

    results = {}

    for hostid, clocks in by_host.items():

        clocks.sort()

        intervals = []

        for previous, current in zip(
            clocks,
            clocks[1:],
        ):

            interval = current - previous

            if interval > 0:
                intervals.append(
                    interval
                )

        if not intervals:
            results[hostid] = {
                "reset_count": len(clocks),
                "intervals": [],
            }

            continue

        counter_intervals = Counter(
            intervals
        )

        results[hostid] = {

            "reset_count": len(
                clocks
            ),

            "intervals": intervals,

            "common_intervals": [
                {
                    "seconds": interval,
                    "count": count,
                }

                for interval, count
                in counter_intervals.most_common(10)
            ],

            "min_interval_sec":
                min(intervals),

            "max_interval_sec":
                max(intervals),

            "mean_interval_sec":
                sum(intervals)
                / len(intervals),
        }

    return results


# ============================================================
# GLOBAL PATTERN SUMMARY
# ============================================================

def build_summary(
    resets,
    analyses,
):

    classification_counts = Counter()

    confidence_counts = Counter()

    host_counts = Counter()

    role_counts = Counter()

    metric_counts = Counter()

    device_wide_count = 0

    multi_interface_count = 0

    related_counter_decrease_count = 0

    oper_status_change_count = 0

    same_timestamp_multi_interface = 0

    for reset, analysis in zip(
        resets,
        analyses,
    ):

        classification_counts[
            analysis["classification"]
        ] += 1

        confidence_counts[
            analysis["confidence"]
        ] += 1

        host = (
            reset.get("host_name")
            or reset.get("host")
            or reset.get("hostid")
        )

        host_counts[host] += 1

        role_counts[
            reset.get("device_role")
            or "unknown"
        ] += 1

        metric_counts[
            reset.get(
                "canonical_metric"
            )
        ] += 1

        same_timestamp_interfaces = (
            analysis[
                "same_timestamp"
            ][
                "interface_count"
            ]
        )

        if same_timestamp_interfaces >= 3:

            device_wide_count += 1

        if same_timestamp_interfaces >= 2:

            multi_interface_count += 1

            same_timestamp_multi_interface += 1

        if analysis[
            "related_counter_decreases"
        ]:

            related_counter_decrease_count += 1

        if analysis[
            "oper_status_changes"
        ]:

            oper_status_change_count += 1

    return {

        "total_resets": len(resets),

        "by_canonical_metric":
            dict(metric_counts),

        "by_device_role":
            dict(role_counts),

        "classification":
            dict(classification_counts),

        "confidence":
            dict(confidence_counts),

        "device_wide_pattern": {

            "events_with_3plus_interfaces":
                device_wide_count,

            "events_with_2plus_interfaces":
                multi_interface_count,

            "same_timestamp_multi_interface_events":
                same_timestamp_multi_interface,

            "events_with_related_counter_decrease":
                related_counter_decrease_count,

            "events_with_oper_status_change":
                oper_status_change_count,
        },

        "top_hosts": [
            {
                "host": host,
                "count": count,
            }

            for host, count
            in host_counts.most_common(20)
        ],
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("COUNTER RESET DEVICE PATTERN AUDIT")
    print("=" * 70)
    print()

    # --------------------------------------------------------
    # 1. Semantic metrics
    # --------------------------------------------------------

    print("[1/7] Loading semantic metrics")

    item_map = load_semantic_metrics(
        SEMANTIC_FILE
    )

    print()

    # --------------------------------------------------------
    # 2. History
    # --------------------------------------------------------

    print("[2/7] Loading transformed history")

    records = load_history(
        TRANSFORMED_FILE,
        item_map,
    )

    print()

    # --------------------------------------------------------
    # 3. Index
    # --------------------------------------------------------

    print("[3/7] Building indexes")

    indexes = build_indexes(
        records
    )

    print()

    # --------------------------------------------------------
    # 4. Find resets
    # --------------------------------------------------------

    print("[4/7] Finding counter reset events")

    resets = find_counter_resets(
        records
    )

    print(
        f"Reset events : {len(resets)}"
    )

    print()

    # --------------------------------------------------------
    # 5. Deep device pattern analysis
    # --------------------------------------------------------

    print(
        "[5/7] Analyzing device-wide patterns"
    )

    analyses = []

    total = len(resets)

    for index, reset in enumerate(
        resets,
        1,
    ):

        analysis = analyze_device_pattern(
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
                f"Processed {index}/{total}"
            )

    print()

    # --------------------------------------------------------
    # 6. Periodicity
    # --------------------------------------------------------

    print("[6/7] Analyzing reset periodicity")

    periodicity = analyze_periodicity(
        resets
    )

    print()

    # --------------------------------------------------------
    # 7. Final report
    # --------------------------------------------------------

    print(
        "[7/7] Building final audit report"
    )

    summary = build_summary(
        resets,
        analyses,
    )

    # --------------------------------------------------------
    # Human-readable report
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("COUNTER RESET DEVICE PATTERN AUDIT")
    print("=" * 70)

    print()

    print(
        f"History records : {len(records):,}"
    )

    print(
        f"Reset events    : {len(resets):,}"
    )

    print()

    print("By canonical metric:")

    for metric, count in sorted(
        summary[
            "by_canonical_metric"
        ].items()
    ):

        print(
            f"  {metric:<30} : {count}"
        )

    print()

    print("By device role:")

    for role, count in sorted(
        summary[
            "by_device_role"
        ].items()
    ):

        print(
            f"  {role:<30} : {count}"
        )

    print()

    print("Device-wide pattern:")

    pattern = summary[
        "device_wide_pattern"
    ]

    print(
        "  3+ interfaces at same timestamp : "
        f"{pattern['events_with_3plus_interfaces']}"
    )

    print(
        "  2+ interfaces at same timestamp : "
        f"{pattern['events_with_2plus_interfaces']}"
    )

    print(
        "  Related counter decreases       : "
        f"{pattern['events_with_related_counter_decrease']}"
    )

    print(
        "  OperStatus changes              : "
        f"{pattern['events_with_oper_status_change']}"
    )

    print()

    print("Classification:")

    for classification, count in sorted(
        summary[
            "classification"
        ].items()
    ):

        print(
            f"  {classification:<40} : {count}"
        )

    print()

    print("Confidence:")

    for confidence, count in sorted(
        summary[
            "confidence"
        ].items()
    ):

        print(
            f"  {confidence:<15} : {count}"
        )

    print()

    print("Top affected hosts:")

    for entry in summary[
        "top_hosts"
    ]:

        print(
            f"  {entry['host']:<35} : "
            f"{entry['count']}"
        )

    # --------------------------------------------------------
    # Build detailed event objects.
    # --------------------------------------------------------

    detailed_events = []

    for reset, analysis in zip(
        resets,
        analyses,
    ):

        detailed_events.append({

            "reset": reset,

            "device_pattern":
                analysis,

        })

    report = {

        "audit": {
            "name":
                "counter_reset_device_pattern_audit",

            "version":
                "1.0",

            "generated_at":
                datetime.now(
                    ).astimezone().isoformat(),

            "semantic_file":
                SEMANTIC_FILE,

            "transformed_file":
                TRANSFORMED_FILE,

            "correlation_window_sec":
                CORRELATION_WINDOW_SEC,

            "context_samples":
                CONTEXT_SAMPLES,
        },

        "summary":
            summary,

        "periodicity":
            periodicity,

        "events":
            detailed_events,
    }

    # --------------------------------------------------------
    # Write JSON
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

    print()

    print(
        f"[+] Output written to: "
        f"{OUTPUT_FILE}"
    )

    print()

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    fatal_errors = 0

    if len(resets) == 0:

        print(
            "Status : PASS"
        )

    else:

        print(
            "Status : PASS"
        )

    print()


if __name__ == "__main__":
    main()