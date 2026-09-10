import json
import re
import statistics
from collections import defaultdict, Counter
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

SEMANTIC_FILE = "semantic_metrics.json"
HISTORY_FILE = "transformed_history.jsonl"

OUTPUT_FILE = "counter_reset_cross_metric_audit.json"

TARGET_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
    "in_bps",
    "out_bps",
    "in_error_rate",
    "out_error_rate",
    "in_pps",
    "out_pps",
    "oper_status",
    "interface_counter",
}

DISCARD_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
}

COUNTER_METRICS = {
    "in_bps",
    "out_bps",
    "in_error_rate",
    "out_error_rate",
    "in_pps",
    "out_pps",
    "interface_counter",
}

STATUS_METRIC = "oper_status"

# Cross-metric correlation window.
# 60 seconds is appropriate because your data contains
# 60s / 180s sampling with some jitter.
CORRELATION_WINDOW_SEC = 60


# ============================================================
# LOADERS
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_semantic_metrics(path):
    """
    semantic_metrics.json can be either:

    [
        {...},
        {...}
    ]

    or:

    {
        "metrics": [
            {...}
        ]
    }
    """

    data = load_json(path)

    if isinstance(data, list):
        metrics = data

    elif isinstance(data, dict):
        metrics = data.get("metrics", [])

    else:
        raise ValueError(
            f"Unexpected semantic_metrics.json structure: {type(data)}"
        )

    return metrics


def load_history(path):
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                records.append(record)

            except json.JSONDecodeError as exc:
                print(
                    f"WARNING: invalid JSON at line {line_number}: {exc}"
                )

    return records


# ============================================================
# IFINDEX PARSER
# ============================================================

IFINDEX_PATTERNS = [
    # Standard:
    # net.if.in[ifHCInOctets.33]
    re.compile(r"\.(\d+)\]$"),

    # Possible quoted form:
    # net.if.in[ifHCInOctets,"33"]
    re.compile(r'["\'](\d+)["\']\]$'),

    # Generic:
    # something[...33]
    re.compile(r"(\d+)\]$"),
]


def parse_ifindex(key):
    """
    Extract IF-MIB ifIndex from Zabbix item key.

    Examples:

        net.if.in[ifHCInOctets.33]
            -> 33

        net.if.out.discards[ifOutDiscards.5]
            -> 5

        net.if.status[ifOperStatus.34]
            -> 34
    """

    if not key:
        return None

    for pattern in IFINDEX_PATTERNS:

        match = pattern.search(str(key))

        if match:
            return int(match.group(1))

    return None


# ============================================================
# INTERFACE IDENTITY
# ============================================================

def interface_identity(record):
    """
    IMPORTANT:

    Do NOT use Zabbix interfaceid here.

    Zabbix interfaceid identifies the polling interface,
    not necessarily the network interface represented by
    ifIndex.

    Correct identity:

        hostid + ifIndex
    """

    hostid = str(record.get("hostid", ""))

    ifindex = record.get("ifindex")

    if ifindex is None:
        ifindex = parse_ifindex(record.get("key", ""))

    if not hostid or ifindex is None:
        return None

    return hostid, int(ifindex)


# ============================================================
# BUILD SEMANTIC MAP
# ============================================================

def build_semantic_map(metrics):
    """
    itemid -> semantic metadata
    """

    item_map = {}

    for metric in metrics:

        itemid = str(metric.get("itemid", ""))

        if not itemid:
            continue

        item_map[itemid] = metric

    return item_map


# ============================================================
# ENRICH HISTORY
# ============================================================

def enrich_history(history, semantic_map):
    """
    Add semantic metadata to raw/transformed history.
    """

    enriched = []

    missing_semantic = 0

    for record in history:

        itemid = str(record.get("itemid", ""))

        metric = semantic_map.get(itemid)

        if metric is None:
            missing_semantic += 1
            continue

        canonical_metric = metric.get("canonical_metric")

        if canonical_metric not in TARGET_METRICS:
            continue

        new_record = dict(record)

        new_record["canonical_metric"] = canonical_metric
        new_record["semantic_type"] = metric.get("semantic_type")
        new_record["transformation"] = metric.get("transformation")
        new_record["key"] = metric.get("key")
        new_record["ifindex"] = parse_ifindex(metric.get("key", ""))

        identity = interface_identity(new_record)

        if identity is None:
            new_record["interface_identity"] = None

        else:
            new_record["interface_identity"] = identity

        enriched.append(new_record)

    return enriched, missing_semantic


# ============================================================
# GROUP HISTORY
# ============================================================

def build_interface_metric_index(records):
    """
    Build:

        (hostid, ifIndex)
            -> canonical_metric
                -> sorted records
    """

    index = defaultdict(lambda: defaultdict(list))

    for record in records:

        identity = record.get("interface_identity")

        if identity is None:
            continue

        metric = record.get("canonical_metric")

        if metric not in TARGET_METRICS:
            continue

        index[identity][metric].append(record)

    # Sort every metric series by clock.
    for identity in index:

        for metric in index[identity]:

            index[identity][metric].sort(
                key=lambda x: int(x.get("clock", 0))
            )

    return index


# ============================================================
# COUNTER DECREASE DETECTION
# ============================================================

def find_counter_decreases(records):
    """
    Find actual raw counter decreases.

    IMPORTANT:

    We use raw_value, not transformed value.

    A counter reset/decrease is:

        current_raw < previous_raw

    Duplicate and out-of-order timestamps are ignored.
    """

    events = []

    previous = None

    ordered = sorted(
        records,
        key=lambda x: int(x.get("clock", 0))
    )

    for current in ordered:

        clock = int(current.get("clock", 0))

        raw_value = current.get("raw_value")

        if raw_value is None:
            continue

        try:
            raw_value = float(raw_value)

        except (TypeError, ValueError):
            continue

        if previous is None:
            previous = (clock, raw_value, current)
            continue

        previous_clock, previous_value, previous_record = previous

        # Ignore duplicate timestamps.
        if clock == previous_clock:
            previous = (clock, raw_value, current)
            continue

        # Ignore out-of-order.
        if clock < previous_clock:
            continue

        if raw_value < previous_value:

            decrease = previous_value - raw_value

            ratio = None

            if previous_value != 0:
                ratio = decrease / abs(previous_value)

            event = {
                "itemid": current.get("itemid"),
                "hostid": current.get("hostid"),
                "host": current.get("host"),
                "host_name": current.get("host_name"),
                "device_role": current.get("device_role"),

                "ifindex": current.get("ifindex"),

                "canonical_metric": current.get(
                    "canonical_metric"
                ),

                "clock": clock,
                "timestamp": current.get("timestamp"),

                "previous_clock": previous_clock,
                "previous_timestamp": previous_record.get(
                    "timestamp"
                ),

                "previous_raw_value": previous_value,
                "raw_value": raw_value,

                "decrease": decrease,
                "decrease_ratio": ratio,
            }

            events.append(event)

        previous = (clock, raw_value, current)

    return events


# ============================================================
# OPER STATUS ANALYSIS
# ============================================================

def status_changes_near_event(
    status_records,
    event_clock,
    window_sec=60,
):
    """
    Detect operStatus changes around a discard reset.

    We look for actual value changes:

        previous status != current status

    Example:

        1 -> 2
        2 -> 1

    """

    changes = []

    ordered = sorted(
        status_records,
        key=lambda x: int(x.get("clock", 0))
    )

    previous = None

    for record in ordered:

        clock = int(record.get("clock", 0))

        value = record.get("raw_value")

        if value is None:
            value = record.get("value")

        if value is None:
            continue

        try:
            value = float(value)

        except (TypeError, ValueError):
            continue

        if previous is None:
            previous = (clock, value, record)
            continue

        previous_clock, previous_value, previous_record = previous

        if clock <= previous_clock:
            continue

        if value != previous_value:

            distance = abs(clock - event_clock)

            if distance <= window_sec:

                changes.append(
                    {
                        "clock": clock,
                        "timestamp": record.get("timestamp"),
                        "previous_value": previous_value,
                        "value": value,
                        "distance_sec": distance,
                    }
                )

        previous = (clock, value, record)

    return changes


# ============================================================
# CROSS-METRIC DECREASE ANALYSIS
# ============================================================

def find_cross_metric_decreases(
    metric_records,
    event_clock,
    target_metric,
    window_sec=60,
):
    """
    Determine whether another cumulative metric on the SAME
    interface also decreases near the discard event.

    This is the critical part that fixes the previous audit.

    We NEVER count:

        counter_reset == True

    because that could simply refer to another discard metric.

    Instead we independently inspect raw_value sequences for
    the target metric.
    """

    records = metric_records.get(target_metric, [])

    if not records:
        return []

    decreases = find_counter_decreases(records)

    correlated = []

    for decrease in decreases:

        distance = abs(
            int(decrease["clock"]) - int(event_clock)
        )

        if distance <= window_sec:

            event = dict(decrease)

            event["distance_sec"] = distance

            correlated.append(event)

    return correlated


# ============================================================
# ACTIVITY ANALYSIS
# ============================================================

def values_near_event(
    metric_records,
    metric,
    event_clock,
    window_sec=60,
):
    """
    Return records from another metric near the event.

    This is contextual evidence only.

    It does NOT classify a reset by itself.
    """

    records = metric_records.get(metric, [])

    result = []

    for record in records:

        clock = int(record.get("clock", 0))

        if abs(clock - event_clock) <= window_sec:

            result.append(
                {
                    "clock": clock,
                    "timestamp": record.get("timestamp"),
                    "value": record.get("value"),
                    "raw_value": record.get("raw_value"),
                }
            )

    return result


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_event(
    event,
    cross_metric_results,
    oper_status_changes,
):
    """
    Conservative classification.

    Case A:
        only discard decreases
        no other counters decrease
        no operStatus change

        -> discard_counter_only

    Case B:
        another cumulative counter decreases too

        -> multiple_counter_decrease

    Case C:
        operStatus changes

        -> possible_interface_event

    Case D:
        insufficient evidence

        -> uncertain
    """

    other_counter_decreases = []

    for metric, events in cross_metric_results.items():

        if metric in DISCARD_METRICS:
            continue

        if events:
            other_counter_decreases.extend(
                [
                    {
                        "metric": metric,
                        **item,
                    }
                    for item in events
                ]
            )

    if oper_status_changes:

        return (
            "possible_interface_event",
            "high"
            if other_counter_decreases
            else "medium",
        )

    if other_counter_decreases:

        return (
            "multiple_counter_decrease",
            "high",
        )

    if event["canonical_metric"] in DISCARD_METRICS:

        return (
            "discard_counter_only",
            "high",
        )

    return (
        "uncertain",
        "low",
    )


# ============================================================
# MAIN AUDIT
# ============================================================

def main():

    print("=" * 72)
    print("COUNTER RESET CROSS-METRIC AUDIT")
    print("=" * 72)

    print()

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    print("Loading semantic metrics...")

    semantic_metrics = load_semantic_metrics(
        SEMANTIC_FILE
    )

    print(
        f"Semantic metrics : {len(semantic_metrics):,}"
    )

    semantic_map = build_semantic_map(
        semantic_metrics
    )

    print(
        f"Item map         : {len(semantic_map):,}"
    )

    print()

    print("Loading transformed history...")

    history = load_history(
        HISTORY_FILE
    )

    print(
        f"History records  : {len(history):,}"
    )

    print()

    # --------------------------------------------------------
    # ENRICH
    # --------------------------------------------------------

    records, missing_semantic = enrich_history(
        history,
        semantic_map,
    )

    print(
        f"Relevant records : {len(records):,}"
    )

    print(
        f"Missing semantic : {missing_semantic:,}"
    )

    print()

    # --------------------------------------------------------
    # BUILD INDEX
    # --------------------------------------------------------

    print("Building interface/metric index...")

    interface_index = build_interface_metric_index(
        records
    )

    print(
        f"Interfaces       : {len(interface_index):,}"
    )

    print()

    # --------------------------------------------------------
    # FIND DISCARD RESETS
    # --------------------------------------------------------

    reset_events = []

    for identity, metric_records in interface_index.items():

        for metric in DISCARD_METRICS:

            records_for_metric = metric_records.get(
                metric,
                []
            )

            if not records_for_metric:
                continue

            events = find_counter_decreases(
                records_for_metric
            )

            reset_events.extend(events)

    print(
        f"Discard decrease events : {len(reset_events):,}"
    )

    print()

    # --------------------------------------------------------
    # CLASSIFY
    # --------------------------------------------------------

    classifications = Counter()
    confidence = Counter()

    detailed_events = []

    for event in reset_events:

        identity = (
            str(event["hostid"]),
            int(event["ifindex"])
        )

        metric_records = interface_index.get(
            identity,
            {}
        )

        event_clock = int(event["clock"])

        # ----------------------------------------------------
        # Cross metric decreases
        # ----------------------------------------------------

        cross_metric_results = {}

        for metric in COUNTER_METRICS:

            if metric in DISCARD_METRICS:
                continue

            correlated = find_cross_metric_decreases(
                metric_records,
                event_clock,
                metric,
                CORRELATION_WINDOW_SEC,
            )

            cross_metric_results[metric] = correlated

        # ----------------------------------------------------
        # OperStatus
        # ----------------------------------------------------

        status_changes = status_changes_near_event(
            metric_records.get(
                STATUS_METRIC,
                []
            ),
            event_clock,
            CORRELATION_WINDOW_SEC,
        )

        # ----------------------------------------------------
        # Activity context
        # ----------------------------------------------------

        activity = {}

        for metric in (
            "in_bps",
            "out_bps",
            "in_pps",
            "out_pps",
        ):

            activity[metric] = values_near_event(
                metric_records,
                metric,
                event_clock,
                CORRELATION_WINDOW_SEC,
            )

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        classification, confidence_level = classify_event(
            event,
            cross_metric_results,
            status_changes,
        )

        classifications[classification] += 1
        confidence[confidence_level] += 1

        detailed_events.append(
            {
                **event,

                "classification": classification,
                "confidence": confidence_level,

                "cross_metric_decreases": {
                    metric: events
                    for metric, events
                    in cross_metric_results.items()
                    if events
                },

                "oper_status_changes": status_changes,

                "activity": activity,
            }
        )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    print()

    print(
        f"Reset/decrease events : {len(reset_events):,}"
    )

    print()

    print("By canonical metric:")

    metric_counter = Counter(
        event["canonical_metric"]
        for event in reset_events
    )

    for metric, count in sorted(
        metric_counter.items()
    ):

        print(
            f"  {metric:30s}: {count:,}"
        )

    print()

    # --------------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------------

    print("Classification:")

    for classification, count in (
        classifications.most_common()
    ):

        percentage = (
            count / len(reset_events) * 100
            if reset_events
            else 0
        )

        print(
            f"  {classification:40s}: "
            f"{count:4d} "
            f"({percentage:6.2f}%)"
        )

    print()

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    print("Confidence:")

    for level, count in confidence.most_common():

        print(
            f"  {level:10s}: {count:,}"
        )

    print()

    # --------------------------------------------------------
    # CROSS-METRIC SUMMARY
    # --------------------------------------------------------

    cross_metric_summary = Counter()

    oper_status_event_count = 0

    for event in detailed_events:

        for metric in event[
            "cross_metric_decreases"
        ]:

            cross_metric_summary[metric] += 1

        if event["oper_status_changes"]:

            oper_status_event_count += 1

    print("Cross-metric decreases:")

    if cross_metric_summary:

        for metric, count in (
            cross_metric_summary.most_common()
        ):

            percentage = (
                count / len(reset_events) * 100
                if reset_events
                else 0
            )

            print(
                f"  {metric:30s}: "
                f"{count:,} "
                f"({percentage:6.2f}%)"
            )

    else:

        print("  None")

    print()

    print(
        "OperStatus changes near discard decrease : "
        f"{oper_status_event_count:,}"
    )

    print()

    # --------------------------------------------------------
    # HOST SUMMARY
    # --------------------------------------------------------

    host_counter = Counter(
        event["host_name"] or event["host"]
        for event in reset_events
    )

    print("Top affected hosts:")

    for host, count in host_counter.most_common(20):

        print(
            f"  {host:40s}: {count:,}"
        )

    print()

    # --------------------------------------------------------
    # INTERFACE SUMMARY
    # --------------------------------------------------------

    interface_counter = Counter(
        (
            event["hostid"],
            event["ifindex"],
        )
        for event in reset_events
    )

    print(
        "Unique affected interfaces : "
        f"{len(interface_counter):,}"
    )

    print()

    # --------------------------------------------------------
    # STRONG EVIDENCE SUMMARY
    # --------------------------------------------------------

    only_discard = classifications[
        "discard_counter_only"
    ]

    multiple_counter = classifications[
        "multiple_counter_decrease"
    ]

    interface_event = classifications[
        "possible_interface_event"
    ]

    uncertain = classifications[
        "uncertain"
    ]

    print("=" * 72)
    print("INTERPRETATION")
    print("=" * 72)

    print()

    print(
        f"Discard-only decreases          : "
        f"{only_discard:,}"
    )

    print(
        f"Multiple counter decreases      : "
        f"{multiple_counter:,}"
    )

    print(
        f"OperStatus/interface events     : "
        f"{interface_event:,}"
    )

    print(
        f"Uncertain                        : "
        f"{uncertain:,}"
    )

    print()

    if (
        only_discard == len(reset_events)
        and multiple_counter == 0
        and interface_event == 0
    ):

        overall_classification = (
            "discard_counter_behavior"
        )

        overall_confidence = "high"

        interpretation = (
            "All detected decreases occur only on "
            "discard counters. No correlated decrease "
            "was detected in other cumulative interface "
            "counters and no operStatus transition was "
            "detected within the correlation window. "
            "This strongly suggests device/counter "
            "behavior rather than a real interface event."
        )

    elif multiple_counter > 0:

        overall_classification = (
            "multiple_counter_reset_behavior"
        )

        overall_confidence = "high"

        interpretation = (
            "Multiple cumulative counters decreased on "
            "the same interface within the correlation "
            "window. This is consistent with a genuine "
            "counter reset or device/interface-level "
            "counter discontinuity."
        )

    elif interface_event > 0:

        overall_classification = (
            "possible_interface_event"
        )

        overall_confidence = "medium"

        interpretation = (
            "Discard counter decreases correlate with "
            "operStatus changes. Further investigation "
            "is required to determine whether the event "
            "represents an interface flap or another "
            "operational transition."
        )

    else:

        overall_classification = (
            "uncertain"
        )

        overall_confidence = "low"

        interpretation = (
            "The available cross-metric evidence is "
            "insufficient for a strong classification."
        )

    print(
        f"Overall classification : "
        f"{overall_classification}"
    )

    print(
        f"Overall confidence     : "
        f"{overall_confidence}"
    )

    print()

    print(
        "Interpretation:"
    )

    print(
        interpretation
    )

    print()

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    output = {
        "audit": {
            "name": "counter_reset_cross_metric_audit",
            "version": "1.0",
            "history_file": HISTORY_FILE,
            "semantic_file": SEMANTIC_FILE,
            "correlation_window_sec": CORRELATION_WINDOW_SEC,
        },

        "summary": {
            "semantic_metrics": len(semantic_metrics),
            "history_records": len(history),
            "relevant_records": len(records),
            "missing_semantic": missing_semantic,

            "discard_decrease_events": len(reset_events),

            "unique_affected_interfaces": len(
                interface_counter
            ),
        },

        "by_metric": dict(metric_counter),

        "classification": dict(
            classifications
        ),

        "confidence": dict(
            confidence
        ),

        "cross_metric_decreases": dict(
            cross_metric_summary
        ),

        "oper_status_correlated_events": (
            oper_status_event_count
        ),

        "top_hosts": [
            {
                "host": host,
                "events": count,
            }
            for host, count
            in host_counter.most_common(20)
        ],

        "overall": {
            "classification": overall_classification,
            "confidence": overall_confidence,
            "interpretation": interpretation,
        },

        "events": detailed_events,
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"Output written to {OUTPUT_FILE}"
    )

    print()

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    print("=" * 72)
    print("STATUS : PASS")
    print("=" * 72)


if __name__ == "__main__":
    main()