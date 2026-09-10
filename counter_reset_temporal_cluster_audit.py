"""
counter_reset_temporal_cluster_audit.py

Purpose
-------
Analyze whether counter decrease/reset events happen independently
or cluster temporally across multiple interfaces on the same device.

This audit is specifically designed for the current AI-NOC pipeline.

Input
-----
1. semantic_metrics.json
2. transformed_history.jsonl

Output
------
counter_reset_temporal_cluster_audit.json

Important
---------
For SNMP interface identity we DO NOT use Zabbix interfaceid.

Interface identity:
    hostid + ifIndex

Example:
    hostid=10768, ifIndex=18

Zabbix interfaceid identifies the polling interface, not the
actual SNMP network interface represented by ifIndex.
"""

import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

SEMANTIC_FILE = Path("semantic_metrics.json")
HISTORY_FILE = Path("transformed_history.jsonl")
OUTPUT_FILE = Path("counter_reset_temporal_cluster_audit.json")

# Temporal windows in seconds.
WINDOWS = {
    "same_timestamp": 0,
    "within_5s": 5,
    "within_30s": 30,
    "within_60s": 60,
    "within_300s": 300,
}

# A reset must involve a decrease.
# Example:
# previous = 10
# current  = 5
#
# decrease = 5
#
# We only analyze semantic counters transformed using delta_rate.
VALID_SEMANTIC_TYPE = "counter"
VALID_TRANSFORMATION = "delta_rate"

# Only these canonical metrics are expected to represent
# standard interface counters in this audit.
TARGET_CANONICAL_METRICS = {
    "in_discard_rate",
    "out_discard_rate",
}

# Limit detailed event output.
MAX_EVENT_DETAILS = 500

# Limit printed clusters.
MAX_PRINT_CLUSTERS = 30


# ============================================================
# HELPERS
# ============================================================


def safe_float(value):
    """Convert value to float or return None."""
    try:
        if value is None:
            return None

        result = float(value)

        if not math.isfinite(result):
            return None

        return result

    except (TypeError, ValueError):
        return None


def safe_int(value):
    """Convert value to int or return None."""
    try:
        if value is None:
            return None

        return int(value)

    except (TypeError, ValueError):
        return None


def timestamp_to_iso(clock):
    """Convert epoch seconds to UTC ISO timestamp."""
    try:
        return datetime.fromtimestamp(
            int(clock),
            tz=timezone.utc,
        ).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def parse_ifindex(key):
    """
    Extract SNMP ifIndex from common Zabbix interface keys.

    Examples
    --------
    ifOutDiscards.34
    ifInDiscards.18
    ifOperStatus.12

    Also handles:
    net.if.out.discards[ifOutDiscards.34]
    net.if.in.discards[ifInDiscards.18]
    """

    if not key:
        return None

    key = str(key)

    # Standard SNMP OID-style reference.
    match = re.search(
        r"if(?:In|Out)(?:Discards|Errors|Octets|UcastPkts|NUcastPkts|OperStatus)"
        r"\.(\d+)",
        key,
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    # Generic ifIndex fallback.
    match = re.search(
        r"if(?:Index|Descr|Name|Alias|Type)\.(\d+)",
        key,
        re.IGNORECASE,
    )

    if match:
        return int(match.group(1))

    return None


def percentile(values, p):
    """Calculate percentile without numpy."""
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    rank = (len(values) - 1) * p
    lower = math.floor(rank)
    upper = math.ceil(rank)

    if lower == upper:
        return values[lower]

    weight = rank - lower

    return (
        values[lower]
        + weight * (values[upper] - values[lower])
    )


# ============================================================
# LOAD SEMANTIC METRICS
# ============================================================


def load_semantic_metrics():
    print()
    print("[1/6] Loading semantic metrics")

    if not SEMANTIC_FILE.exists():
        raise FileNotFoundError(
            f"Missing file: {SEMANTIC_FILE}"
        )

    with SEMANTIC_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:
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
            continue

        item_map[itemid] = metric

    print(f"Source format    : {source_format}")
    print(f"Semantic metrics : {len(metrics)}")
    print(f"Item map         : {len(item_map)}")
    print(f"Invalid records  : {invalid_records}")
    print(f"Duplicate itemid : {duplicate_itemid}")

    return item_map


# ============================================================
# LOAD HISTORY
# ============================================================


def load_history(item_map):
    print()
    print("[2/6] Loading transformed history")

    if not HISTORY_FILE.exists():
        raise FileNotFoundError(
            f"Missing file: {HISTORY_FILE}"
        )

    records = []

    parse_errors = 0
    missing_semantic = 0

    with HISTORY_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(f, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

            except json.JSONDecodeError:
                parse_errors += 1
                continue

            itemid = str(
                record.get("itemid", "")
            ).strip()

            if itemid not in item_map:
                missing_semantic += 1
                continue

            semantic = item_map[itemid]

            enriched = dict(record)

            enriched["_key"] = semantic.get(
                "key"
            )

            enriched["_canonical_metric"] = semantic.get(
                "canonical_metric"
            )

            enriched["_semantic_type"] = semantic.get(
                "semantic_type"
            )

            enriched["_transformation"] = semantic.get(
                "transformation"
            )

            enriched["_ifindex"] = parse_ifindex(
                semantic.get("key")
            )

            records.append(enriched)

    print(f"Records          : {len(records):,}")
    print(f"Parse errors     : {parse_errors}")
    print(f"Missing semantic : {missing_semantic}")

    return records


# ============================================================
# FIND RESET EVENTS
# ============================================================


def find_reset_events(records):
    print()
    print("[3/6] Finding counter reset events")

    # Group by itemid.
    item_records = defaultdict(list)

    for record in records:

        if (
            record.get("_semantic_type")
            != VALID_SEMANTIC_TYPE
        ):
            continue

        if (
            record.get("_transformation")
            != VALID_TRANSFORMATION
        ):
            continue

        if (
            record.get("_canonical_metric")
            not in TARGET_CANONICAL_METRICS
        ):
            continue

        clock = safe_int(
            record.get("clock")
        )

        raw_value = safe_float(
            record.get("raw_value")
        )

        if clock is None:
            continue

        if raw_value is None:
            continue

        itemid = str(
            record.get("itemid")
        )

        item_records[itemid].append(
            record
        )

    reset_events = []

    for itemid, history in item_records.items():

        history.sort(
            key=lambda x: safe_int(
                x.get("clock")
            ) or 0
        )

        previous = None

        for record in history:

            clock = safe_int(
                record.get("clock")
            )

            raw_value = safe_float(
                record.get("raw_value")
            )

            if clock is None or raw_value is None:
                continue

            if previous is None:
                previous = record
                continue

            previous_clock = safe_int(
                previous.get("clock")
            )

            previous_value = safe_float(
                previous.get("raw_value")
            )

            if (
                previous_clock is None
                or previous_value is None
            ):
                previous = record
                continue

            # Ignore duplicate timestamps.
            if clock <= previous_clock:
                previous = record
                continue

            # Counter decrease.
            if raw_value < previous_value:

                reset_events.append(
                    {
                        "itemid": itemid,
                        "hostid": str(
                            record.get("hostid", "")
                        ),
                        "host": record.get(
                            "host"
                        ),
                        "host_name": record.get(
                            "host_name"
                        ),
                        "device_role": record.get(
                            "device_role"
                        ),
                        "ifindex": record.get(
                            "_ifindex"
                        ),
                        "canonical_metric": record.get(
                            "_canonical_metric"
                        ),
                        "key": record.get(
                            "_key"
                        ),
                        "clock": clock,
                        "timestamp": timestamp_to_iso(
                            clock
                        ),
                        "previous_clock": previous_clock,
                        "previous_timestamp": timestamp_to_iso(
                            previous_clock
                        ),
                        "previous_raw_value": previous_value,
                        "raw_value": raw_value,
                        "decrease": (
                            previous_value
                            - raw_value
                        ),
                    }
                )

            previous = record

    reset_events.sort(
        key=lambda x: (
            x.get("hostid", ""),
            x.get("clock", 0),
        )
    )

    print(
        f"Reset events     : {len(reset_events)}"
    )

    return reset_events


# ============================================================
# TEMPORAL CLUSTERING
# ============================================================


def cluster_events(reset_events):
    """
    Determine whether reset events happen close together.

    Two events can be clustered when:

        abs(clock_a - clock_b) <= window

    We analyze:
        same timestamp
        <=5 sec
        <=30 sec
        <=60 sec
        <=300 sec
    """

    print()
    print("[4/6] Building temporal clusters")

    by_host = defaultdict(list)
    by_global_time = defaultdict(list)

    for event in reset_events:

        hostid = str(
            event.get("hostid", "")
        )

        clock = safe_int(
            event.get("clock")
        )

        if clock is None:
            continue

        by_host[hostid].append(
            event
        )

        by_global_time[clock].append(
            event
        )

    for events in by_host.values():
        events.sort(
            key=lambda x: safe_int(
                x.get("clock")
            ) or 0
        )

    for events in by_global_time.values():
        events.sort(
            key=lambda x: (
                x.get("hostid", ""),
                x.get("ifindex") or -1,
            )
        )

    # --------------------------------------------------------
    # Global temporal statistics
    # --------------------------------------------------------

    global_stats = {}

    sorted_events = sorted(
        reset_events,
        key=lambda x: safe_int(
            x.get("clock")
        ) or 0,
    )

    for window_name, window_sec in WINDOWS.items():

        matched_events = 0
        unique_events = set()

        for i, event in enumerate(
            sorted_events
        ):

            clock = safe_int(
                event.get("clock")
            )

            if clock is None:
                continue

            # Search forward.
            j = i + 1

            found = False

            while j < len(sorted_events):

                other_clock = safe_int(
                    sorted_events[j].get(
                        "clock"
                    )
                )

                if other_clock is None:
                    j += 1
                    continue

                diff = (
                    other_clock
                    - clock
                )

                if diff > window_sec:
                    break

                if (
                    sorted_events[j]
                    is not event
                ):
                    found = True

                    unique_events.add(
                        id(event)
                    )

                    unique_events.add(
                        id(sorted_events[j])
                    )

                j += 1

            if found:
                matched_events += 1

        global_stats[window_name] = {
            "window_sec": window_sec,
            "events_with_neighbor": len(
                unique_events
            ),
            "event_pairs_approx": matched_events,
            "percentage_of_all_events": (
                round(
                    (
                        len(unique_events)
                        / len(reset_events)
                        * 100
                    ),
                    2,
                )
                if reset_events
                else 0
            ),
        }

    # --------------------------------------------------------
    # Per-host temporal statistics
    # --------------------------------------------------------

    host_stats = {}

    for hostid, events in by_host.items():

        host_name = (
            events[0].get("host_name")
            or events[0].get("host")
        )

        stats = {
            "hostid": hostid,
            "host": events[0].get(
                "host"
            ),
            "host_name": host_name,
            "device_role": events[0].get(
                "device_role"
            ),
            "reset_events": len(events),
        }

        for window_name, window_sec in WINDOWS.items():

            event_indexes = set()

            for i, event in enumerate(events):

                clock = safe_int(
                    event.get("clock")
                )

                if clock is None:
                    continue

                j = i + 1

                while j < len(events):

                    other_clock = safe_int(
                        events[j].get(
                            "clock"
                        )
                    )

                    if other_clock is None:
                        j += 1
                        continue

                    diff = (
                        other_clock
                        - clock
                    )

                    if diff > window_sec:
                        break

                    event_indexes.add(i)
                    event_indexes.add(j)

                    j += 1

            stats[
                f"events_with_neighbor_{window_name}"
            ] = len(event_indexes)

            stats[
                f"percentage_{window_name}"
            ] = round(
                (
                    len(event_indexes)
                    / len(events)
                    * 100
                ),
                2,
            ) if events else 0

        host_stats[hostid] = stats

    return {
        "global": global_stats,
        "by_host": host_stats,
    }


# ============================================================
# SAME-TIMESTAMP CLUSTERS
# ============================================================


def build_same_timestamp_clusters(reset_events):
    """
    Build exact timestamp clusters.

    A cluster contains every reset event that occurs
    at exactly the same epoch second.
    """

    print()
    print("[5/6] Analyzing same-timestamp clusters")

    groups = defaultdict(list)

    for event in reset_events:

        clock = safe_int(
            event.get("clock")
        )

        if clock is None:
            continue

        groups[clock].append(
            event
        )

    clusters = []

    for clock, events in groups.items():

        if len(events) < 2:
            continue

        hosts = set()
        interfaces = set()
        metrics = Counter()

        for event in events:

            hostid = str(
                event.get("hostid", "")
            )

            hosts.add(hostid)

            ifindex = event.get(
                "ifindex"
            )

            interfaces.add(
                (
                    hostid,
                    ifindex,
                )
            )

            metrics[
                event.get(
                    "canonical_metric"
                )
            ] += 1

        clusters.append(
            {
                "clock": clock,
                "timestamp": timestamp_to_iso(
                    clock
                ),
                "event_count": len(events),
                "host_count": len(hosts),
                "interface_count": len(
                    interfaces
                ),
                "hosts": sorted(
                    hosts
                ),
                "metrics": dict(
                    metrics
                ),
                "events": events[
                    :MAX_EVENT_DETAILS
                ],
            }
        )

    clusters.sort(
        key=lambda x: (
            x["event_count"],
            x["host_count"],
        ),
        reverse=True,
    )

    return clusters


# ============================================================
# PER-HOST CLUSTER ANALYSIS
# ============================================================


def build_host_clusters(reset_events):
    """
    Detect clusters within each host.

    A cluster is a group of reset events occurring
    within 60 seconds.

    This helps distinguish:

        independent interface behavior

    from:

        device-wide behavior.
    """

    by_host = defaultdict(list)

    for event in reset_events:

        hostid = str(
            event.get("hostid", "")
        )

        by_host[hostid].append(
            event
        )

    clusters = []

    for hostid, events in by_host.items():

        events.sort(
            key=lambda x: safe_int(
                x.get("clock")
            ) or 0
        )

        current_cluster = []

        cluster_start = None
        cluster_end = None

        for event in events:

            clock = safe_int(
                event.get("clock")
            )

            if clock is None:
                continue

            if not current_cluster:

                current_cluster = [
                    event
                ]

                cluster_start = clock
                cluster_end = clock

                continue

            if (
                clock
                - cluster_start
                <= WINDOWS["within_60s"]
            ):

                current_cluster.append(
                    event
                )

                cluster_end = clock

            else:

                if len(current_cluster) >= 2:

                    clusters.append(
                        {
                            "hostid": hostid,
                            "host": current_cluster[
                                0
                            ].get("host"),
                            "host_name": current_cluster[
                                0
                            ].get("host_name"),
                            "device_role": current_cluster[
                                0
                            ].get("device_role"),
                            "start_clock": cluster_start,
                            "end_clock": cluster_end,
                            "start_timestamp": timestamp_to_iso(
                                cluster_start
                            ),
                            "end_timestamp": timestamp_to_iso(
                                cluster_end
                            ),
                            "duration_sec": (
                                cluster_end
                                - cluster_start
                            ),
                            "event_count": len(
                                current_cluster
                            ),
                            "unique_interfaces": len(
                                {
                                    (
                                        e.get("hostid"),
                                        e.get("ifindex"),
                                    )
                                    for e in current_cluster
                                }
                            ),
                            "metrics": dict(
                                Counter(
                                    e.get(
                                        "canonical_metric"
                                    )
                                    for e in current_cluster
                                )
                            ),
                            "events": current_cluster[
                                :MAX_EVENT_DETAILS
                            ],
                        }
                    )

                current_cluster = [
                    event
                ]

                cluster_start = clock
                cluster_end = clock

        # Final cluster.
        if len(current_cluster) >= 2:

            clusters.append(
                {
                    "hostid": hostid,
                    "host": current_cluster[
                        0
                    ].get("host"),
                    "host_name": current_cluster[
                        0
                    ].get("host_name"),
                    "device_role": current_cluster[
                        0
                    ].get("device_role"),
                    "start_clock": cluster_start,
                    "end_clock": cluster_end,
                    "start_timestamp": timestamp_to_iso(
                        cluster_start
                    ),
                    "end_timestamp": timestamp_to_iso(
                        cluster_end
                    ),
                    "duration_sec": (
                        cluster_end
                        - cluster_start
                    ),
                    "event_count": len(
                        current_cluster
                    ),
                    "unique_interfaces": len(
                        {
                            (
                                e.get("hostid"),
                                e.get("ifindex"),
                            )
                            for e in current_cluster
                        }
                    ),
                    "metrics": dict(
                        Counter(
                            e.get(
                                "canonical_metric"
                            )
                            for e in current_cluster
                        )
                    ),
                    "events": current_cluster[
                        :MAX_EVENT_DETAILS
                    ],
                }
            )

    clusters.sort(
        key=lambda x: (
            x["event_count"],
            x["unique_interfaces"],
        ),
        reverse=True,
    )

    return clusters


# ============================================================
# CLASSIFICATION
# ============================================================


def classify_temporal_behavior(
    reset_events,
    temporal_stats,
    same_timestamp_clusters,
    host_clusters,
):
    """
    Produce an interpretation of the reset behavior.

    Important:
    This classification does NOT claim vendor bugs.

    It only describes temporal behavior.
    """

    total = len(reset_events)

    if total == 0:
        return {
            "classification": "no_counter_decrease",
            "confidence": "high",
            "reason": "No counter decrease events detected.",
        }

    same_timestamp_events = sum(
        cluster["event_count"]
        for cluster in same_timestamp_clusters
    )

    within_60_events = temporal_stats[
        "global"
    ]["within_60s"][
        "events_with_neighbor"
    ]

    same_timestamp_pct = (
        same_timestamp_events
        / total
        * 100
    )

    within_60_pct = (
        within_60_events
        / total
        * 100
    )

    multi_interface_clusters = [
        cluster
        for cluster in host_clusters
        if cluster[
            "unique_interfaces"
        ] >= 2
    ]

    if (
        same_timestamp_pct >= 50
        and multi_interface_clusters
    ):

        return {
            "classification": "strong_device_wide_temporal_clustering",
            "confidence": "high",
            "reason": (
                "A large proportion of counter decreases "
                "occur at the same timestamp and affect "
                "multiple interfaces on the same device."
            ),
        }

    if (
        within_60_pct >= 50
        and multi_interface_clusters
    ):

        return {
            "classification": "device_level_temporal_clustering",
            "confidence": "high",
            "reason": (
                "A large proportion of counter decreases "
                "occur within 60 seconds and affect "
                "multiple interfaces on the same device."
            ),
        }

    if within_60_pct >= 50:

        return {
            "classification": "temporal_clustering_without_strong_multi_interface_evidence",
            "confidence": "medium",
            "reason": (
                "Counter decreases frequently occur "
                "close together in time, but strong "
                "multi-interface clustering is limited."
            ),
        }

    return {
        "classification": "mostly_independent_counter_decreases",
        "confidence": "medium",
        "reason": (
            "Counter decreases are generally separated "
            "in time and do not show strong temporal "
            "device-wide clustering."
        ),
    }


# ============================================================
# STATISTICS
# ============================================================


def build_statistics(reset_events):
    magnitudes = [
        safe_float(
            event.get("decrease")
        )
        for event in reset_events
    ]

    magnitudes = [
        x for x in magnitudes
        if x is not None
    ]

    by_metric = Counter(
        event.get(
            "canonical_metric"
        )
        for event in reset_events
    )

    by_host = Counter(
        event.get(
            "host_name"
        )
        or event.get("host")
        for event in reset_events
    )

    by_role = Counter(
        event.get(
            "device_role"
        )
        for event in reset_events
    )

    by_interface = Counter(
        (
            event.get("hostid"),
            event.get("ifindex"),
        )
        for event in reset_events
    )

    return {
        "total_reset_events": len(
            reset_events
        ),
        "by_canonical_metric": dict(
            by_metric
        ),
        "by_device_role": dict(
            by_role
        ),
        "top_hosts": [
            {
                "host": host,
                "count": count,
            }
            for host, count
            in by_host.most_common(20)
        ],
        "top_interfaces": [
            {
                "hostid": hostid,
                "ifindex": ifindex,
                "count": count,
            }
            for (
                hostid,
                ifindex,
            ), count
            in by_interface.most_common(20)
        ],
        "reset_magnitude": {
            "count": len(magnitudes),
            "min": min(magnitudes)
            if magnitudes
            else None,
            "max": max(magnitudes)
            if magnitudes
            else None,
            "mean": statistics.mean(
                magnitudes
            )
            if magnitudes
            else None,
            "median": statistics.median(
                magnitudes
            )
            if magnitudes
            else None,
            "p95": percentile(
                magnitudes,
                0.95,
            ),
            "p99": percentile(
                magnitudes,
                0.99,
            ),
        },
    }


# ============================================================
# PRINT REPORT
# ============================================================


def print_report(
    reset_events,
    temporal_stats,
    same_timestamp_clusters,
    host_clusters,
    classification,
    statistics,
):

    print()
    print("=" * 80)
    print("COUNTER RESET TEMPORAL CLUSTER AUDIT")
    print("=" * 80)

    print()
    print(
        f"Reset events                 : "
        f"{len(reset_events):,}"
    )

    print()
    print("By canonical metric:")

    for metric, count in sorted(
        statistics[
            "by_canonical_metric"
        ].items()
    ):

        print(
            f"  {metric:<30} : {count}"
        )

    print()
    print("By device role:")

    for role, count in sorted(
        statistics[
            "by_device_role"
        ].items()
    ):

        print(
            f"  {role:<30} : {count}"
        )

    print()
    print("Temporal clustering:")

    for name, stats in temporal_stats[
        "global"
    ].items():

        print(
            f"  {name:<30} : "
            f"{stats['events_with_neighbor']} "
            f"events "
            f"({stats['percentage_of_all_events']:.2f}%)"
        )

    print()
    print("Exact same-timestamp clusters:")

    print(
        f"  Cluster count               : "
        f"{len(same_timestamp_clusters)}"
    )

    multi_interface_exact = sum(
        1
        for cluster
        in same_timestamp_clusters
        if cluster[
            "interface_count"
        ] >= 2
    )

    print(
        f"  Multi-interface clusters    : "
        f"{multi_interface_exact}"
    )

    print()
    print(
        "Host-level clusters "
        "(multiple resets within 60 sec):"
    )

    print(
        f"  Cluster count               : "
        f"{len(host_clusters)}"
    )

    multi_interface_clusters = sum(
        1
        for cluster
        in host_clusters
        if cluster[
            "unique_interfaces"
        ] >= 2
    )

    print(
        f"  Multi-interface clusters    : "
        f"{multi_interface_clusters}"
    )

    print()
    print("Top same-timestamp clusters:")

    for cluster in same_timestamp_clusters[
        :MAX_PRINT_CLUSTERS
    ]:

        print(
            f"  {cluster['timestamp']} | "
            f"events={cluster['event_count']} | "
            f"hosts={cluster['host_count']} | "
            f"interfaces={cluster['interface_count']}"
        )

    print()
    print("Top host temporal clusters:")

    for cluster in host_clusters[
        :MAX_PRINT_CLUSTERS
    ]:

        print(
            f"  {cluster['host_name']:<35} | "
            f"events={cluster['event_count']:<3} | "
            f"interfaces={cluster['unique_interfaces']:<3} | "
            f"duration={cluster['duration_sec']}s | "
            f"{cluster['start_timestamp']}"
        )

    print()
    print("Top affected hosts:")

    for host in statistics[
        "top_hosts"
    ]:

        print(
            f"  {host['host']:<35} : "
            f"{host['count']}"
        )

    print()
    print("Top affected interfaces:")

    for interface in statistics[
        "top_interfaces"
    ]:

        print(
            f"  "
            f"{interface['hostid']}:"
            f"{interface['ifindex']}"
            f"{'':<20} : "
            f"{interface['count']}"
        )

    print()
    print("Reset magnitude:")

    magnitude = statistics[
        "reset_magnitude"
    ]

    print(
        f"  Count  : {magnitude['count']}"
    )
    print(
        f"  Min    : {magnitude['min']}"
    )
    print(
        f"  Max    : {magnitude['max']}"
    )
    print(
        f"  Mean   : {magnitude['mean']}"
    )
    print(
        f"  Median : {magnitude['median']}"
    )
    print(
        f"  P95    : {magnitude['p95']}"
    )
    print(
        f"  P99    : {magnitude['p99']}"
    )

    print()
    print("Classification:")

    print(
        f"  {classification['classification']}"
    )

    print(
        f"  Confidence : "
        f"{classification['confidence']}"
    )

    print(
        f"  Reason     : "
        f"{classification['reason']}"
    )

    print()
    print("=" * 80)


# ============================================================
# MAIN
# ============================================================


def main():

    print()
    print("=" * 80)
    print("COUNTER RESET TEMPORAL CLUSTER AUDIT")
    print("=" * 80)

    # --------------------------------------------------------
    # 1. Semantic metrics
    # --------------------------------------------------------

    item_map = load_semantic_metrics()

    # --------------------------------------------------------
    # 2. History
    # --------------------------------------------------------

    records = load_history(
        item_map
    )

    # --------------------------------------------------------
    # 3. Find reset events
    # --------------------------------------------------------

    reset_events = find_reset_events(
        records
    )

    # --------------------------------------------------------
    # 4. Temporal clustering
    # --------------------------------------------------------

    temporal_stats = cluster_events(
        reset_events
    )

    # --------------------------------------------------------
    # 5. Exact timestamp clusters
    # --------------------------------------------------------

    same_timestamp_clusters = (
        build_same_timestamp_clusters(
            reset_events
        )
    )

    # --------------------------------------------------------
    # 6. Host-level clusters
    # --------------------------------------------------------

    host_clusters = build_host_clusters(
        reset_events
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    statistics = build_statistics(
        reset_events
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    classification = (
        classify_temporal_behavior(
            reset_events,
            temporal_stats,
            same_timestamp_clusters,
            host_clusters,
        )
    )

    # --------------------------------------------------------
    # Print report
    # --------------------------------------------------------

    print_report(
        reset_events,
        temporal_stats,
        same_timestamp_clusters,
        host_clusters,
        classification,
        statistics,
    )

    # --------------------------------------------------------
    # Output JSON
    # --------------------------------------------------------

    report = {
        "audit": {
            "name": (
                "counter_reset_temporal_cluster_audit"
            ),
            "version": "1.0",
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },

        "configuration": {
            "semantic_file": str(
                SEMANTIC_FILE
            ),
            "history_file": str(
                HISTORY_FILE
            ),
            "target_canonical_metrics": sorted(
                TARGET_CANONICAL_METRICS
            ),
            "windows_seconds": WINDOWS,
            "interface_identity": (
                "hostid + ifIndex"
            ),
        },

        "statistics": statistics,

        "temporal_clustering": temporal_stats,

        "classification": classification,

        "same_timestamp_clusters": (
            same_timestamp_clusters[
                :MAX_EVENT_DETAILS
            ]
        ),

        "host_temporal_clusters": (
            host_clusters[
                :MAX_EVENT_DETAILS
            ]
        ),

        "reset_events": reset_events[
            :MAX_EVENT_DETAILS
        ],

        "notes": [
            (
                "A counter decrease is treated as a "
                "counter behavior event, not automatically "
                "as a network incident."
            ),
            (
                "Zabbix interfaceid is intentionally not "
                "used as network interface identity."
            ),
            (
                "SNMP interface identity is derived from "
                "hostid + ifIndex."
            ),
            (
                "Temporal clustering indicates correlation "
                "in time but does not prove causation."
            ),
            (
                "This audit does not determine whether a "
                "device/vendor has a broken SNMP implementation."
            ),
        ],
    }

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

    print()
    print(
        f"[+] Output written to: "
        f"{OUTPUT_FILE}"
    )

    print()
    print("Status : PASS")


if __name__ == "__main__":
    main()
