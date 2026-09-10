"""
Counter Reset Correlation Audit v2
==================================

Tujuan:
    Menghubungkan counter reset/decrease dengan event jaringan
    yang terjadi pada interface atau host yang sama.

Input:
    1. transformed_history.jsonl
    2. semantic_metrics.json

Output:
    counter_reset_correlation_audit.json

Identitas interface:
    JANGAN menggunakan Zabbix interfaceid.

    Untuk metric SNMP IF-MIB, gunakan:

        hostid + ifIndex

    Contoh:

        net.if.out.discards[ifOutDiscards.34]
                                    ^^^^^^
                                    ifIndex = 34

    sehingga:

        interface_identity = (hostid, 34)

Correlation hierarchy:

    1. uptime decrease
         -> likely_device_reboot

    2. same-interface oper_status transition
         -> likely_interface_flap

    3. ICMP anomaly on same host
         -> possible_network_disruption

    4. same-interface supporting activity
         -> possible_interface_counter_reset

    5. no strong evidence
         -> counter_reset_without_correlated_event

Important:
    "activity" bukan bukti bahwa interface flap terjadi.
    Activity hanya supporting evidence.

"""

from __future__ import annotations

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

TRANSFORMED_FILE = Path(
    "transformed_history.jsonl"
)

SEMANTIC_FILE = Path(
    "semantic_metrics.json"
)

OUTPUT_FILE = Path(
    "counter_reset_correlation_audit.json"
)

WINDOW_SEC = 300

# Toleransi untuk menentukan perubahan oper_status
# yang benar-benar dekat dengan counter reset.
STATUS_CORRELATION_WINDOW_SEC = 300

# ICMP dianggap anomaly jika:
#   loss > threshold
# atau
#   RTT > threshold
ICMP_LOSS_THRESHOLD = 1.0       # percent
ICMP_RTT_THRESHOLD_SEC = 0.200  # 200 ms

# Hanya metric berikut yang dianggap supporting
# activity pada interface yang sama.
INTERFACE_ACTIVITY_METRICS = {
    "in_bps",
    "out_bps",
    "in_pps",
    "out_pps",
    "in_error_rate",
    "out_error_rate",
    "in_discard_rate",
    "out_discard_rate",
}


# ============================================================
# REGEX
# ============================================================

# Standard Zabbix SNMP interface keys.
#
# Examples:
#
#   net.if.in[ifHCInOctets.34]
#   net.if.out[ifHCOutOctets.34]
#   net.if.in.errors[ifInErrors.34]
#   net.if.out.errors[ifOutErrors.34]
#   net.if.in.discards[ifInDiscards.34]
#   net.if.out.discards[ifOutDiscards.34]
#   net.if.status[ifOperStatus.34]
#
# Capture the final numeric IF-MIB index.

IFINDEX_PATTERNS = [
    re.compile(
        r"if(?:HC)?InOctets\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"if(?:HC)?OutOctets\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifInUcastPkts\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifOutUcastPkts\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifInErrors\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifOutErrors\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifInDiscards\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifOutDiscards\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifOperStatus\.(\d+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"ifAdminStatus\.(\d+)",
        re.IGNORECASE,
    ),
]


# ============================================================
# HELPERS
# ============================================================

def safe_float(value):
    """
    Convert value to float.

    Return None if conversion fails or value is not finite.
    """

    try:
        result = float(value)

        if not math.isfinite(result):
            return None

        return result

    except (TypeError, ValueError):
        return None


def safe_int(value):
    """
    Convert value to int.
    """

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


def timestamp_to_iso(clock):
    """
    Convert Unix epoch timestamp to ISO-8601 UTC.
    """

    try:
        return datetime.fromtimestamp(
            int(clock),
            tz=timezone.utc,
        ).isoformat()

    except (TypeError, ValueError, OSError):
        return None


def parse_ifindex(key):
    """
    Extract IF-MIB ifIndex from a Zabbix item key.

    Example:

        net.if.out.discards[ifOutDiscards.34]

    returns:

        34

    Returns None if the metric is not a recognizable
    interface metric.
    """

    if not key:
        return None

    key = str(key)

    for pattern in IFINDEX_PATTERNS:

        match = pattern.search(key)

        if match:
            return int(match.group(1))

    return None


def is_oper_status_metric(metric):
    """
    Determine whether a semantic metric represents
    interface operational status.
    """

    return (
        metric.get("canonical_metric") == "oper_status"
    )


def is_uptime_metric(metric):
    """
    Determine whether metric represents device uptime.
    """

    return (
        metric.get("canonical_metric") == "uptime"
    )


def is_icmp_loss_metric(metric):
    return (
        metric.get("canonical_metric")
        == "icmp_loss_pct"
    )


def is_icmp_rtt_metric(metric):
    return (
        metric.get("canonical_metric")
        == "icmp_rtt_sec"
    )


def is_interface_metric(metric):
    """
    Determine whether metric has an IF-MIB ifIndex.
    """

    key = metric.get("key", "")

    return parse_ifindex(key) is not None


def make_interface_identity(hostid, ifindex):
    """
    Canonical interface identity.

    IMPORTANT:
        hostid + ifIndex

    NOT:
        hostid + Zabbix interfaceid
    """

    if hostid is None or ifindex is None:
        return None

    return (
        str(hostid),
        int(ifindex),
    )


# ============================================================
# LOAD SEMANTIC METRICS
# ============================================================

def load_semantic_metrics():
    """
    Load semantic_metrics.json.

    Supports both formats:

    Format 1:
        [
            {...},
            {...}
        ]

    Format 2:
        {
            "metrics": [
                {...},
                {...}
            ]
        }

    Returns:
        itemid -> semantic metadata
    """

    print()
    print("=" * 70)
    print("Loading semantic metrics")
    print("=" * 70)

    with SEMANTIC_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:

        data = json.load(f)

    # --------------------------------------------------------
    # Detect JSON structure
    # --------------------------------------------------------

    if isinstance(data, list):

        # semantic_metrics.json is a direct array
        metrics = data

        source_format = "list"

    elif isinstance(data, dict):

        # semantic_metrics.json is wrapped in:
        #
        # {
        #     "metrics": [...]
        # }

        metrics = data.get(
            "metrics",
            []
        )

        source_format = "object.metrics"

    else:

        raise ValueError(
            "Unsupported semantic_metrics.json format. "
            "Expected a JSON list or an object containing "
            "'metrics'."
        )

    # --------------------------------------------------------
    # Validate metrics
    # --------------------------------------------------------

    if not isinstance(metrics, list):

        raise ValueError(
            "'metrics' must be a JSON list."
        )

    # --------------------------------------------------------
    # Build itemid -> metadata map
    # --------------------------------------------------------

    item_map = {}

    invalid_records = 0
    duplicate_itemids = 0

    for metric in metrics:

        if not isinstance(
            metric,
            dict,
        ):

            invalid_records += 1

            continue

        itemid = metric.get(
            "itemid"
        )

        if itemid is None:

            invalid_records += 1

            continue

        itemid = str(
            itemid
        )

        if itemid in item_map:

            duplicate_itemids += 1

        item_map[
            itemid
        ] = metric

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    print(
        f"Source format    : {source_format}"
    )

    print(
        f"Semantic metrics : {len(metrics)}"
    )

    print(
        f"Item map         : {len(item_map)}"
    )

    print(
        f"Invalid records  : {invalid_records}"
    )

    print(
        f"Duplicate itemid : {duplicate_itemids}"
    )

    return item_map


# ============================================================
# LOAD TRANSFORMED HISTORY
# ============================================================

def load_history(semantic_map):
    """
    Load transformed history.

    Add semantic metadata to every record.

    Returns:

        records

    and statistics.
    """

    print()
    print("=" * 70)
    print("Loading transformed history")
    print("=" * 70)

    records = []

    parse_errors = 0

    missing_semantic = 0

    with TRANSFORMED_FILE.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):

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
            )

            semantic = semantic_map.get(
                itemid
            )

            if semantic is None:

                missing_semantic += 1

                continue

            clock = safe_int(
                record.get("clock")
            )

            if clock is None:
                continue

            hostid = str(
                record.get(
                    "hostid",
                    "",
                )
            )

            canonical_metric = semantic.get(
                "canonical_metric"
            )

            key = semantic.get(
                "key",
                "",
            )

            ifindex = parse_ifindex(key)

            enriched = {
                **record,

                "semantic_key": key,

                "semantic_type": semantic.get(
                    "semantic_type"
                ),

                "transformation": semantic.get(
                    "transformation"
                ),

                "canonical_metric": canonical_metric,

                "ifindex": ifindex,

                "interface_identity": (
                    make_interface_identity(
                        hostid,
                        ifindex,
                    )
                ),
            }

            records.append(enriched)

    print(
        f"Records          : {len(records)}"
    )

    print(
        f"Parse errors     : {parse_errors}"
    )

    print(
        f"Missing semantic : {missing_semantic}"
    )

    return records


# ============================================================
# DEDUPLICATE TIMESTAMPS
# ============================================================

def deduplicate_records(records):
    """
    Deduplicate records at:

        itemid + clock

    This is important because the same metric can sometimes
    appear multiple times at the same timestamp.

    For correlation, we must NOT create fake transitions such as:

        1 -> 2 -> 1 -> 2

    when all samples actually have the same timestamp.

    Returns:

        deduplicated records
        duplicate statistics
        duplicate conflicts
    """

    print()
    print("=" * 70)
    print("Deduplicating timestamps")
    print("=" * 70)

    groups = defaultdict(list)

    for record in records:

        itemid = str(
            record.get("itemid", "")
        )

        clock = safe_int(
            record.get("clock")
        )

        if not itemid or clock is None:
            continue

        groups[
            (
                itemid,
                clock,
            )
        ].append(record)

    deduplicated = []

    duplicate_groups = 0
    duplicate_records = 0
    duplicate_conflicts = 0

    for _, group in groups.items():

        if len(group) == 1:

            deduplicated.append(
                group[0]
            )

            continue

        duplicate_groups += 1

        duplicate_records += (
            len(group) - 1
        )

        values = []

        for record in group:

            value = safe_float(
                record.get("value")
            )

            if value is not None:
                values.append(value)

        unique_values = set(values)

        if len(unique_values) > 1:

            duplicate_conflicts += 1

        # Prefer the first record.
        #
        # For correlation, all records represent
        # the same item at the same timestamp.
        chosen = group[0].copy()

        chosen[
            "duplicate_timestamp"
        ] = True

        chosen[
            "duplicate_count"
        ] = len(group)

        chosen[
            "duplicate_conflict"
        ] = (
            len(unique_values) > 1
        )

        deduplicated.append(
            chosen
        )

    print(
        f"Original records       : {len(records)}"
    )

    print(
        f"Deduplicated records   : {len(deduplicated)}"
    )

    print(
        f"Duplicate groups       : {duplicate_groups}"
    )

    print(
        f"Duplicate records      : {duplicate_records}"
    )

    print(
        f"Duplicate conflicts    : {duplicate_conflicts}"
    )

    return (
        deduplicated,
        {
            "duplicate_groups": duplicate_groups,
            "duplicate_records": duplicate_records,
            "duplicate_conflicts": duplicate_conflicts,
        },
    )


# ============================================================
# BUILD INDEXES
# ============================================================

def build_indexes(records):
    """
    Build indexes for correlation.

    Interface-level:

        (hostid, ifIndex)

    Host-level:

        hostid

    Metric-level:

        itemid
    """

    print()
    print("=" * 70)
    print("Building correlation indexes")
    print("=" * 70)

    interface_index = defaultdict(list)

    host_index = defaultdict(list)

    item_index = defaultdict(list)

    for record in records:

        hostid = str(
            record.get(
                "hostid",
                "",
            )
        )

        itemid = str(
            record.get(
                "itemid",
                "",
            )
        )

        ifindex = record.get(
            "ifindex"
        )

        if hostid:

            host_index[
                hostid
            ].append(record)

        if itemid:

            item_index[
                itemid
            ].append(record)

        interface_identity = (
            record.get(
                "interface_identity"
            )
        )

        if interface_identity:

            interface_index[
                interface_identity
            ].append(record)

    # Sort all indexes by clock.

    for collection in (
        interface_index,
        host_index,
        item_index,
    ):

        for key in collection:

            collection[key].sort(
                key=lambda x: int(
                    x.get(
                        "clock",
                        0,
                    )
                )
            )

    print(
        f"Hosts indexed          : {len(host_index)}"
    )

    print(
        f"Interfaces indexed     : {len(interface_index)}"
    )

    print(
        f"Items indexed          : {len(item_index)}"
    )

    return (
        interface_index,
        host_index,
        item_index,
    )


# ============================================================
# FIND COUNTER RESETS
# ============================================================

def find_counter_resets(records):
    """
    Find counter decreases.

    Conditions:

        transformation == delta_rate

        current raw value < previous raw value

    Ignore:
        duplicate timestamps
        out-of-order records
    """

    print()
    print("=" * 70)
    print("Finding counter resets")
    print("=" * 70)

    resets = []

    # Group by itemid.

    item_records = defaultdict(list)

    for record in records:

        if (
            record.get("transformation")
            != "delta_rate"
        ):
            continue

        itemid = str(
            record.get("itemid", "")
        )

        item_records[
            itemid
        ].append(record)

    for itemid, group in item_records.items():

        group.sort(
            key=lambda x: int(
                x.get(
                    "clock",
                    0,
                )
            )
        )

        previous = None

        for current in group:

            clock = safe_int(
                current.get("clock")
            )

            raw_value = safe_float(
                current.get("raw_value")
            )

            if clock is None:
                continue

            if raw_value is None:
                continue

            if previous is None:

                previous = current

                continue

            previous_clock = safe_int(
                previous.get("clock")
            )

            previous_raw = safe_float(
                previous.get(
                    "raw_value"
                )
            )

            if previous_clock is None:
                previous = current
                continue

            if previous_raw is None:
                previous = current
                continue

            # Same timestamp.
            if clock == previous_clock:

                previous = current
                continue

            # Out-of-order.
            if clock < previous_clock:

                previous = current
                continue

            # Counter decrease.
            if raw_value < previous_raw:

                hostid = str(
                    current.get(
                        "hostid",
                        "",
                    )
                )

                ifindex = current.get(
                    "ifindex"
                )

                reset = {
                    "timestamp": timestamp_to_iso(
                        clock
                    ),

                    "clock": clock,

                    "itemid": itemid,

                    "hostid": hostid,

                    "host": current.get(
                        "host"
                    ),

                    "host_name": current.get(
                        "host_name"
                    ),

                    "device_role": current.get(
                        "device_role"
                    ),

                    "canonical_metric": current.get(
                        "canonical_metric"
                    ),

                    "semantic_key": current.get(
                        "semantic_key"
                    ),

                    "ifindex": ifindex,

                    "interface_identity": (
                        current.get(
                            "interface_identity"
                        )
                    ),

                    "raw_value": raw_value,

                    "previous_raw_value": previous_raw,

                    "delta_value": (
                        raw_value
                        - previous_raw
                    ),

                    "reset_magnitude": (
                        previous_raw
                        - raw_value
                    ),
                }

                resets.append(
                    reset
                )

            previous = current

    resets.sort(
        key=lambda x: int(
            x["clock"]
        )
    )

    print(
        f"Reset events : {len(resets)}"
    )

    return resets


# ============================================================
# TIME WINDOW
# ============================================================

def records_in_window(
    records,
    center_clock,
    window_sec,
):
    """
    Return records within:

        center_clock +/- window_sec
    """

    result = []

    start = (
        center_clock
        - window_sec
    )

    end = (
        center_clock
        + window_sec
    )

    for record in records:

        clock = safe_int(
            record.get("clock")
        )

        if clock is None:
            continue

        if start <= clock <= end:

            result.append(
                record
            )

    return result


# ============================================================
# OPER STATUS CORRELATION
# ============================================================

def correlate_oper_status(
    reset,
    interface_index,
):
    """
    Detect real operational-status transitions
    on the SAME host + SAME ifIndex.

    Important:
        We do not use Zabbix interfaceid.

    We only consider unique timestamps.
    """

    interface_identity = (
        reset.get(
            "interface_identity"
        )
    )

    if not interface_identity:

        return {
            "detected": False,
            "reason": "No IF-MIB ifIndex available.",
            "transitions": [],
        }

    records = interface_index.get(
        tuple(interface_identity),
        [],
    )

    status_records = [
        r
        for r in records
        if r.get(
            "canonical_metric"
        ) == "oper_status"
    ]

    if not status_records:

        return {
            "detected": False,
            "reason": (
                "No oper_status metric for "
                "same host + ifIndex."
            ),
            "transitions": [],
        }

    status_records.sort(
        key=lambda x: int(
            x.get(
                "clock",
                0,
            )
        )
    )

    # Deduplicate by clock.
    unique_by_clock = {}

    for record in status_records:

        clock = safe_int(
            record.get("clock")
        )

        value = safe_float(
            record.get("value")
        )

        if clock is None:
            continue

        if value is None:
            continue

        unique_by_clock[
            clock
        ] = record

    unique_records = [
        unique_by_clock[clock]
        for clock in sorted(
            unique_by_clock
        )
    ]

    transitions = []

    previous = None

    reset_clock = safe_int(
        reset.get("clock")
    )

    for current in unique_records:

        current_clock = safe_int(
            current.get("clock")
        )

        current_value = safe_float(
            current.get("value")
        )

        if (
            current_clock is None
            or current_value is None
        ):
            continue

        if previous is None:

            previous = current

            continue

        previous_clock = safe_int(
            previous.get("clock")
        )

        previous_value = safe_float(
            previous.get("value")
        )

        if (
            previous_clock is None
            or previous_value is None
        ):
            previous = current
            continue

        if current_value != previous_value:

            distance = abs(
                current_clock
                - reset_clock
            )

            if (
                distance
                <= STATUS_CORRELATION_WINDOW_SEC
            ):

                transitions.append(
                    {
                        "previous": previous_value,

                        "current": current_value,

                        "previous_clock": previous_clock,

                        "current_clock": current_clock,

                        "previous_timestamp": (
                            timestamp_to_iso(
                                previous_clock
                            )
                        ),

                        "current_timestamp": (
                            timestamp_to_iso(
                                current_clock
                            )
                        ),

                        "distance_from_reset_sec": (
                            distance
                        ),
                    }
                )

        previous = current

    return {
        "detected": len(
            transitions
        ) > 0,

        "transitions": transitions,

        "same_interface": True,

        "identity": {
            "hostid": reset.get(
                "hostid"
            ),

            "ifindex": reset.get(
                "ifindex"
            ),
        },
    }


# ============================================================
# UPTIME CORRELATION
# ============================================================

def correlate_uptime(
    reset,
    host_index,
):
    """
    Detect uptime decrease on the same host.

    Uptime decrease is stronger evidence of
    device reboot than counter reset alone.
    """

    hostid = str(
        reset.get(
            "hostid",
            "",
        )
    )

    records = host_index.get(
        hostid,
        [],
    )

    uptime_records = [
        r
        for r in records
        if r.get(
            "canonical_metric"
        ) == "uptime"
    ]

    if not uptime_records:

        return {
            "detected": False,
            "decrease": [],
        }

    uptime_records.sort(
        key=lambda x: int(
            x.get(
                "clock",
                0,
            )
        )
    )

    reset_clock = safe_int(
        reset.get("clock")
    )

    decreases = []

    previous = None

    for current in uptime_records:

        current_clock = safe_int(
            current.get("clock")
        )

        current_value = safe_float(
            current.get("value")
        )

        if (
            current_clock is None
            or current_value is None
        ):
            continue

        if previous is None:

            previous = current

            continue

        previous_clock = safe_int(
            previous.get("clock")
        )

        previous_value = safe_float(
            previous.get("value")
        )

        if (
            previous_clock is None
            or previous_value is None
        ):
            previous = current
            continue

        # Only evaluate uptime transitions
        # close to reset.

        distance = min(
            abs(
                previous_clock
                - reset_clock
            ),
            abs(
                current_clock
                - reset_clock
            ),
        )

        if (
            current_value
            < previous_value
            and
            distance
            <= WINDOW_SEC
        ):

            decreases.append(
                {
                    "previous": previous_value,

                    "current": current_value,

                    "previous_clock": previous_clock,

                    "current_clock": current_clock,

                    "previous_timestamp": (
                        timestamp_to_iso(
                            previous_clock
                        )
                    ),

                    "current_timestamp": (
                        timestamp_to_iso(
                            current_clock
                        )
                    ),

                    "distance_from_reset_sec": (
                        distance
                    ),
                }
            )

        previous = current

    return {
        "detected": len(
            decreases
        ) > 0,

        "decrease": decreases,
    }


# ============================================================
# ICMP CORRELATION
# ============================================================

def correlate_icmp(
    reset,
    host_index,
):
    """
    Detect ICMP degradation on the same host.

    Conditions:

        loss > ICMP_LOSS_THRESHOLD

        OR

        RTT > ICMP_RTT_THRESHOLD_SEC
    """

    hostid = str(
        reset.get(
            "hostid",
            "",
        )
    )

    records = host_index.get(
        hostid,
        [],
    )

    reset_clock = safe_int(
        reset.get("clock")
    )

    icmp_records = records_in_window(
        records,
        reset_clock,
        WINDOW_SEC,
    )

    anomalies = []

    for record in icmp_records:

        metric = record.get(
            "canonical_metric"
        )

        value = safe_float(
            record.get("value")
        )

        clock = safe_int(
            record.get("clock")
        )

        if (
            value is None
            or clock is None
        ):
            continue

        distance = abs(
            clock
            - reset_clock
        )

        if metric == "icmp_loss_pct":

            if (
                value
                > ICMP_LOSS_THRESHOLD
            ):

                anomalies.append(
                    {
                        "canonical_metric": metric,

                        "value": value,

                        "clock": clock,

                        "timestamp": (
                            timestamp_to_iso(
                                clock
                            )
                        ),

                        "distance_from_reset_sec": (
                            distance
                        ),

                        "reason": (
                            f"ICMP loss "
                            f"{value}% > "
                            f"{ICMP_LOSS_THRESHOLD}%"
                        ),
                    }
                )

        elif metric == "icmp_rtt_sec":

            if (
                value
                > ICMP_RTT_THRESHOLD_SEC
            ):

                anomalies.append(
                    {
                        "canonical_metric": metric,

                        "value": value,

                        "clock": clock,

                        "timestamp": (
                            timestamp_to_iso(
                                clock
                            )
                        ),

                        "distance_from_reset_sec": (
                            distance
                        ),

                        "reason": (
                            f"ICMP RTT "
                            f"{value}s > "
                            f"{ICMP_RTT_THRESHOLD_SEC}s"
                        ),
                    }
                )

    return {
        "detected": len(
            anomalies
        ) > 0,

        "anomalies": anomalies,

        "thresholds": {
            "loss_pct": (
                ICMP_LOSS_THRESHOLD
            ),

            "rtt_sec": (
                ICMP_RTT_THRESHOLD_SEC
            ),
        },
    }


# ============================================================
# INTERFACE SUPPORTING ACTIVITY
# ============================================================

def correlate_interface_activity(
    reset,
    interface_index,
):
    """
    Find traffic/errors/discards activity on
    the same interface.

    IMPORTANT:
        This is supporting evidence only.

    Activity != interface flap.
    """

    interface_identity = (
        reset.get(
            "interface_identity"
        )
    )

    if not interface_identity:

        return {
            "detected": False,
            "records": [],
        }

    records = interface_index.get(
        tuple(interface_identity),
        [],
    )

    reset_clock = safe_int(
        reset.get("clock")
    )

    nearby = records_in_window(
        records,
        reset_clock,
        WINDOW_SEC,
    )

    activity = []

    for record in nearby:

        metric = record.get(
            "canonical_metric"
        )

        if metric not in (
            INTERFACE_ACTIVITY_METRICS
        ):
            continue

        value = safe_float(
            record.get("value")
        )

        clock = safe_int(
            record.get("clock")
        )

        if (
            value is None
            or clock is None
        ):
            continue

        activity.append(
            {
                "canonical_metric": metric,

                "clock": clock,

                "timestamp": (
                    timestamp_to_iso(
                        clock
                    )
                ),

                "value": value,

                "distance_from_reset_sec": (
                    abs(
                        clock
                        - reset_clock
                    )
                ),
            }
        )

    return {
        "detected": len(
            activity
        ) > 0,

        "count": len(
            activity
        ),

        "records": activity[:100],
    }


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_event(
    uptime,
    oper_status,
    icmp,
    activity,
):
    """
    Classify counter reset using evidence hierarchy.

    Priority:

        1. Device reboot
        2. Interface flap
        3. Network disruption
        4. Counter reset with supporting activity
        5. Unknown
    """

    if uptime.get(
        "detected"
    ):

        return {
            "classification": (
                "likely_device_reboot"
            ),

            "confidence": "high",

            "reason": (
                "Device uptime decreased "
                "within the correlation window."
            ),
        }

    if oper_status.get(
        "detected"
    ):

        return {
            "classification": (
                "likely_interface_flap"
            ),

            "confidence": "high",

            "reason": (
                "Operational status changed "
                "on the SAME host + ifIndex "
                "as the counter reset."
            ),
        }

    if icmp.get(
        "detected"
    ):

        return {
            "classification": (
                "possible_network_disruption"
            ),

            "confidence": "medium",

            "reason": (
                "ICMP loss or RTT anomaly "
                "was detected on the same host "
                "within the correlation window."
            ),
        }

    if activity.get(
        "detected"
    ):

        return {
            "classification": (
                "possible_interface_counter_reset"
            ),

            "confidence": "medium",
            
            "reason": (
                "Interface activity was present "
                "near the counter reset, but no "
                "direct reboot or oper_status "
                "transition was observed."
            ),
        }

    return {
        "classification": (
            "counter_reset_without_correlated_event"
        ),

        "confidence": "low",

        "reason": (
            "No uptime decrease, same-interface "
            "oper_status transition, or ICMP "
            "anomaly was detected."
        ),
    }


# ============================================================
# CORRELATE ONE RESET
# ============================================================

def correlate_reset(
    reset,
    interface_index,
    host_index,
):
    """
    Correlate one reset event.
    """

    uptime = correlate_uptime(
        reset,
        host_index,
    )

    oper_status = correlate_oper_status(
        reset,
        interface_index,
    )

    icmp = correlate_icmp(
        reset,
        host_index,
    )

    activity = correlate_interface_activity(
        reset,
        interface_index,
    )

    classification = classify_event(
        uptime,
        oper_status,
        icmp,
        activity,
    )

    return {
        "reset": reset,

        "correlation": {
            "window_sec": WINDOW_SEC,

            "uptime": uptime,

            "same_interface_oper_status": (
                oper_status
            ),

            "icmp": icmp,

            "same_interface_activity": (
                activity
            ),
        },

        "classification": classification,
    }


# ============================================================
# AGGREGATE RESULTS
# ============================================================

def aggregate_results(results):
    """
    Produce summary statistics.
    """

    classification_counts = Counter()

    confidence_counts = Counter()

    metric_counts = Counter()

    role_counts = Counter()

    host_counts = Counter()

    interface_counts = Counter()

    uptime_count = 0
    oper_status_count = 0
    icmp_count = 0
    activity_count = 0

    for result in results:

        reset = result["reset"]

        classification = result[
            "classification"
        ]

        correlation = result[
            "correlation"
        ]

        classification_counts[
            classification[
                "classification"
            ]
        ] += 1

        confidence_counts[
            classification[
                "confidence"
            ]
        ] += 1

        metric_counts[
            reset.get(
                "canonical_metric"
            )
        ] += 1

        role_counts[
            reset.get(
                "device_role"
            )
        ] += 1

        host_counts[
            reset.get(
                "host_name"
            )
        ] += 1

        interface_identity = (
            reset.get(
                "interface_identity"
            )
        )

        if interface_identity:

            interface_counts[
                str(
                    tuple(
                        interface_identity
                    )
                )
            ] += 1

        if correlation[
            "uptime"
        ].get("detected"):

            uptime_count += 1

        if correlation[
            "same_interface_oper_status"
        ].get("detected"):

            oper_status_count += 1

        if correlation[
            "icmp"
        ].get("detected"):

            icmp_count += 1

        if correlation[
            "same_interface_activity"
        ].get("detected"):

            activity_count += 1

    return {
        "by_classification": dict(
            classification_counts
        ),

        "by_confidence": dict(
            confidence_counts
        ),

        "by_canonical_metric": dict(
            metric_counts
        ),

        "by_device_role": dict(
            role_counts
        ),

        "by_host": dict(
            host_counts.most_common()
        ),

        "by_interface": dict(
            interface_counts.most_common()
        ),

        "correlated_signals": {
            "uptime_decrease": uptime_count,

            "same_interface_oper_status": (
                oper_status_count
            ),

            "icmp_anomaly": icmp_count,

            "same_interface_activity": (
                activity_count
            ),
        },
    }


# ============================================================
# RESET STATISTICS
# ============================================================

def reset_statistics(resets):
    """
    Calculate reset magnitude statistics.
    """

    magnitudes = []

    for reset in resets:

        value = safe_float(
            reset.get(
                "reset_magnitude"
            )
        )

        if value is not None:
            magnitudes.append(
                value
            )

    if not magnitudes:

        return {
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "p95": None,
            "p99": None,
        }

    magnitudes.sort()

    def percentile(p):

        if len(magnitudes) == 1:
            return magnitudes[0]

        position = (
            (len(magnitudes) - 1)
            * p
        )

        lower = math.floor(
            position
        )

        upper = math.ceil(
            position
        )

        if lower == upper:
            return magnitudes[
                lower
            ]

        weight = (
            position
            - lower
        )

        return (
            magnitudes[lower]
            * (1 - weight)
            +
            magnitudes[upper]
            * weight
        )

    return {
        "count": len(
            magnitudes
        ),

        "min": min(
            magnitudes
        ),

        "max": max(
            magnitudes
        ),

        "mean": statistics.mean(
            magnitudes
        ),

        "median": statistics.median(
            magnitudes
        ),

        "p95": percentile(
            0.95
        ),

        "p99": percentile(
            0.99
        ),
    }


# ============================================================
# REPORT
# ============================================================

def print_report(
    records,
    resets,
    results,
    aggregate,
    dedup_stats,
):
    """
    Print human-readable audit report.
    """

    print()
    print("=" * 70)
    print("COUNTER RESET CORRELATION AUDIT v2")
    print("=" * 70)

    print()

    print(
        f"History records              : "
        f"{len(records):,}"
    )

    print(
        f"Reset events                 : "
        f"{len(resets):,}"
    )

    print(
        f"Duplicate groups             : "
        f"{dedup_stats['duplicate_groups']:,}"
    )

    print(
        f"Duplicate conflicts          : "
        f"{dedup_stats['duplicate_conflicts']:,}"
    )

    print()

    print("By canonical metric:")

    for key, value in sorted(
        aggregate[
            "by_canonical_metric"
        ].items()
    ):

        print(
            f"  {key:32} : "
            f"{value}"
        )

    print()

    print("By device role:")

    for key, value in sorted(
        aggregate[
            "by_device_role"
        ].items()
    ):

        print(
            f"  {str(key):32} : "
            f"{value}"
        )

    print()

    print("Correlated signals:")

    signals = aggregate[
        "correlated_signals"
    ]

    print(
        f"  Uptime decrease             : "
        f"{signals['uptime_decrease']}"
    )

    print(
        f"  Same-interface oper_status  : "
        f"{signals['same_interface_oper_status']}"
    )

    print(
        f"  ICMP anomaly                : "
        f"{signals['icmp_anomaly']}"
    )

    print(
        f"  Same-interface activity     : "
        f"{signals['same_interface_activity']}"
    )

    print()

    print("Classification:")

    for key, value in sorted(
        aggregate[
            "by_classification"
        ].items()
    ):

        print(
            f"  {key:42} : "
            f"{value}"
        )

    print()

    print("Confidence:")

    for key, value in sorted(
        aggregate[
            "by_confidence"
        ].items()
    ):

        print(
            f"  {key:10} : "
            f"{value}"
        )

    print()

    stats = reset_statistics(
        resets
    )

    print("Reset magnitude:")

    print(
        f"  Count  : {stats['count']}"
    )

    print(
        f"  Min    : {stats['min']}"
    )

    print(
        f"  Max    : {stats['max']}"
    )

    print(
        f"  Mean   : {stats['mean']}"
    )

    print(
        f"  Median : {stats['median']}"
    )

    print(
        f"  P95    : {stats['p95']}"
    )

    print(
        f"  P99    : {stats['p99']}"
    )

    print()

    print("Top affected hosts:")

    for host, count in list(
        aggregate[
            "by_host"
        ].items()
    )[:20]:

        print(
            f"  {str(host):35} : "
            f"{count}"
        )

    print()

    print("Top affected interfaces:")

    for interface, count in list(
        aggregate[
            "by_interface"
        ].items()
    )[:20]:

        print(
            f"  {interface:35} : "
            f"{count}"
        )

    print()

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("COUNTER RESET CORRELATION AUDIT v2")
    print("=" * 70)

    # --------------------------------------------------------
    # Check files
    # --------------------------------------------------------

    if not TRANSFORMED_FILE.exists():

        raise FileNotFoundError(
            f"Input file not found: "
            f"{TRANSFORMED_FILE}"
        )

    if not SEMANTIC_FILE.exists():

        raise FileNotFoundError(
            f"Semantic file not found: "
            f"{SEMANTIC_FILE}"
        )

    # --------------------------------------------------------
    # Load semantic metadata
    # --------------------------------------------------------

    semantic_map = (
        load_semantic_metrics()
    )

    # --------------------------------------------------------
    # Load transformed history
    # --------------------------------------------------------

    records = load_history(
        semantic_map
    )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    (
        records,
        dedup_stats,
    ) = deduplicate_records(
        records
    )

    # --------------------------------------------------------
    # Build indexes
    # --------------------------------------------------------

    (
        interface_index,
        host_index,
        item_index,
    ) = build_indexes(
        records
    )

    # --------------------------------------------------------
    # Find resets
    # --------------------------------------------------------

    resets = find_counter_resets(
        records
    )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("Correlating reset events")
    print("=" * 70)

    results = []

    total = len(resets)

    for index, reset in enumerate(
        resets,
        start=1,
    ):

        result = correlate_reset(
            reset,
            interface_index,
            host_index,
        )

        results.append(
            result
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

    # --------------------------------------------------------
    # Aggregate
    # --------------------------------------------------------

    aggregate = (
        aggregate_results(
            results
        )
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    statistics_output = (
        reset_statistics(
            resets
        )
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    fatal_errors = []

    # Every result should map to one reset.
    if len(results) != len(resets):

        fatal_errors.append(
            "Result count does not match reset count."
        )

    # Check that every reset has identity metadata.
    missing_identity = 0

    for reset in resets:

        if not reset.get(
            "hostid"
        ):

            missing_identity += 1

    # Missing ifIndex is not fatal.
    # Some counter metrics may not expose an IF-MIB
    # identity.
    #
    # It is therefore reported separately.

    missing_ifindex = sum(
        1
        for reset in resets
        if reset.get(
            "ifindex"
        ) is None
    )

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------

    output = {
        "audit": {
            "name": (
                "counter_reset_correlation_audit"
            ),

            "version": "2.0",

            "generated_at": (
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

            "status": (
                "PASS"
                if not fatal_errors
                else "FAIL"
            ),
        },

        "configuration": {
            "window_sec": WINDOW_SEC,

            "status_correlation_window_sec": (
                STATUS_CORRELATION_WINDOW_SEC
            ),

            "icmp_loss_threshold_pct": (
                ICMP_LOSS_THRESHOLD
            ),

            "icmp_rtt_threshold_sec": (
                ICMP_RTT_THRESHOLD_SEC
            ),

            "interface_identity": (
                "hostid + ifIndex"
            ),

            "zabbix_interfaceid_used": False,
        },

        "input": {
            "transformed_file": str(
                TRANSFORMED_FILE
            ),

            "semantic_file": str(
                SEMANTIC_FILE
            ),

            "records": len(
                records
            ),

            "reset_events": len(
                resets
            ),
        },

        "deduplication": dedup_stats,

        "statistics": statistics_output,

        "aggregate": aggregate,

        "validation": {
            "fatal_errors": fatal_errors,

            "missing_hostid": missing_identity,

            "missing_ifindex": missing_ifindex,

            "duplicate_conflicts": (
                dedup_stats[
                    "duplicate_conflicts"
                ]
            ),
        },

        "results": results,
    }

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # --------------------------------------------------------
    # Print report
    # --------------------------------------------------------

    print_report(
        records,
        resets,
        results,
        aggregate,
        dedup_stats,
    )

    print()

    print(
        f"[+] Output written to: "
        f"{OUTPUT_FILE}"
    )

    print()

    if fatal_errors:

        print(
            "Status : FAIL"
        )

        for error in fatal_errors:

            print(
                f"  ERROR: {error}"
            )

    else:

        print(
            "Status : PASS"
        )

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
