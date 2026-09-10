#!/usr/bin/env python3

import json
import re
from collections import Counter
from pathlib import Path

# ============================================================
# CONFIG
# ============================================================

INPUT_FILE = Path("selected_metrics.json")
OUTPUT_FILE = Path("semantic_metrics.json")

# ============================================================
# REGEX
# ============================================================

# Interface traffic
RE_IN_BPS = re.compile(r"^net\.if\.in\[", re.I)
RE_OUT_BPS = re.compile(r"^net\.if\.out\[", re.I)

# PPS
RE_IN_PPS = re.compile(
    r"^net\.if\.in\.pass\.v[46]\.pps\[",
    re.I,
)

RE_OUT_PPS = re.compile(
    r"^net\.if\.out\.pass\.v[46]\.pps\[",
    re.I,
)

# Interface state
RE_OPER_STATUS = re.compile(
    r"^net\.if\.status\[",
    re.I,
)

# Interface errors/discards
RE_IN_ERRORS = re.compile(
    r"^net\.if\.in\.errors\[",
    re.I,
)

RE_OUT_ERRORS = re.compile(
    r"^net\.if\.out\.errors\[",
    re.I,
)

RE_IN_DISCARDS = re.compile(
    r"^net\.if\.in\.discards\[",
    re.I,
)

RE_OUT_DISCARDS = re.compile(
    r"^net\.if\.out\.discards\[",
    re.I,
)

# Linux/Zabbix-agent interface counters
RE_LINUX_IN_DROPPED = re.compile(
    r'^net\.if\.in\["[^"]+",dropped\]$',
    re.I,
)

RE_LINUX_OUT_DROPPED = re.compile(
    r'^net\.if\.out\["[^"]+",dropped\]$',
    re.I,
)

RE_LINUX_IN_ERRORS = re.compile(
    r'^net\.if\.in\["[^"]+",errors\]$',
    re.I,
)

RE_LINUX_OUT_ERRORS = re.compile(
    r'^net\.if\.out\["[^"]+",errors\]$',
    re.I,
)

# SNMP standard interface counters
RE_IFHC_IN = re.compile(
    r"ifHCInOctets",
    re.I,
)

RE_IFHC_OUT = re.compile(
    r"ifHCOutOctets",
    re.I,
)

RE_IF_IN_ERRORS = re.compile(
    r"ifInErrors",
    re.I,
)

RE_IF_OUT_ERRORS = re.compile(
    r"ifOutErrors",
    re.I,
)

RE_IF_IN_DISCARDS = re.compile(
    r"ifInDiscards",
    re.I,
)

RE_IF_OUT_DISCARDS = re.compile(
    r"ifOutDiscards",
    re.I,
)

# Device health
RE_CPU = re.compile(
    r"^system\.cpu\.util",
    re.I,
)

RE_MEMORY = re.compile(
    r"^(vm\.memory\.util|vm\.memory\.size\[)",
    re.I,
)

RE_TEMPERATURE = re.compile(
    r"^sensor\.temp\.value\[",
    re.I,
)

RE_FAN = re.compile(
    r"^sensor\.fan\.status",
    re.I,
)

RE_PSU = re.compile(
    r"^sensor\.psu\.status",
    re.I,
)

RE_UPTIME = re.compile(
    r"^system\.net\.uptime",
    re.I,
)

RE_ICMP_LOSS = re.compile(
    r"^icmppingloss$",
    re.I,
)

RE_ICMP_RTT = re.compile(
    r"^icmppingsec$",
    re.I,
)

# Generic rate
RE_GENERIC_RATE = re.compile(
    r"rate|throughput|bandwidth",
    re.I,
)

# Percentage
RE_PERCENT = re.compile(
    r"%",
)

# ============================================================
# HELPERS
# ============================================================


def normalize_units(units):
    """
    Normalize units for semantic processing.

    IMPORTANT:
    Original Zabbix units are preserved in `units`.
    Normalized representation is stored in `normalized_units`.
    """
    if units is None:
        return ""

    value = str(units).strip()

    # Zabbix may expose !°C for some temperature items.
    if value.lower() == "!°c":
        return "°C"

    return value


def is_enabled(metric):
    """
    Zabbix status:
      0 = enabled
      1 = disabled
    """
    return str(metric.get("status", "1")) == "0"


def has_error(metric):
    """
    Detect Zabbix item error.
    """
    error = metric.get("error")

    if error is None:
        return False

    return str(error).strip() != ""


def get_state(metric):
    try:
        return int(metric.get("state", 0))
    except (TypeError, ValueError):
        return 0


def get_key(metric):
    return str(metric.get("key", "")).strip()


def get_units(metric):
    return str(metric.get("units", "")).strip()


def get_value_type(metric):
    try:
        return int(metric.get("value_type", 0))
    except (TypeError, ValueError):
        return 0


def is_bps(units):
    return str(units).strip().lower() == "bps"


def is_pps(units):
    return str(units).strip().lower() == "pps"


def is_percent(units):
    return str(units).strip() == "%"


# ============================================================
# CLASSIFIER
# ============================================================


def classify_metric(metric):
    """
    Deterministic semantic classifier.

    Priority:
      1. disabled / unsupported
      2. temperature
      3. PPS
      4. interface state
      5. known interface counters
      6. interface traffic
      7. device health
      8. ICMP
      9. generic rate
      10. generic percentage
      11. unknown
    """

    key = get_key(metric)
    units = get_units(metric)
    normalized_units = normalize_units(units)

    state = get_state(metric)
    error = has_error(metric)

    result = {
        "semantic_type": "unknown",
        "transformation": "direct",
        "canonical_metric": None,
        "normalized_units": normalized_units,
        "confidence": "low",
        "excluded": False,
        "exclude_reason": None,
        "classification_reason": "",
    }

    # --------------------------------------------------------
    # DISABLED
    # --------------------------------------------------------

    if not is_enabled(metric):
        result.update(
            {
                "semantic_type": "unknown",
                "transformation": "direct",
                "canonical_metric": None,
                "confidence": "low",
                "excluded": True,
                "exclude_reason": "disabled",
                "classification_reason":
                    "Zabbix item is disabled",
            }
        )

        return result

    # --------------------------------------------------------
    # UNSUPPORTED / ERROR
    # --------------------------------------------------------

    # Do not automatically exclude every metric with state/error
    # because some metrics can contain recoverable metadata.
    #
    # Temperature is explicitly handled below.

    # --------------------------------------------------------
    # TEMPERATURE
    # --------------------------------------------------------

    if RE_TEMPERATURE.match(key):
        if state != 0 or error:
            result.update(
                {
                    "semantic_type": "unknown",
                    "transformation": "direct",
                    "canonical_metric": None,
                    "confidence": "high",
                    "excluded": True,
                    "exclude_reason": "unsupported_temperature_sensor",
                    "classification_reason":
                        "Temperature sensor is unsupported or "
                        "has a Zabbix item error",
                }
            )

            return result

        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "temperature_c",
                "normalized_units": "°C",
                "confidence": "high",
                "excluded": False,
                "classification_reason":
                    "SNMP temperature sensor is a gauge; "
                    "unit normalized to °C",
            }
        )

        return result

    # --------------------------------------------------------
    # PPS
    # --------------------------------------------------------

    if RE_IN_PPS.match(key):
        result.update(
            {
                "semantic_type": "rate",
                "transformation": "direct",
                "canonical_metric": "in_pps",
                "normalized_units": "pps",
                "confidence": "high",
                "classification_reason":
                    "IPv4/IPv6 inbound passed-packet rate",
            }
        )

        return result

    if RE_OUT_PPS.match(key):
        result.update(
            {
                "semantic_type": "rate",
                "transformation": "direct",
                "canonical_metric": "out_pps",
                "normalized_units": "pps",
                "confidence": "high",
                "classification_reason":
                    "IPv4/IPv6 outbound passed-packet rate",
            }
        )

        return result

    # --------------------------------------------------------
    # OPER STATUS
    # --------------------------------------------------------

    if RE_OPER_STATUS.match(key):
        result.update(
            {
                "semantic_type": "state",
                "transformation": "direct",
                "canonical_metric": "oper_status",
                "normalized_units": "",
                "confidence": "high",
                "classification_reason":
                    "Interface operational state",
            }
        )

        return result

    # --------------------------------------------------------
    # STANDARD SNMP ERROR/DISCARD COUNTERS
    # --------------------------------------------------------

    if RE_IF_IN_ERRORS.search(key) or RE_IN_ERRORS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "in_error_rate",
                "confidence": "high",
                "classification_reason":
                    "Inbound interface error counter",
            }
        )

        return result

    if RE_IF_OUT_ERRORS.search(key) or RE_OUT_ERRORS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "out_error_rate",
                "confidence": "high",
                "classification_reason":
                    "Outbound interface error counter",
            }
        )

        return result

    if RE_IF_IN_DISCARDS.search(key) or RE_IN_DISCARDS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "in_discard_rate",
                "confidence": "high",
                "classification_reason":
                    "Inbound interface discard counter",
            }
        )

        return result

    if RE_IF_OUT_DISCARDS.search(key) or RE_OUT_DISCARDS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "out_discard_rate",
                "confidence": "high",
                "classification_reason":
                    "Outbound interface discard counter",
            }
        )

        return result

    # --------------------------------------------------------
    # LINUX ZABBIX AGENT INTERFACE METRICS
    # --------------------------------------------------------
    #
    # These were the 8 previously unknown metrics.
    #
    # We classify them as counters because the key semantics
    # represent interface errors/dropped packets.
    #
    # Confidence is MEDIUM because they are not standard
    # SNMP ifInErrors/ifOutErrors/ifInDiscards/ifOutDiscards
    # items and should ideally be verified against the Linux
    # source (/proc/net/dev or Zabbix agent implementation).
    #

    if RE_LINUX_IN_DROPPED.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "in_discard_rate",
                "confidence": "medium",
                "classification_reason":
                    "Linux interface inbound dropped-packet "
                    "counter; source semantics should be verified",
            }
        )

        return result

    if RE_LINUX_OUT_DROPPED.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "out_discard_rate",
                "confidence": "medium",
                "classification_reason":
                    "Linux interface outbound dropped-packet "
                    "counter; source semantics should be verified",
            }
        )

        return result

    if RE_LINUX_IN_ERRORS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "in_error_rate",
                "confidence": "medium",
                "classification_reason":
                    "Linux interface inbound error counter; "
                    "source semantics should be verified",
            }
        )

        return result

    if RE_LINUX_OUT_ERRORS.match(key):
        result.update(
            {
                "semantic_type": "counter",
                "transformation": "delta_rate",
                "canonical_metric": "out_error_rate",
                "confidence": "medium",
                "classification_reason":
                    "Linux interface outbound error counter; "
                    "source semantics should be verified",
            }
        )

        return result

    # --------------------------------------------------------
    # IFHC OCTETS
    # --------------------------------------------------------

    if RE_IFHC_IN.search(key):
        if is_bps(units):
            result.update(
                {
                    "semantic_type": "rate",
                    "transformation": "direct",
                    "canonical_metric": "in_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Inbound interface traffic already "
                        "represented as bps",
                }
            )
        else:
            result.update(
                {
                    "semantic_type": "counter",
                    "transformation": "delta_rate",
                    "canonical_metric": "in_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Inbound high-capacity interface octet "
                        "counter",
                }
            )

        return result

    if RE_IFHC_OUT.search(key):
        if is_bps(units):
            result.update(
                {
                    "semantic_type": "rate",
                    "transformation": "direct",
                    "canonical_metric": "out_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Outbound interface traffic already "
                        "represented as bps",
                }
            )
        else:
            result.update(
                {
                    "semantic_type": "counter",
                    "transformation": "delta_rate",
                    "canonical_metric": "out_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Outbound high-capacity interface octet "
                        "counter",
                }
            )

        return result

    # --------------------------------------------------------
    # INTERFACE TRAFFIC
    # --------------------------------------------------------

    if RE_IN_BPS.match(key):
        if is_bps(units):
            result.update(
                {
                    "semantic_type": "rate",
                    "transformation": "direct",
                    "canonical_metric": "in_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Inbound interface traffic with bps unit",
                }
            )
        else:
            result.update(
                {
                    "semantic_type": "counter",
                    "transformation": "delta_rate",
                    "canonical_metric": "in_bps",
                    "confidence": "medium",
                    "classification_reason":
                        "Inbound interface traffic item without "
                        "explicit bps unit",
                }
            )

        return result

    if RE_OUT_BPS.match(key):
        if is_bps(units):
            result.update(
                {
                    "semantic_type": "rate",
                    "transformation": "direct",
                    "canonical_metric": "out_bps",
                    "confidence": "high",
                    "classification_reason":
                        "Outbound interface traffic with bps unit",
                }
            )
        else:
            result.update(
                {
                    "semantic_type": "counter",
                    "transformation": "delta_rate",
                    "canonical_metric": "out_bps",
                    "confidence": "medium",
                    "classification_reason":
                        "Outbound interface traffic item without "
                        "explicit bps unit",
                }
            )

        return result

    # --------------------------------------------------------
    # CPU
    # --------------------------------------------------------

    if RE_CPU.match(key):
        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "cpu_pct",
                "normalized_units": "%",
                "confidence": "high",
                "classification_reason":
                    "CPU utilization gauge",
            }
        )

        return result

    # --------------------------------------------------------
    # MEMORY
    # --------------------------------------------------------

    if RE_MEMORY.match(key):
        if is_percent(units):
            result.update(
                {
                    "semantic_type": "gauge",
                    "transformation": "direct",
                    "canonical_metric": "memory_pct",
                    "normalized_units": "%",
                    "confidence": "high",
                    "classification_reason":
                        "Memory utilization percentage",
                }
            )

            return result

    # --------------------------------------------------------
    # FAN
    # --------------------------------------------------------

    if RE_FAN.match(key):
        result.update(
            {
                "semantic_type": "state",
                "transformation": "direct",
                "canonical_metric": "fan_status",
                "confidence": "high",
                "classification_reason":
                    "Fan operational status",
            }
        )

        return result

    # --------------------------------------------------------
    # PSU
    # --------------------------------------------------------

    if RE_PSU.match(key):
        result.update(
            {
                "semantic_type": "state",
                "transformation": "direct",
                "canonical_metric": "psu_status",
                "confidence": "high",
                "classification_reason":
                    "Power supply operational status",
            }
        )

        return result

    # --------------------------------------------------------
    # UPTIME
    # --------------------------------------------------------

    if RE_UPTIME.match(key):
        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "uptime",
                "confidence": "high",
                "classification_reason":
                    "System uptime",
            }
        )

        return result

    # --------------------------------------------------------
    # ICMP LOSS
    # --------------------------------------------------------

    if RE_ICMP_LOSS.match(key):
        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "icmp_loss_pct",
                "normalized_units": "%",
                "confidence": "high",
                "classification_reason":
                    "ICMP packet loss percentage",
            }
        )

        return result

    # --------------------------------------------------------
    # ICMP RTT
    # --------------------------------------------------------

    if RE_ICMP_RTT.match(key):
        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "icmp_rtt_sec",
                "normalized_units": "s",
                "confidence": "high",
                "classification_reason":
                    "ICMP round-trip response time",
            }
        )

        return result

    # --------------------------------------------------------
    # GENERIC RATE
    # --------------------------------------------------------

    if RE_GENERIC_RATE.search(key):
        if units:
            result.update(
                {
                    "semantic_type": "rate",
                    "transformation": "direct",
                    "canonical_metric": "rate",
                    "confidence": "medium",
                    "classification_reason":
                        "Generic metric with rate-like key",
                }
            )

            return result

    # --------------------------------------------------------
    # GENERIC PERCENTAGE
    # --------------------------------------------------------

    if is_percent(units):
        result.update(
            {
                "semantic_type": "gauge",
                "transformation": "direct",
                "canonical_metric": "percentage",
                "normalized_units": "%",
                "confidence": "medium",
                "classification_reason":
                    "Generic percentage gauge",
            }
        )

        return result

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    result.update(
        {
            "semantic_type": "unknown",
            "transformation": "direct",
            "canonical_metric": None,
            "confidence": "low",
            "classification_reason":
                "No deterministic semantic rule matched",
        }
    )

    return result


# ============================================================
# MAIN
# ============================================================


def main():

    print(f"[+] Loading {INPUT_FILE}")

    with INPUT_FILE.open("r", encoding="utf-8") as f:
        selected = json.load(f)

    # --------------------------------------------------------
    # Support both:
    #
    # 1. list
    # 2. {"metrics": [...]}
    # --------------------------------------------------------

    if isinstance(selected, list):
        metrics = selected

    elif isinstance(selected, dict):
        if isinstance(selected.get("metrics"), list):
            metrics = selected["metrics"]

        elif isinstance(selected.get("items"), list):
            metrics = selected["items"]

        else:
            raise RuntimeError(
                "selected_metrics.json does not contain "
                "`metrics` or `items` list"
            )

    else:
        raise RuntimeError(
            "Unsupported selected_metrics.json structure"
        )

    # --------------------------------------------------------
    # Deduplicate by itemid
    # --------------------------------------------------------

    unique = {}

    for metric in metrics:

        itemid = metric.get("itemid")

        if itemid is None:
            continue

        itemid = str(itemid)

        unique[itemid] = metric

    print(f"[+] Selected unique items: {len(unique)}")

    output = []

    semantic_counter = Counter()
    transformation_counter = Counter()
    confidence_counter = Counter()
    canonical_counter = Counter()
    excluded_counter = Counter()

    for itemid, metric in unique.items():

        classification = classify_metric(metric)

        record = dict(metric)

        record.update(classification)

        # Keep identity explicit
        record["itemid"] = str(itemid)

        # Useful metadata for downstream audits
        record["preprocessing"] = metric.get(
            "preprocessing",
            [],
        )

        record["preprocessing_types"] = [
            str(x.get("type"))
            for x in metric.get("preprocessing", [])
            if isinstance(x, dict)
            and x.get("type") is not None
        ]

        record["master_itemid"] = str(
            metric.get("master_itemid", "0")
        )

        record["interfaceid"] = str(
            metric.get("interfaceid", "0")
        )

        output.append(record)

        semantic_counter[
            classification["semantic_type"]
        ] += 1

        transformation_counter[
            classification["transformation"]
        ] += 1

        confidence_counter[
            classification["confidence"]
        ] += 1

        canonical = classification["canonical_metric"]

        if canonical:
            canonical_counter[canonical] += 1

        if classification["excluded"]:
            excluded_counter[
                classification["exclude_reason"]
            ] += 1

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("SEMANTIC METRIC SUMMARY")
    print("=" * 60)

    print(f"Selected       : {len(metrics)}")
    print(f"Unique items   : {len(output)}")

    print()
    print("Semantic types:")

    for key, value in sorted(
        semantic_counter.items()
    ):
        print(f"  {key:20s} : {value}")

    print()
    print("Transformations:")

    for key, value in sorted(
        transformation_counter.items()
    ):
        print(f"  {key:20s} : {value}")

    print()
    print("Confidence:")

    for key, value in sorted(
        confidence_counter.items()
    ):
        print(f"  {key:20s} : {value}")

    print()
    print("Canonical metrics:")

    for key, value in sorted(
        canonical_counter.items()
    ):
        print(f"  {key:25s} : {value}")

    print()
    print("Excluded:")

    if excluded_counter:
        for key, value in sorted(
            excluded_counter.items()
        ):
            print(f"  {str(key):35s} : {value}")
    else:
        print("  none")

    print()
    print(f"[+] Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()