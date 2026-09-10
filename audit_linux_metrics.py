#!/usr/bin/env python3

import json
import os
import statistics
from datetime import datetime, timezone

import requests


# ============================================================
# Configuration
# ============================================================

ZABBIX_URL = os.getenv(
    "ZABBIX_URL",
    "http://192.168.3.10/api_jsonrpc.php",
)

ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

OUTPUT_FILE = "linux_metrics_audit.json"

# How many historical samples to retrieve per item
HISTORY_LIMIT = 100

# Zabbix history types:
# 0 = numeric float
# 3 = numeric unsigned integer
#
# Linux dropped/errors metrics are normally integer-like,
# so try numeric unsigned first.
HISTORY_TYPES = [3, 0]

TARGET_ITEMIDS = [
    "80514",
    "80515",
    "80517",
    "80518",
    "50113",
    "50114",
    "50116",
    "50117",
]


# ============================================================
# Zabbix API Client
# ============================================================

class ZabbixAPI:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.request_id = 0

        self.session = requests.Session()

    def call(self, method, params=None, authenticated=True):
        self.request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id,
        }

        headers = {
            "Content-Type": "application/json-rpc",
        }

        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"

        response = self.session.post(
            self.url,
            json=payload,
            headers=headers,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        if "error" in data:
            error = data["error"]

            raise RuntimeError(
                f'Zabbix API error: '
                f'{error.get("code")} - '
                f'{error.get("message")} - '
                f'{error.get("data")}'
            )

        return data["result"]


# ============================================================
# Utility Functions
# ============================================================

def ts_to_iso(timestamp):
    return datetime.fromtimestamp(
        int(timestamp),
        tz=timezone.utc,
    ).isoformat()


def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def calculate_deltas(values):
    """
    Calculate consecutive deltas.

    Positive delta:
        possible counter increment

    Zero:
        counter unchanged

    Negative:
        possible counter reset/wraparound
    """

    deltas = []

    for previous, current in zip(values, values[1:]):
        deltas.append(current - previous)

    return deltas


def is_monotonic_non_decreasing(values):
    if len(values) < 2:
        return False

    return all(
        current >= previous
        for previous, current in zip(values, values[1:])
    )


def calculate_statistics(values):
    if not values:
        return {}

    return {
        "min": min(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "unique_values": len(set(values)),
    }


# ============================================================
# Semantic Analysis
# ============================================================

def analyze_history(history):
    """
    Analyze historical values and determine whether the metric
    behaves more like a cumulative counter or an interval metric.
    """

    values = []

    samples = []

    for row in history:
        value = safe_float(row.get("value"))

        if value is None:
            continue

        values.append(value)

        samples.append({
            "clock": int(row["clock"]),
            "timestamp": ts_to_iso(row["clock"]),
            "value": value,
        })

    if len(values) < 2:
        return {
            "sample_count": len(values),
            "classification": "insufficient_data",
            "confidence": "low",
            "reason": "Less than 2 valid historical samples",
            "samples": samples,
        }

    deltas = calculate_deltas(values)

    positive_deltas = [d for d in deltas if d > 0]
    zero_deltas = [d for d in deltas if d == 0]
    negative_deltas = [d for d in deltas if d < 0]

    positive_ratio = (
        len(positive_deltas) / len(deltas)
        if deltas
        else 0
    )

    zero_ratio = (
        len(zero_deltas) / len(deltas)
        if deltas
        else 0
    )

    negative_ratio = (
        len(negative_deltas) / len(deltas)
        if deltas
        else 0
    )

    monotonic = is_monotonic_non_decreasing(values)

    # --------------------------------------------------------
    # Heuristic classification
    # --------------------------------------------------------
    #
    # Strong counter signal:
    #
    #   value 0
    #   value 0
    #   value 5
    #   value 5
    #   value 9
    #
    # mostly non-decreasing, with occasional increments.
    #
    # Interval/rate signal:
    #
    #   0
    #   4
    #   1
    #   8
    #   0
    #
    # frequent decreases.
    # --------------------------------------------------------

    if monotonic:
        if positive_ratio > 0:
            classification = "likely_counter"
            confidence = "high"
            reason = (
                "Historical values are monotonically non-decreasing "
                "with observed increments."
            )
        else:
            classification = "possible_counter"
            confidence = "medium"
            reason = (
                "Historical values are constant/non-decreasing, "
                "but no increments were observed."
            )

    elif negative_ratio < 0.10 and positive_ratio > 0:
        classification = "likely_counter_with_resets"
        confidence = "medium"
        reason = (
            "Mostly increasing values with occasional decreases, "
            "which may indicate counter resets or interface resets."
        )

    elif negative_ratio >= 0.10:
        classification = "likely_interval_or_rate"
        confidence = "medium"
        reason = (
            "Historical values frequently decrease, which is "
            "inconsistent with a normal cumulative counter."
        )

    else:
        classification = "unknown"
        confidence = "low"
        reason = "History does not provide a clear semantic signal."

    return {
        "sample_count": len(values),

        "first_sample": samples[0] if samples else None,
        "last_sample": samples[-1] if samples else None,

        "statistics": calculate_statistics(values),

        "monotonic_non_decreasing": monotonic,

        "delta_analysis": {
            "total_deltas": len(deltas),
            "positive": len(positive_deltas),
            "zero": len(zero_deltas),
            "negative": len(negative_deltas),

            "positive_ratio": positive_ratio,
            "zero_ratio": zero_ratio,
            "negative_ratio": negative_ratio,

            "min_delta": min(deltas) if deltas else None,
            "max_delta": max(deltas) if deltas else None,
            "mean_delta": (
                statistics.mean(deltas)
                if deltas
                else None
            ),
        },

        "classification": classification,
        "confidence": confidence,
        "reason": reason,

        "samples": samples,
    }


# ============================================================
# Audit One Item
# ============================================================

def audit_item(api, itemid):
    print(f"\n{'=' * 70}")
    print(f"Auditing item: {itemid}")
    print(f"{'=' * 70}")

    # --------------------------------------------------------
    # 1. Get item metadata
    # --------------------------------------------------------

    items = api.call(
        "item.get",
        {
            "output": [
                "itemid",
                "hostid",
                "name",
                "key_",
                "units",
                "value_type",
                "type",
                "delay",
                "status",
                "state",
                "master_itemid",
                "interfaceid",
            ],
            "itemids": [itemid],
        },
    )

    if not items:
        return {
            "itemid": itemid,
            "error": "Item not found",
        }

    item = items[0]

    print(f"Host       : {item.get('hostid')}")
    print(f"Name       : {item.get('name')}")
    print(f"Key        : {item.get('key_')}")
    print(f"Units      : {item.get('units')}")
    print(f"Value type : {item.get('value_type')}")
    print(f"Type       : {item.get('type')}")
    print(f"Delay      : {item.get('delay')}")
    print(f"Status     : {item.get('status')}")
    print(f"State      : {item.get('state')}")
    print(f"Master     : {item.get('master_itemid')}")
    print(f"Interface  : {item.get('interfaceid')}")

    # --------------------------------------------------------
    # 2. Get preprocessing configuration
    # --------------------------------------------------------

    preprocessing = api.call(
        "item.get",
        {
            "output": [
                "itemid",
            ],
            "selectPreprocessing": [
                "type",
                "params",
                "error_handler",
                "error_handler_params",
            ],
            "itemids": [itemid],
        },
    )

    preprocessing_data = []

    if preprocessing:
        preprocessing_data = preprocessing[0].get(
            "preprocessing",
            [],
        )

    # --------------------------------------------------------
    # 3. Retrieve history
    # --------------------------------------------------------

    history_result = None
    history_error = None

    for history_type in HISTORY_TYPES:

        try:
            history_result = api.call(
                "history.get",
                {
                    "output": "extend",
                    "history": history_type,
                    "itemids": [itemid],
                    "sortfield": "clock",
                    "sortorder": "DESC",
                    "limit": HISTORY_LIMIT,
                },
            )

            if history_result:
                print(
                    f"History type {history_type}: "
                    f"{len(history_result)} samples"
                )
                break

        except RuntimeError as exc:
            history_error = str(exc)

    if history_result is None:
        return {
            "item": item,
            "preprocessing": preprocessing_data,
            "error": history_error or "Unable to retrieve history",
        }

    # history.get DESC → reverse to chronological order
    history_result = list(reversed(history_result))

    # --------------------------------------------------------
    # 4. Analyze history
    # --------------------------------------------------------

    analysis = analyze_history(history_result)

    print()
    print(f"Samples        : {analysis.get('sample_count')}")
    print(
        f"Monotonic      : "
        f"{analysis.get('monotonic_non_decreasing')}"
    )

    delta = analysis.get("delta_analysis", {})

    print(f"Positive delta : {delta.get('positive')}")
    print(f"Zero delta     : {delta.get('zero')}")
    print(f"Negative delta : {delta.get('negative')}")

    print(
        f"Classification : "
        f"{analysis.get('classification')}"
    )

    print(
        f"Confidence     : "
        f"{analysis.get('confidence')}"
    )

    print(
        f"Reason         : "
        f"{analysis.get('reason')}"
    )

    # --------------------------------------------------------
    # 5. Semantic recommendation
    # --------------------------------------------------------

    classification = analysis.get("classification")

    if classification in (
        "likely_counter",
        "possible_counter",
        "likely_counter_with_resets",
    ):
        recommended_semantic = "counter"
        recommended_transformation = "delta_rate"
        recommended_canonical = infer_canonical_metric(
            item.get("key_", "")
        )

    elif classification == "likely_interval_or_rate":
        recommended_semantic = "rate"
        recommended_transformation = "direct"
        recommended_canonical = infer_canonical_metric(
            item.get("key_", "")
        )

    else:
        recommended_semantic = "unknown"
        recommended_transformation = "manual_review"
        recommended_canonical = None

    result = {
        "item": item,
        "preprocessing": preprocessing_data,
        "history_type_used": (
            "numeric_unsigned_or_float"
        ),
        "analysis": analysis,
        "recommendation": {
            "semantic_type": recommended_semantic,
            "transformation": recommended_transformation,
            "canonical_metric": recommended_canonical,
        },
    }

    return result


# ============================================================
# Canonical Metric Mapping
# ============================================================

def infer_canonical_metric(key):
    """
    Map Linux interface metric keys into the canonical
    metrics used by semantic_metrics.json.
    """

    key_lower = key.lower()

    is_in = ".in[" in key_lower
    is_out = ".out[" in key_lower

    if "dropped" in key_lower:
        if is_in:
            return "in_discard_rate"

        if is_out:
            return "out_discard_rate"

    if "errors" in key_lower:
        if is_in:
            return "in_error_rate"

        if is_out:
            return "out_error_rate"

    return None


# ============================================================
# Summary
# ============================================================

def build_summary(results):

    summary = {
        "total_items": len(results),
        "likely_counter": 0,
        "likely_counter_with_resets": 0,
        "possible_counter": 0,
        "likely_interval_or_rate": 0,
        "unknown": 0,
        "insufficient_data": 0,
        "errors": 0,
    }

    for result in results:

        if "error" in result and "analysis" not in result:
            summary["errors"] += 1
            continue

        classification = result.get(
            "analysis",
            {},
        ).get(
            "classification"
        )

        if classification in summary:
            summary[classification] += 1

    return summary


# ============================================================
# Main
# ============================================================

def main():

    if not ZABBIX_TOKEN:
        raise SystemExit(
            "ERROR: ZABBIX_TOKEN environment variable is not set.\n\n"
            "Example:\n"
            "  export ZABBIX_TOKEN='your-token'\n"
            "  python3 audit_linux_metrics.py"
        )

    print("=" * 70)
    print("Linux Interface Metrics Semantic Audit")
    print("=" * 70)

    print(f"Zabbix URL : {ZABBIX_URL}")
    print(f"Items      : {len(TARGET_ITEMIDS)}")
    print(f"History    : {HISTORY_LIMIT} samples/item")

    api = ZabbixAPI(
        url=ZABBIX_URL,
        token=ZABBIX_TOKEN,
    )

    results = []

    for itemid in TARGET_ITEMIDS:

        try:
            result = audit_item(
                api,
                itemid,
            )

            results.append(result)

        except Exception as exc:

            print(
                f"\nERROR auditing {itemid}: {exc}"
            )

            results.append({
                "itemid": itemid,
                "error": str(exc),
            })

    # --------------------------------------------------------
    # Build final audit document
    # --------------------------------------------------------

    output = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "zabbix_url": ZABBIX_URL,

        "purpose": (
            "Audit Linux net.if.in/out dropped/errors "
            "metrics currently classified as unknown/"
            "low-confidence."
        ),

        "heuristic_warning": (
            "Historical behavior is evidence only. "
            "Final semantic classification should also "
            "consider Zabbix item key, item type, template "
            "definition, preprocessing, and source semantics."
        ),

        "target_items": TARGET_ITEMIDS,

        "summary": build_summary(results),

        "items": results,
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

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("AUDIT SUMMARY")
    print("=" * 70)

    for key, value in output["summary"].items():
        print(f"{key:35}: {value}")

    print()
    print(f"Output written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()