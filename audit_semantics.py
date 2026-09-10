import json
from collections import Counter


SEMANTIC_FILE = "semantic_metrics.json"
AUDIT_FILE = "semantic_audit.json"


# ============================================================
# Expected semantic types per canonical metric
# ============================================================
#
# Catatan:
#
# in_bps / out_bps dan error/discard rate dapat berasal dari:
#
#   counter -> delta_rate
#
# atau metric yang memang sudah berupa rate:
#
#   rate -> direct
#
# Karena itu keduanya tidak boleh dipaksa hanya menjadi
# semantic_type tertentu.
#
EXPECTED_CANONICAL_SEMANTICS = {
    "in_bps": {
        "counter",
        "rate",
    },
    "out_bps": {
        "counter",
        "rate",
    },
    "in_error_rate": {
        "counter",
        "rate",
    },
    "out_error_rate": {
        "counter",
        "rate",
    },
    "in_discard_rate": {
        "counter",
        "rate",
    },
    "out_discard_rate": {
        "counter",
        "rate",
    },
    "in_pps": {
        "rate",
    },
    "out_pps": {
        "rate",
    },
    "cpu_pct": {
        "gauge",
    },
    "memory_pct": {
        "gauge",
    },
    "temperature_c": {
        "gauge",
    },
    "icmp_loss_pct": {
        "gauge",
    },
    "icmp_rtt_sec": {
        "gauge",
    },
    "oper_status": {
        "state",
    },
    "fan_status": {
        "state",
    },
    "psu_status": {
        "state",
    },
    "uptime": {
        "gauge",
    },
}


# ============================================================
# Expected transformation per semantic type
# ============================================================

EXPECTED_TRANSFORMATION = {
    "counter": "delta_rate",
    "gauge": "direct",
    "rate": "direct",
    "state": "direct",
}


# ============================================================
# Helpers
# ============================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def is_excluded(metric):
    """
    Metric excluded dari downstream pipeline.

    Excluded metric bukan unknown.
    """

    return bool(metric.get("excluded", False))


def is_unknown(metric):
    """
    Unknown hanya untuk metric yang:
      - semantic_type == unknown
      - DAN tidak excluded
    """

    return (
        metric.get("semantic_type") == "unknown"
        and not is_excluded(metric)
    )


def fmt(value):
    """
    Safe formatting untuk None / value lainnya.
    """

    if value is None:
        return "<none>"

    return str(value)


# ============================================================
# Validate canonical metric
# ============================================================

def validate_canonical_metric(metric):
    issues = []

    if is_excluded(metric):
        return issues

    canonical = metric.get("canonical_metric")

    # Metric tanpa canonical metric tidak otomatis salah.
    #
    # Contohnya generic:
    #   interface_counter
    #   rate
    #
    # masih dapat dipertahankan untuk audit lanjutan.
    if canonical is None:
        return issues

    expected_semantics = EXPECTED_CANONICAL_SEMANTICS.get(
        canonical
    )

    # Canonical metric yang belum memiliki aturan audit.
    if expected_semantics is None:
        return issues

    semantic_type = metric.get("semantic_type")

    if semantic_type not in expected_semantics:
        issues.append({
            "type": "wrong_semantic_type",
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
            "canonical_metric": canonical,
            "expected": sorted(expected_semantics),
            "actual": semantic_type,
        })

    return issues


# ============================================================
# Validate transformation
# ============================================================

def validate_transformation(metric):
    issues = []

    if is_excluded(metric):
        return issues

    semantic_type = metric.get("semantic_type")
    transformation = metric.get("transformation")

    expected = EXPECTED_TRANSFORMATION.get(
        semantic_type
    )

    # Unknown semantic ditangani oleh validator unknown.
    if expected is None:
        return issues

    if transformation != expected:
        issues.append({
            "type": "wrong_transformation",
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
            "canonical_metric": metric.get("canonical_metric"),
            "semantic_type": semantic_type,
            "expected": expected,
            "actual": transformation,
        })

    return issues


# ============================================================
# Validate unknown semantic
# ============================================================

def validate_unknown(metric):
    issues = []

    if is_unknown(metric):
        issues.append({
            "type": "unknown_semantic",
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
            "semantic_type": metric.get("semantic_type"),
            "canonical_metric": metric.get("canonical_metric"),
            "transformation": metric.get("transformation"),
            "confidence": metric.get("confidence"),
        })

    return issues


# ============================================================
# Validate confidence
# ============================================================

def validate_confidence(metric):
    issues = []

    if is_excluded(metric):
        return issues

    confidence = metric.get("confidence")

    if confidence not in {
        "high",
        "medium",
        "low",
    }:
        issues.append({
            "type": "invalid_confidence",
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
            "confidence": confidence,
        })

    return issues


# ============================================================
# Validate excluded metrics
# ============================================================

def validate_excluded(metric):
    issues = []

    if not is_excluded(metric):
        return issues

    exclude_reason = metric.get("exclude_reason")

    if not exclude_reason:
        issues.append({
            "type": "excluded_without_reason",
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
        })

    return issues


# ============================================================
# Validate one metric
# ============================================================

def validate_metric(metric):
    issues = []

    # Excluded metric:
    # hanya validasi metadata exclusion.
    if is_excluded(metric):
        issues.extend(
            validate_excluded(metric)
        )

        return issues

    # Normal metric.
    issues.extend(
        validate_unknown(metric)
    )

    issues.extend(
        validate_canonical_metric(metric)
    )

    issues.extend(
        validate_transformation(metric)
    )

    issues.extend(
        validate_confidence(metric)
    )

    return issues


# ============================================================
# Main
# ============================================================

def main():

    metrics = load_json(
        SEMANTIC_FILE
    )

    if not isinstance(metrics, list):
        raise ValueError(
            f"{SEMANTIC_FILE} harus berupa JSON list"
        )

    total_metrics = len(metrics)

    # ========================================================
    # Excluded
    # ========================================================

    excluded_metrics = [
        metric
        for metric in metrics
        if is_excluded(metric)
    ]

    excluded_count = len(
        excluded_metrics
    )

    usable_metrics = (
        total_metrics
        - excluded_count
    )

    # ========================================================
    # Semantic types
    #
    # IMPORTANT:
    # excluded metric tidak masuk semantic count.
    # ========================================================

    semantic_counts = Counter(
        metric.get("semantic_type")
        for metric in metrics
        if not is_excluded(metric)
    )

    # ========================================================
    # Transformations
    # ========================================================

    transformation_counts = Counter(
        metric.get("transformation")
        for metric in metrics
        if not is_excluded(metric)
    )

    # ========================================================
    # Confidence
    # ========================================================

    confidence_counts = Counter(
        metric.get("confidence")
        for metric in metrics
        if not is_excluded(metric)
    )

    # ========================================================
    # Canonical metrics
    # ========================================================

    canonical_counts = Counter(
        metric.get("canonical_metric")
        for metric in metrics
        if (
            not is_excluded(metric)
            and metric.get("canonical_metric") is not None
        )
    )

    # ========================================================
    # Unknown metrics
    #
    # IMPORTANT:
    # excluded metric tidak dihitung sebagai unknown.
    # ========================================================

    unknown_metrics = [
        metric
        for metric in metrics
        if is_unknown(metric)
    ]

    # ========================================================
    # Excluded by reason
    # ========================================================

    excluded_by_reason = Counter(
        metric.get("exclude_reason")
        for metric in excluded_metrics
    )

    # ========================================================
    # Validation issues
    # ========================================================

    issues = []

    for metric in metrics:
        issues.extend(
            validate_metric(metric)
        )

    # ========================================================
    # Duplicate itemid
    #
    # itemid adalah identity utama Zabbix item.
    # ========================================================

    itemids = [
        metric.get("itemid")
        for metric in metrics
        if metric.get("itemid") is not None
    ]

    itemid_counts = Counter(
        itemids
    )

    duplicate_itemids = {
        itemid: count
        for itemid, count in itemid_counts.items()
        if count > 1
    }

    # ========================================================
    # Excluded details
    # ========================================================

    excluded_details = [
        {
            "itemid": metric.get("itemid"),
            "hostid": metric.get("hostid"),
            "host": metric.get("host"),
            "key": metric.get("key"),
            "semantic_type": metric.get("semantic_type"),
            "transformation": metric.get("transformation"),
            "canonical_metric": metric.get(
                "canonical_metric"
            ),
            "confidence": metric.get(
                "confidence"
            ),
            "exclude_reason": metric.get(
                "exclude_reason"
            ),
        }
        for metric in excluded_metrics
    ]

    # ========================================================
    # Issue counts
    # ========================================================

    issue_counts = Counter(
        issue["type"]
        for issue in issues
    )

    # ========================================================
    # Audit object
    # ========================================================

    audit = {
        "total_metrics": total_metrics,

        "usable_metrics": usable_metrics,

        "excluded_metrics": excluded_count,

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

        "confidence": dict(
            sorted(
                confidence_counts.items()
            )
        ),

        "canonical_metrics": dict(
            sorted(
                canonical_counts.items()
            )
        ),

        "unknown_semantic": len(
            unknown_metrics
        ),

        "unknown_metrics": [
            {
                "itemid": metric.get("itemid"),
                "hostid": metric.get("hostid"),
                "host": metric.get("host"),
                "key": metric.get("key"),
                "semantic_type": metric.get(
                    "semantic_type"
                ),
                "transformation": metric.get(
                    "transformation"
                ),
                "canonical_metric": metric.get(
                    "canonical_metric"
                ),
                "confidence": metric.get(
                    "confidence"
                ),
            }
            for metric in unknown_metrics
        ],

        "excluded_by_reason": dict(
            sorted(
                excluded_by_reason.items()
            )
        ),

        "excluded_metric_details": excluded_details,

        "duplicate_itemids": duplicate_itemids,

        "duplicate_itemid_count": len(
            duplicate_itemids
        ),

        "issues": issues,

        "issue_counts": dict(
            sorted(
                issue_counts.items()
            )
        ),

        "validation": {
            "unknown_semantic_count": len(
                unknown_metrics
            ),
            "excluded_count": excluded_count,
            "duplicate_itemid_count": len(
                duplicate_itemids
            ),
            "total_issue_count": len(
                issues
            ),
        },
    }

    # ========================================================
    # Write JSON
    # ========================================================

    with open(
        AUDIT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            audit,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # ========================================================
    # Console output
    # ========================================================

    print("=" * 70)
    print("SEMANTIC AUDIT")
    print("=" * 70)

    print(
        f"\nTotal metrics        : "
        f"{total_metrics}"
    )

    print(
        f"Usable metrics       : "
        f"{usable_metrics}"
    )

    print(
        f"Excluded metrics     : "
        f"{excluded_count}"
    )

    # --------------------------------------------------------
    # Semantic
    # --------------------------------------------------------

    print("\nSemantic types:")

    for name, count in sorted(
        semantic_counts.items()
    ):
        print(
            f"  {str(name):15s}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # Excluded
    # --------------------------------------------------------

    print("\nExcluded:")

    if excluded_by_reason:

        for reason, count in sorted(
            excluded_by_reason.items()
        ):
            print(
                f"  {fmt(reason):35s}: "
                f"{count}"
            )

    else:
        print("  none")

    # --------------------------------------------------------
    # Transformations
    # --------------------------------------------------------

    print("\nTransformations:")

    for name, count in sorted(
        transformation_counts.items()
    ):
        print(
            f"  {str(name):15s}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    print("\nConfidence:")

    for name, count in sorted(
        confidence_counts.items()
    ):
        print(
            f"  {str(name):15s}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # Canonical
    # --------------------------------------------------------

    print("\nCanonical metrics:")

    for name, count in sorted(
        canonical_counts.items()
    ):
        print(
            f"  {str(name):25s}: "
            f"{count}"
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        "\nUnknown semantic      : "
        f"{len(unknown_metrics)}"
    )

    print(
        "Duplicate itemids     : "
        f"{len(duplicate_itemids)}"
    )

    print(
        "Total issues          : "
        f"{len(issues)}"
    )

    # --------------------------------------------------------
    # Unknown details
    # --------------------------------------------------------

    if unknown_metrics:

        print("\nUnknown metrics:")

        for metric in unknown_metrics:

            print("-" * 70)

            print(
                f"itemid      : "
                f"{fmt(metric.get('itemid'))}"
            )

            print(
                f"hostid      : "
                f"{fmt(metric.get('hostid'))}"
            )

            print(
                f"host        : "
                f"{fmt(metric.get('host'))}"
            )

            print(
                f"key         : "
                f"{fmt(metric.get('key'))}"
            )

            print(
                f"semantic    : "
                f"{fmt(metric.get('semantic_type'))}"
            )

            print(
                f"canonical   : "
                f"{fmt(metric.get('canonical_metric'))}"
            )

            print(
                f"transformation: "
                f"{fmt(metric.get('transformation'))}"
            )

    # --------------------------------------------------------
    # Excluded details
    # --------------------------------------------------------

    if excluded_metrics:

        print("\nExcluded metrics:")

        for metric in excluded_metrics:

            print("-" * 70)

            print(
                f"itemid      : "
                f"{fmt(metric.get('itemid'))}"
            )

            print(
                f"host        : "
                f"{fmt(metric.get('host'))}"
            )

            print(
                f"key         : "
                f"{fmt(metric.get('key'))}"
            )

            print(
                f"reason      : "
                f"{fmt(metric.get('exclude_reason'))}"
            )

    # --------------------------------------------------------
    # Issues
    # --------------------------------------------------------

    print("\nIssue counts:")

    if issue_counts:

        for issue_type, count in sorted(
            issue_counts.items()
        ):
            print(
                f"  {issue_type:30s}: "
                f"{count}"
            )

    else:

        print("  none")

    print(
        "\nAudit written to:",
        AUDIT_FILE
    )


if __name__ == "__main__":
    main()