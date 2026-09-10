import json

with open("semantic_metrics.json", "r", encoding="utf-8") as f:
    metrics = json.load(f)

unknown = [
    m
    for m in metrics
    if m.get("semantic_type") == "unknown"
]

print(f"Unknown metrics: {len(unknown)}\n")

for i, metric in enumerate(unknown, 1):
    print("=" * 80)
    print(f"[{i}]")

    fields = [
        "itemid",
        "hostid",
        "host",
        "name",
        "key",
        "units",
        "value_type",
        "type",
        "delay",
        "history",
        "trends",
        "status",
        "state",
        "error",
        "last_value",
        "last_clock",
        "snmp_oid",
        "interfaceid",
        "templateid",
        "semantic_type",
        "transformation",
        "canonical_metric",
        "confidence",
        "excluded",
        "exclude_reason",
        "classification_reason",
    ]

    for field in fields:
        print(f"{field:25s}: {metric.get(field)}")