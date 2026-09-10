import json
import re


INPUT_FILE = "zabbix_inventory.json"
OUTPUT_FILE = "selected_metrics.json"


# ============================================================
# P1 - Core Network Telemetry
# ============================================================

P1_PATTERNS = [

    # --------------------------------------------------------
    # Interface traffic
    # --------------------------------------------------------
    # Contoh:
    # net.if.in["ens3",]
    # net.if.out["ens3",]
    #
    # Kita akan melakukan validasi status/state setelah pattern.
    #
    r'^net\.if\.in\[',
    r'^net\.if\.out\[',


    # --------------------------------------------------------
    # Interface packet rate
    # --------------------------------------------------------
    # Contoh:
    # net.if.in.pass.v4.pps[12]
    # net.if.in.pass.v6.pps[12]
    # net.if.out.pass.v4.pps[12]
    # net.if.out.pass.v6.pps[12]
    #
    r'^net\.if\.in\.pass\.v[46]\.pps\[',
    r'^net\.if\.out\.pass\.v[46]\.pps\[',


    # --------------------------------------------------------
    # Interface errors
    # --------------------------------------------------------
    r'^net\.if\.in\.errors\[',
    r'^net\.if\.out\.errors\[',


    # --------------------------------------------------------
    # Interface discards
    # --------------------------------------------------------
    r'^net\.if\.in\.discards\[',
    r'^net\.if\.out\.discards\[',


    # --------------------------------------------------------
    # Interface operational status
    # --------------------------------------------------------
    r'^net\.if\.status\[',


    # --------------------------------------------------------
    # ICMP quality
    # --------------------------------------------------------
    r'^icmppingloss$',
    r'^icmppingsec$',
]


# ============================================================
# P2 - Device Health
# ============================================================

P2_PATTERNS = [

    # CPU
    r'^system\.cpu\.util',

    # Memory
    r'^vm\.memory\.util',

    # Temperature
    r'^sensor\.temp\.value',

    # Fan
    r'^sensor\.fan\.status',

    # PSU
    r'^sensor\.psu\.status',

    # Uptime
    r'^system\.net\.uptime',
]


def matches(key, patterns):
    """Check whether a metric key matches any pattern."""
    return any(
        re.search(pattern, key or "", re.IGNORECASE)
        for pattern in patterns
    )


def is_enabled(metric):
    """
    Zabbix item status.

    status=0 -> enabled
    status=1 -> disabled
    """
    return str(metric.get("status", "1")) == "0"


def classify_metric(metric):

    key = metric.get("key", "")

    # Ignore disabled items
    if not is_enabled(metric):
        return None

    # P1
    if matches(key, P1_PATTERNS):
        return "P1"

    # P2
    if matches(key, P2_PATTERNS):
        return "P2"

    return None


# ============================================================
# Load inventory
# ============================================================

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    inventory = json.load(f)


selected = []


# ============================================================
# Process hosts
# ============================================================

for host in inventory.get("hosts", []):

    host_id = host.get("hostid")
    host_name = host.get("host") or host.get("name")

    for metric in host.get("metrics", []):

        priority = classify_metric(metric)

        if priority is None:
            continue

        selected.append({
            "priority": priority,

            "hostid": host_id,
            "host": host_name,

            "itemid": metric.get("itemid"),
            "metric_name": metric.get("name"),
            "key": metric.get("key"),

            "units": metric.get("units"),
            "value_type": metric.get("value_type"),
            "delay": metric.get("delay"),

            "interfaceid": metric.get("interfaceid"),

            "last_value": metric.get("last_value"),
            "last_clock": metric.get("last_clock"),

            "status": metric.get("status"),
            "state": metric.get("state"),

            "categories": metric.get("categories", []),
        })


# ============================================================
# Save
# ============================================================

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(
        selected,
        f,
        indent=2,
        ensure_ascii=False
    )


# ============================================================
# Summary
# ============================================================

p1 = [x for x in selected if x["priority"] == "P1"]
p2 = [x for x in selected if x["priority"] == "P2"]


print("=" * 60)
print("ZABBIX METRIC SELECTION")
print("=" * 60)

print(f"Total selected : {len(selected)}")
print(f"P1             : {len(p1)}")
print(f"P2             : {len(p2)}")

print()
print(f"Output         : {OUTPUT_FILE}")