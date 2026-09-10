#!/usr/bin/env python3

import json
import re
from pathlib import Path


INPUT_FILE = "zabbix_inventory.json"
OUTPUT_FILE = "scope_config.json"


# ============================================================
# DEVICE CLASSIFICATION RULES
# ============================================================

SCOPE_RULES = {
    "switch": [
        r"\bICX\b",
        r"\bSardina\b",
        r"\bMikrotik\b",
        r"\bExxadata\b",
        r"\bNexus\b",
        r"\bOpenStck\b",
        r"\bOpenStack\b",
        r"\bSW[-_]",
        r"\bCore[-_]?SW\b",
        r"\bCES[-_]?SW\b",
        r"\bISP[-_]?SW\b",
        r"\bX460G2\b"
    ],

    "router": [
        r"\bMikrotik\b",
        r"\bMikroTik\b",
        r"\bRouter\b",
        r"\bRTR[-_]"
    ],

    "firewall": [
        r"\bpfsense\b",
        r"\bPFSense\b",
        r"\bFortigate\b",
        r"\bFortiGate\b",
        r"\bFortinet\b",
        r"\bFirewall\b"
    ],

    "access_point": [
        r"\bAP[-_].*\bVDX\b",
        r"\bAP[-_].*\bICX\b",
        r"\bAP[-_]?RU\b",
        r"\bRuijie\b"
    ]
}


COMPILED_RULES = {
    category: [re.compile(pattern, re.IGNORECASE)
               for pattern in patterns]
    for category, patterns in SCOPE_RULES.items()
}


# ============================================================
# HELPERS
# ============================================================

def load_inventory():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def host_text(host):
    """
    Gabungkan semua informasi yang berguna untuk classification.
    """

    values = [
        str(host.get("host", "")),
        str(host.get("name", ""))
    ]

    inventory = host.get("inventory", {})

    if isinstance(inventory, dict):
        values.extend([
            str(inventory.get("name", "")),
            str(inventory.get("model", "")),
            str(inventory.get("vendor", "")),
            str(inventory.get("os", ""))
        ])

    templates = host.get("templates", [])

    for template in templates:
        if isinstance(template, dict):
            values.extend([
                str(template.get("host", "")),
                str(template.get("name", ""))
            ])

    return " ".join(values)


def classify_host(host):
    text = host_text(host)

    matches = []

    for category, patterns in COMPILED_RULES.items():
        for pattern in patterns:
            if pattern.search(text):
                matches.append(category)
                break

    return list(dict.fromkeys(matches))


# ============================================================
# MAIN
# ============================================================

def main():

    inventory = load_inventory()

    hosts = inventory.get("hosts", [])

    scope = {
        "version": "1.0",
        "description": "AI-NOC network device scope",
        "source": INPUT_FILE,
        "default_action": "exclude",

        "include": {
            "switch": [],
            "router": [],
            "firewall": [],
            "access_point": []
        },

        "exclude_hostids": [],
        "unmatched_hostids": []
    }

    classified = set()

    print("=" * 80)
    print("GENERATING AI-NOC SCOPE CONFIG")
    print("=" * 80)

    for host in hosts:

        hostid = str(host.get("hostid", ""))
        hostname = host.get("host", "")
        name = host.get("name", "")

        if not hostid:
            continue

        categories = classify_host(host)

        if categories:

            classified.add(hostid)

            print(
                f"[INCLUDE] {hostid:<8} "
                f"{hostname:<35} "
                f"{', '.join(categories)}"
            )

            for category in categories:
                scope["include"][category].append({
                    "hostid": hostid,
                    "host": hostname,
                    "name": name
                })

        else:

            scope["unmatched_hostids"].append({
                "hostid": hostid,
                "host": hostname,
                "name": name
            })

    # Host yang tidak ter-classify tetap exclude.
    for host in hosts:

        hostid = str(host.get("hostid", ""))

        if hostid and hostid not in classified:
            scope["exclude_hostids"].append(hostid)

    # Sort supaya deterministic.
    for category in scope["include"]:
        scope["include"][category].sort(
            key=lambda x: x["hostid"]
        )

    scope["exclude_hostids"].sort(
        key=lambda x: int(x) if x.isdigit() else x
    )

    scope["unmatched_hostids"].sort(
        key=lambda x: int(x["hostid"])
        if x["hostid"].isdigit()
        else x["hostid"]
    )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(
            scope,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    for category, devices in scope["include"].items():
        print(f"{category:<15}: {len(devices):>4}")

    print(
        f"{'Excluded':<15}: "
        f"{len(scope['exclude_hostids']):>4}"
    )

    print(
        f"{'Unmatched':<15}: "
        f"{len(scope['unmatched_hostids']):>4}"
    )

    print()
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    main()