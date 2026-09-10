#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime

import requests


# ============================================================
# Configuration
# ============================================================

ZABBIX_URL = os.getenv(
    "ZABBIX_URL",
    "http://192.168.3.10/api_jsonrpc.php"
)

ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

OUTPUT_FILE = os.getenv(
    "OUTPUT_FILE",
    "zabbix_inventory.json"
)

TIMEOUT = 15


# ============================================================
# Zabbix API Client
# ============================================================

class ZabbixAPI:

    def __init__(self, url, token):
        self.url = url
        self.token = token

        self.session = requests.Session()

        self.session.headers.update({
            "Content-Type": "application/json-rpc",
        })

        self.request_id = 0

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
            timeout=TIMEOUT,
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
# Metric classification
# ============================================================

def classify_metric(item):

    text = " ".join([
        str(item.get("name", "")),
        str(item.get("key_", "")),
        str(item.get("snmp_oid", "")),
    ]).lower()

    categories = []

    rules = {
        "interface_traffic": [
            "inbound traffic",
            "outbound traffic",
            "bits received",
            "bits sent",
            "ifhcinoctets",
            "ifhcoutoctets",
            "net.if.in",
            "net.if.out",
        ],

        "packets": [
            "packets received",
            "packets sent",
            "ifhcinucastpkts",
            "ifhcoutucastpkts",
            "packets",
        ],

        "errors": [
            "error",
            "errors",
            "ifinerrors",
            "ifouterrors",
        ],

        "discards": [
            "discard",
            "discards",
            "ifindiscards",
            "ifoutdiscards",
        ],

        "cpu": [
            "cpu",
            "processor utilization",
            "system.cpu",
        ],

        "memory": [
            "memory",
            "mem.",
            "vm.memory",
        ],

        "temperature": [
            "temperature",
            "temp",
        ],

        "fan": [
            "fan",
        ],

        "power": [
            "power",
            "psu",
            "power supply",
        ],

        "uptime": [
            "uptime",
            "sysuptime",
        ],

        "availability": [
            "availability",
            "icmp",
            "ping",
        ],

        "latency": [
            "latency",
            "response time",
            "rtt",
        ],

        "snmp": [
            "snmp",
        ],
    }

    for category, keywords in rules.items():

        for keyword in keywords:

            if keyword in text:
                categories.append(category)
                break

    if not categories:
        categories.append("other")

    return categories


# ============================================================
# Main discovery
# ============================================================

def main():

    if not ZABBIX_TOKEN:
        print(
            "ERROR: ZABBIX_TOKEN environment variable is not set.",
            file=sys.stderr,
        )

        print(
            "\nExample:",
            file=sys.stderr,
        )

        print(
            'export ZABBIX_TOKEN="your-token"',
            file=sys.stderr,
        )

        sys.exit(1)

    print("=" * 70)
    print("ZABBIX INVENTORY DISCOVERY")
    print("=" * 70)

    print(f"API URL : {ZABBIX_URL}")
    print()

    zabbix = ZabbixAPI(
        ZABBIX_URL,
        ZABBIX_TOKEN,
    )

    # --------------------------------------------------------
    # 1. API connectivity / version
    # --------------------------------------------------------

    print("[1/5] Checking Zabbix API...")

    version = zabbix.call(
        "apiinfo.version",
        {},
        authenticated=False,
    )

    print(f"      Zabbix version : {version}")

    # --------------------------------------------------------
    # 2. Host discovery
    # --------------------------------------------------------

    print("\n[2/5] Discovering hosts...")

    hosts = zabbix.call(
        "host.get",
        {
            "output": [
                "hostid",
                "host",
                "name",
                "status",
            ],

            "selectGroups": [
                "groupid",
                "name",
            ],

            "selectInterfaces": [
                "interfaceid",
                "type",
                "main",
                "useip",
                "ip",
                "dns",
                "port",
            ],

            "selectTags": "extend",

            "selectInventory": "extend",

            "selectParentTemplates": [
                "templateid",
                "host",
                "name",
            ],

            "sortfield": "name",
        },
    )

    print(f"      Hosts found : {len(hosts)}")

    # --------------------------------------------------------
    # 3. Process each host
    # --------------------------------------------------------

    print("\n[3/5] Discovering metrics...")

    inventory = []

    total_items = 0

    for index, host in enumerate(hosts, start=1):

        hostid = host["hostid"]

        print(
            f"      [{index}/{len(hosts)}] "
            f'{host["name"]}'
        )

        # ----------------------------------------------------
        # Get items
        # ----------------------------------------------------

        items = zabbix.call(
            "item.get",
            {
                "output": [
                    "itemid",
                    "name",
                    "key_",
                    "type",
                    "value_type",
                    "units",
                    "delay",
                    "history",
                    "trends",
                    "status",
                    "state",
                    "error",
                    "snmp_oid",
                    "interfaceid",
                    "master_itemid",
                    "templateid",
                    "lastvalue",
                    "lastclock",
                ],

                "hostids": hostid,

                "sortfield": "name",
            },
        )

        total_items += len(items)

        # ----------------------------------------------------
        # Add category to every metric
        # ----------------------------------------------------

        metric_list = []

        for item in items:

            categories = classify_metric(item)

            metric = {
                "itemid": item.get("itemid"),
                "name": item.get("name"),
                "key": item.get("key_"),
                "type": item.get("type"),
                "value_type": item.get("value_type"),
                "units": item.get("units"),
                "delay": item.get("delay"),
                "history": item.get("history"),
                "trends": item.get("trends"),
                "status": item.get("status"),
                "state": item.get("state"),
                "error": item.get("error"),
                "snmp_oid": item.get("snmp_oid"),
                "interfaceid": item.get("interfaceid"),
                "templateid": item.get("templateid"),
                "last_value": item.get("lastvalue"),
                "last_clock": item.get("lastclock"),
                "categories": categories,
            }

            metric_list.append(metric)

        # ----------------------------------------------------
        # Host object
        # ----------------------------------------------------

        host_data = {
            "hostid": host.get("hostid"),
            "host": host.get("host"),
            "name": host.get("name"),
            "status": host.get("status"),

            "groups": host.get(
                "groups",
                []
            ),

            "interfaces": host.get(
                "interfaces",
                []
            ),

            "tags": host.get(
                "tags",
                []
            ),

            "inventory": host.get(
                "inventory",
                {}
            ),

            "templates": host.get(
                "parentTemplates",
                []
            ),

            "metrics": metric_list,

            "metric_count": len(metric_list),
        }

        inventory.append(host_data)

    # --------------------------------------------------------
    # 4. Summary
    # --------------------------------------------------------

    print("\n[4/5] Building summary...")

    category_count = {}

    for host in inventory:

        for metric in host["metrics"]:

            for category in metric["categories"]:

                category_count[category] = (
                    category_count.get(category, 0) + 1
                )

    summary = {
        "host_count": len(inventory),
        "metric_count": total_items,
        "metric_categories": category_count,
    }

    # --------------------------------------------------------
    # 5. Save result
    # --------------------------------------------------------

    print("\n[5/5] Saving inventory...")

    result = {
        "generated_at": datetime.utcnow().isoformat() + "Z",

        "zabbix": {
            "url": ZABBIX_URL,
            "version": version,
        },

        "summary": summary,

        "hosts": inventory,
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print("=" * 70)
    print("DISCOVERY COMPLETE")
    print("=" * 70)

    print(
        f"Hosts   : {summary['host_count']}"
    )

    print(
        f"Metrics : {summary['metric_count']}"
    )

    print(
        f"Output  : {OUTPUT_FILE}"
    )

    print("\nMetric categories:")

    for category, count in sorted(
        category_count.items(),
        key=lambda x: x[1],
        reverse=True,
    ):

        print(
            f"  {category:<25} {count}"
        )


if __name__ == "__main__":
    main()