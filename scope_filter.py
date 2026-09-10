#!/usr/bin/env python3

import json
from pathlib import Path
from collections import Counter


INPUT_METRICS = Path("semantic_metrics.json")
INPUT_SCOPE = Path("scope_config.json")
INPUT_INVENTORY = Path("zabbix_inventory.json")

OUTPUT_METRICS = Path("scoped_metrics.json")
OUTPUT_AUDIT = Path("scope_filter_audit.json")


# ============================================================
# Load JSON
# ============================================================

def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# Load semantic metrics
# ============================================================

def load_metrics(data):

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        if "metrics" in data:
            return data["metrics"]

    raise ValueError(
        "semantic_metrics.json must be either a list "
        "or contain a 'metrics' field"
    )


# ============================================================
# Build itemid -> host information
#
# zabbix_inventory.json structure:
#
# hosts[]
#   ├── hostid
#   ├── host
#   ├── name
#   └── metrics[]
#          └── itemid
#
# ============================================================

def build_item_index(inventory):

    item_index = {}

    hosts = inventory.get("hosts", [])

    for host in hosts:

        hostid = str(host["hostid"])
        hostname = host.get("host", "")
        name = host.get("name", "")

        for metric in host.get("metrics", []):

            itemid = str(metric["itemid"])

            if itemid in item_index:

                previous = item_index[itemid]

                raise ValueError(
                    f"Duplicate itemid detected: {itemid}\n"
                    f"Existing host: {previous['hostid']}\n"
                    f"New host:      {hostid}"
                )

            item_index[itemid] = {
                "hostid": hostid,
                "host": hostname,
                "name": name,
            }

    return item_index


# ============================================================
# Build hostid -> role
# ============================================================

def build_scope_index(scope_config):

    host_to_role = {}

    include = scope_config.get("include", {})

    for role, hosts in include.items():

        for host in hosts:

            hostid = str(host["hostid"])

            if hostid in host_to_role:

                previous_role = host_to_role[hostid]

                raise ValueError(
                    f"HostID {hostid} has multiple roles:\n"
                    f"  previous: {previous_role}\n"
                    f"  current : {role}"
                )

            host_to_role[hostid] = role

    return host_to_role


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("AI-NOC Scope Filter")
    print("=" * 70)

    # --------------------------------------------------------
    # Load files
    # --------------------------------------------------------

    metrics_data = load_json(INPUT_METRICS)
    scope_config = load_json(INPUT_SCOPE)
    inventory = load_json(INPUT_INVENTORY)

    metrics = load_metrics(metrics_data)

    # --------------------------------------------------------
    # Build indexes
    # --------------------------------------------------------

    item_index = build_item_index(inventory)
    host_to_role = build_scope_index(scope_config)

    print(
        f"Semantic metrics : {len(metrics)}"
    )

    print(
        f"Inventory items  : {len(item_index)}"
    )

    print(
        f"Allowed hosts    : {len(host_to_role)}"
    )

    print()

    # --------------------------------------------------------
    # Filtering
    # --------------------------------------------------------

    scoped_metrics = []
    excluded_metrics = []

    role_counter = Counter()
    host_counter = Counter()
    excluded_host_counter = Counter()

    missing_itemid = []
    item_not_in_inventory = []

    for metric in metrics:

        itemid = str(metric.get("itemid", ""))

        # ----------------------------------------------------
        # semantic_metrics must have itemid
        # ----------------------------------------------------

        if not itemid:

            missing_itemid.append(metric)

            continue

        # ----------------------------------------------------
        # Resolve itemid -> hostid
        # ----------------------------------------------------

        inventory_info = item_index.get(itemid)

        if inventory_info is None:

            item_not_in_inventory.append({
                "itemid": itemid,
                "metric": metric,
            })

            continue

        hostid = inventory_info["hostid"]

        hostname = inventory_info["host"]
        host_name = inventory_info["name"]

        # ----------------------------------------------------
        # Check host scope
        # ----------------------------------------------------

        role = host_to_role.get(hostid)

        if role is None:

            excluded_metrics.append({
                **metric,
                "hostid": hostid,
                "host": hostname,
                "host_name": host_name,
            })

            excluded_host_counter[hostid] += 1

            continue

        # ----------------------------------------------------
        # Include
        # ----------------------------------------------------

        metric_copy = dict(metric)

        metric_copy["hostid"] = hostid
        metric_copy["host"] = hostname
        metric_copy["host_name"] = host_name
        metric_copy["device_role"] = role

        scoped_metrics.append(metric_copy)

        role_counter[role] += 1
        host_counter[hostid] += 1

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    total_input = len(metrics)

    total_scoped = len(scoped_metrics)

    total_excluded = len(excluded_metrics)

    total_unresolved = (
        len(missing_itemid)
        + len(item_not_in_inventory)
    )

    summary = {

        "input_metrics": total_input,

        "scoped_metrics": total_scoped,

        "excluded_metrics": total_excluded,

        "unresolved_metrics": total_unresolved,

        "excluded_percentage": (
            round(
                total_excluded / total_input * 100,
                2
            )
            if total_input
            else 0
        ),

        "device_roles": dict(
            sorted(role_counter.items())
        ),

        "scoped_hosts": len(host_counter),

        "excluded_hosts": len(
            excluded_host_counter
        ),

        "metrics_without_itemid": len(
            missing_itemid
        ),

        "items_not_in_inventory": len(
            item_not_in_inventory
        ),
    }

    # --------------------------------------------------------
    # Output scoped metrics
    # --------------------------------------------------------

    output = {

        "version": "1.1",

        "source": INPUT_METRICS.name,

        "inventory_source": INPUT_INVENTORY.name,

        "scope_source": INPUT_SCOPE.name,

        "metrics": scoped_metrics,

        "summary": summary,
    }

    with OUTPUT_METRICS.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False
        )

        f.write("\n")

    # --------------------------------------------------------
    # Build audit
    # --------------------------------------------------------

    excluded_hosts = []

    for hostid, count in sorted(
        excluded_host_counter.items(),
        key=lambda x: int(x[0])
        if x[0].isdigit()
        else x[0]
    ):

        info = next(
            (
                host
                for host in inventory.get("hosts", [])
                if str(host["hostid"]) == hostid
            ),
            None
        )

        excluded_hosts.append({

            "hostid": hostid,

            "host": (
                info.get("host", "")
                if info
                else ""
            ),

            "name": (
                info.get("name", "")
                if info
                else ""
            ),

            "metric_count": count,
        })

    audit = {

        "version": "1.1",

        "input": INPUT_METRICS.name,

        "inventory": INPUT_INVENTORY.name,

        "scope": INPUT_SCOPE.name,

        "summary": summary,

        "excluded_hosts": excluded_hosts,

        "missing_itemid": missing_itemid,

        "items_not_in_inventory": [
            {
                "itemid": item["itemid"]
            }
            for item in item_not_in_inventory
        ],
    }

    with OUTPUT_AUDIT.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            audit,
            f,
            indent=2,
            ensure_ascii=False
        )

        f.write("\n")

    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print(
        f"Input metrics    : {total_input}"
    )

    print(
        f"Scoped metrics   : {total_scoped}"
    )

    print(
        f"Excluded metrics : {total_excluded}"
    )

    print(
        f"Unresolved       : {total_unresolved}"
    )

    print()

    print("Metrics by device role:")

    for role, count in sorted(
        role_counter.items()
    ):

        print(
            f"  {role:15s}: {count}"
        )

    print()

    print(
        f"Scoped hosts     : "
        f"{len(host_counter)}"
    )

    print(
        f"Excluded hosts   : "
        f"{len(excluded_host_counter)}"
    )

    print()

    if missing_itemid:

        print(
            f"WARNING: "
            f"{len(missing_itemid)} metrics "
            f"without itemid"
        )

    if item_not_in_inventory:

        print(
            f"WARNING: "
            f"{len(item_not_in_inventory)} items "
            f"not found in inventory"
        )

    print()

    print(
        f"Output           : "
        f"{OUTPUT_METRICS}"
    )

    print(
        f"Audit            : "
        f"{OUTPUT_AUDIT}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()