import json

TARGETS = {
    "80514", "80515", "80517", "80518",
    "50113", "50114", "50116", "50117",
}

with open("zabbix_inventory.json", "r", encoding="utf-8") as f:
    inventory = json.load(f)

hosts = inventory["hosts"]

print(f"Hosts loaded: {len(hosts)}")
print()

found = []

for host in hosts:

    for metric in host.get("metrics", []):

        itemid = str(metric.get("itemid", ""))

        if itemid not in TARGETS:
            continue

        found.append({
            "itemid": itemid,
            "hostid": host.get("hostid"),
            "host": host.get("host"),
            "name": metric.get("name"),
            "key": metric.get("key"),
            "units": metric.get("units"),
            "value_type": metric.get("value_type"),
            "type": metric.get("type"),
            "delay": metric.get("delay"),
            "history": metric.get("history"),
            "trends": metric.get("trends"),
            "status": metric.get("status"),
            "state": metric.get("state"),
            "error": metric.get("error"),
            "snmp_oid": metric.get("snmp_oid"),
            "interfaceid": metric.get("interfaceid"),
            "templateid": metric.get("templateid"),
            "last_value": metric.get("last_value"),
            "last_clock": metric.get("last_clock"),
            "categories": metric.get("categories"),
        })

print("=" * 100)
print(f"Found: {len(found)} / {len(TARGETS)}")
print("=" * 100)

for item in found:

    print()
    print("=" * 100)
    print(f"ITEM {item['itemid']}")
    print("=" * 100)

    for key, value in item.items():
        if key != "itemid":
            print(f"{key:15s}: {value}")