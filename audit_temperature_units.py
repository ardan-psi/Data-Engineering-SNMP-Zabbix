import json

INVENTORY_FILE = "zabbix_inventory.json"

with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
    inventory = json.load(f)

hosts = inventory.get("hosts", [])

targets = []

for host in hosts:
    hostid = host.get("hostid")
    hostname = host.get("host")
    host_name = host.get("name")

    for metric in host.get("metrics", []):
        units = str(metric.get("units", "")).strip()

        if units.lower() == "!°c":
            targets.append({
                "itemid": metric.get("itemid"),
                "hostid": hostid,
                "host": hostname,
                "host_name": host_name,
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
                "last_value": metric.get("last_value"),
                "last_clock": metric.get("last_clock"),
                "snmp_oid": metric.get("snmp_oid"),
                "interfaceid": metric.get("interfaceid"),
                "templateid": metric.get("templateid"),
            })

print(f"Found {len(targets)} temperature metrics with units !°C\n")

for i, item in enumerate(targets, 1):
    print("=" * 80)
    print(f"[{i}]")
    for key, value in item.items():
        print(f"{key:15s}: {value}")