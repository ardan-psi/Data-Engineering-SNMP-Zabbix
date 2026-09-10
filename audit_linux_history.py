import json
import os
import time
import requests
from collections import defaultdict
from datetime import datetime, timedelta, timezone


ZABBIX_URL = "http://192.168.3.10/api_jsonrpc.php"

ZABBIX_TOKEN = os.environ["ZABBIX_TOKEN"]

TARGETS = [
    "80514",
    "80515",
    "80517",
    "80518",
    "50113",
    "50114",
    "50116",
    "50117",
]

# 7 hari
TIME_WINDOW_DAYS = 7


def zabbix_api(method, params, request_id=1):

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": request_id,
    }

    headers = {
        "Content-Type": "application/json-rpc",
        "Authorization": f"Bearer {ZABBIX_TOKEN}",
    }

    response = requests.post(
        ZABBIX_URL,
        json=payload,
        headers=headers,
        timeout=30,
    )

    response.raise_for_status()

    data = response.json()

    if "error" in data:
        raise RuntimeError(data["error"])

    return data["result"]


now = int(time.time())
time_from = int(
    (
        datetime.now(timezone.utc)
        - timedelta(days=TIME_WINDOW_DAYS)
    ).timestamp()
)

print("=" * 100)
print("ZABBIX LINUX INTERFACE HISTORY AUDIT")
print("=" * 100)

print("From:", datetime.fromtimestamp(time_from, timezone.utc))
print("To  :", datetime.fromtimestamp(now, timezone.utc))
print()


result = zabbix_api(
    "history.get",
    {
        "output": [
            "itemid",
            "clock",
            "value",
        ],
        "history": 3,
        "itemids": TARGETS,
        "time_from": time_from,
        "time_till": now,
        "sortfield": "clock",
        "sortorder": "ASC",
        "limit": 100000,
    },
)

print(f"Total records: {len(result)}")
print()


history = defaultdict(list)

for r in result:
    history[str(r["itemid"])].append(r)


for itemid in TARGETS:

    records = history[itemid]

    print("=" * 100)
    print(f"ITEM {itemid}")
    print(f"SAMPLES: {len(records)}")
    print("=" * 100)

    if not records:
        print("NO HISTORY IN ZABBIX")
        print()
        continue

    values = [int(r["value"]) for r in records]

    increases = 0
    decreases = 0
    unchanged = 0

    for previous, current in zip(values, values[1:]):

        if current > previous:
            increases += 1

        elif current < previous:
            decreases += 1

        else:
            unchanged += 1

    print(f"FIRST VALUE : {values[0]}")
    print(f"LAST VALUE  : {values[-1]}")
    print(f"MIN VALUE   : {min(values)}")
    print(f"MAX VALUE   : {max(values)}")
    print(f"INCREASES   : {increases}")
    print(f"DECREASES   : {decreases}")
    print(f"UNCHANGED   : {unchanged}")

    print("\nFIRST 10:")

    for r in records[:10]:
        ts = datetime.fromtimestamp(
            int(r["clock"]),
            timezone.utc,
        )

        print(
            ts.isoformat(),
            r["value"],
        )

    print("\nLAST 10:")

    for r in records[-10:]:
        ts = datetime.fromtimestamp(
            int(r["clock"]),
            timezone.utc,
        )

        print(
            ts.isoformat(),
            r["value"],
        )

    print()