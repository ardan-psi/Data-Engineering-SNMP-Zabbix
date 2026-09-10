import json
from collections import defaultdict

TARGETS = {
    "80514", "80515", "80517", "80518",
    "50113", "50114", "50116", "50117",
}

data = defaultdict(list)

with open("raw_history.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)

        itemid = str(r.get("itemid"))

        if itemid in TARGETS:
            data[itemid].append(r)

for itemid in sorted(TARGETS):
    records = sorted(data[itemid], key=lambda x: x["clock"])

    print("=" * 100)
    print("ITEM:", itemid)
    print("RECORDS:", len(records))

    if not records:
        print("NO HISTORY")
        continue

    values = [float(r["value"]) for r in records]

    print("FIRST 10:")
    for r in records[:10]:
        print(
            r["clock"],
            r["value"]
        )

    print("\nLAST 10:")
    for r in records[-10:]:
        print(
            r["clock"],
            r["value"]
        )

    decreases = 0
    increases = 0
    unchanged = 0

    previous = None

    for value in values:
        if previous is not None:
            if value > previous:
                increases += 1
            elif value < previous:
                decreases += 1
            else:
                unchanged += 1

        previous = value

    print("\nVALUE BEHAVIOR")
    print("increases :", increases)
    print("decreases :", decreases)
    print("unchanged :", unchanged)