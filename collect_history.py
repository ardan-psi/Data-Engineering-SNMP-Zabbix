import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import requests


ZABBIX_URL = os.getenv(
    "ZABBIX_URL",
    "http://192.168.3.10/api_jsonrpc.php",
)

ZABBIX_TOKEN = os.getenv("ZABBIX_TOKEN")

INPUT_FILE = "scoped_metrics.json"
OUTPUT_FILE = "raw_history.jsonl"

# POC: ambil 1 jam terakhir
HOURS = 1

# Jangan terlalu besar agar response API tidak terlalu berat
BATCH_SIZE = 100

TIMEOUT = 60


if not ZABBIX_TOKEN:
    raise RuntimeError("ZABBIX_TOKEN environment variable belum diset")


class ZabbixAPI:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.request_id = 0
        self.session = requests.Session()

    def call(self, method, params):
        self.request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id,
        }

        headers = {
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {self.token}",
        }

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
                f"Zabbix API error: "
                f'{error.get("code")} - '
                f'{error.get("message")} - '
                f'{error.get("data")}'
            )

        return data["result"]


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def load_metrics():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    metrics = data["metrics"]

    print(f"Loaded metrics: {len(metrics)}")

    return metrics


def classify_history_type(metric):
    """
    Zabbix value_type:
      0 = float
      1 = character
      2 = log
      3 = unsigned integer
      4 = text

    Untuk AI-NOC kita hanya mengambil numeric:
      float (0)
      uint (3)
    """

    value_type = str(metric.get("value_type"))

    if value_type == "0":
        return 0

    if value_type == "3":
        return 3

    return None


def main():
    metrics = load_metrics()

    api = ZabbixAPI(
        ZABBIX_URL,
        ZABBIX_TOKEN,
    )

    now = int(time.time())

    start = int(
        (
            datetime.now(timezone.utc)
            - timedelta(hours=HOURS)
        ).timestamp()
    )

    print(
        f"History window: "
        f"{datetime.fromtimestamp(start, timezone.utc)} "
        f"-> "
        f"{datetime.fromtimestamp(now, timezone.utc)}"
    )

    # Pisahkan berdasarkan Zabbix history type.
    #
    # history.get membutuhkan type yang sama.
    grouped = defaultdict(list)

    metadata = {}

    for metric in metrics:
        itemid = str(metric["itemid"])

        history_type = classify_history_type(metric)

        if history_type is None:
            continue

        grouped[history_type].append(itemid)
        metadata[itemid] = metric

    print()
    print("Numeric items:")

    for history_type, itemids in grouped.items():
        print(
            f"  history type {history_type}: "
            f"{len(itemids)}"
        )

    total_records = 0

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as output:

        for history_type, itemids in grouped.items():

            print()
            print(
                f"Collecting history type "
                f"{history_type}..."
            )

            for batch_no, batch in enumerate(
                chunks(itemids, BATCH_SIZE),
                start=1,
            ):

                result = api.call(
                    "history.get",
                    {
                        "output": [
                            "itemid",
                            "clock",
                            "value",
                        ],
                        "history": history_type,
                        "itemids": batch,
                        "time_from": start,
                        "time_till": now,
                        "sortfield": "clock",
                        "sortorder": "ASC",
                        "limit": 100000,
                    },
                )

                for point in result:
                    itemid = str(point["itemid"])
                    metric = metadata[itemid]

                    record = {
                        "timestamp": datetime.fromtimestamp(
                            int(point["clock"]),
                            timezone.utc,
                        ).isoformat(),
                        "clock": int(point["clock"]),
                        "itemid": itemid,
                        "hostid": metric["hostid"],
                        "host": metric.get("host"),
                        "host_name": metric.get("host_name"),
                        "device_role": metric["device_role"],
                        "canonical_metric": metric[
                            "canonical_metric"
                        ],
                        "semantic_type": metric[
                            "semantic_type"
                        ],
                        "transformation": metric[
                            "transformation"
                        ],
                        "value": float(point["value"]),
                    }

                    output.write(
                        json.dumps(
                            record,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    total_records += 1

                print(
                    f"  batch {batch_no}: "
                    f"{len(result)} records"
                )

    print()
    print("=" * 60)
    print("DONE")
    print("=" * 60)
    print(f"Total records : {total_records}")
    print(f"Output        : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()