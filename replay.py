import json
import re
import pandas as pd
from datetime import datetime, timedelta


patterns = {
    'pcap': re.compile(
        r'''
        \[(?P<time>\d{2}:\d{2}:\d{2})]\s+
        replaying\s+\./(?P<file>.*)
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'actual': re.compile(
        r'''
        Actual:\s+(?P<packets>\d+)\s+packets\s+
        \((?P<bytes>\d+)\s+bytes\)\s+
        sent\s+in\s+(?P<duration>\d+\.\d+)\s+seconds
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'rated': re.compile(
        r'''
        Rated:\s+(?P<bps>\d+\.\d+)\s+Bps,\s+
        (?P<mbps>\d+\.\d+)\s+Mbps,\s+
        (?P<pps>\d+\.\d+)\s+pps
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'flows': re.compile(
        r'''
        Flows:\s+(?P<flows>\d+)\s+flows,\s+
        (?P<fps>\d+\.\d+)\s+fps,\s+
        (?P<flow_packets>\d+)\s+flow\s+packets,\s+
        (?P<non_flow_packets>\d+)\s+non-flow
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'packets_successful': re.compile(
        r'''
        Successful\s+packets:\s+(?P<packets_successful>\d+)
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'packets_failed': re.compile(
        r'''
        Failed\s+packets:\s+(?P<packets_failed>\d+)
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'packets_truncated': re.compile(
        r'''
        Truncated\s+packets:\s+(?P<packets_truncated>\d+)
        ''', re.VERBOSE | re.IGNORECASE
    ),
    'packets_retried_enobufs': re.compile(
        r'''
        Retried\s+packets\s+\(ENOBUFS\):\s+(?P<packets_retried_enobufs>\d+)
    ''', re.VERBOSE | re.IGNORECASE
    ),
    'packets_retried_eagain': re.compile(
        r'''
        Retried\s+packets\s+\(EAGAIN\):\s+(?P<packets_retried_eagain>\d+)
        ''', re.VERBOSE | re.IGNORECASE
    ),
}


def normalize_tcpreplay_data(data: dict) -> pd.DataFrame:
    """
    Normalize parsed tcpreplay log data into a typed DataFrame.
    One row per pcap, numeric fields converted, replay order added.
    """

    rows = []

    for order, (pcap, metrics) in enumerate(data.items(), start=1):
        row = {
            "order": order,
            "pcap": pcap.strip(),
            "time": metrics.get("time"),
        }

        # Numeric fields to convert
        numeric_fields = [
            "packets",
            "bytes",
            "duration",
            "bps",
            "mbps",
            "pps",
            "flows",
            "fps",
            "flow_packets",
            "non_flow_packets",
            "packets_successful",
            "packets_failed",
            "packets_truncated",
            "packets_retried_enobufs",
            "packets_retried_eagain",
        ]

        for field in numeric_fields:
            value = metrics.get(field)
            row[field] = float(value) if value is not None else None

        rows.append(row)

    df = pd.DataFrame(rows)

    # Optional: enforce dtypes explicitly
    df = df.convert_dtypes()

    return df


results = {}
key = None
rows = 0

with open('data/replay.log', 'r', encoding='utf-8', errors='ignore') as f:
    for line_num, line in enumerate(f, start=1):
        line = line.strip()
        if not line:
            continue
        for line_type in patterns.keys():
            m = patterns[line_type].search(line)
            if m:
                # print(line_type)
                val_dict = m.groupdict()
                if 'file' in val_dict:
                    key = val_dict['file']
                    rows += 1
                if key in results:
                    results[key].update(val_dict)
                else:
                    results[key] = val_dict
                break

start_date="2026-02-21"
current_date = datetime.strptime(start_date, "%Y-%m-%d").date()
last_time = None

pcap_skipped = []
rows = []

for pcap in results.keys():
    if 'packets' not in results[pcap]:
        pcap_skipped.append(pcap)
        continue
    results[pcap]['order'] = int(results[pcap]['file'][0:4])
    time_start = datetime.strptime(results[pcap]['time'], "%H:%M:%S").time()
    if last_time and time_start < last_time:  # detect midnight rollover
        current_date += timedelta(days=1)
    results[pcap]['date_time'] = datetime.combine(current_date, time_start).strftime("%Y-%m-%d %H:%M:%S")
    last_time = time_start
    rows.append(results[pcap])

for pcap in pcap_skipped:
    del results[pcap]

with open('data/replay.json', 'w', encoding='utf-8', errors='ignore') as f:
    json.dump(results, f, indent=2)

# print(json.dumps(results, indent=2))

print(f"results contains {len(results)} entries")

df = pd.DataFrame(rows)

# Save the DataFrame to CSV
csv_file = "data/replay.csv"
df.to_csv(csv_file, index=False)  # index=False avoids writing the row numbers
print(f"Saved {len(df)} rows to {csv_file}")
