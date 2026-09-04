import json
import re

FIELDS = [
    "date", "time", "action", "protocol", "src_ip", "dst_ip",
    "src_port", "dst_port", "size", "tcpflags", "tcpsyn",
    "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path"
]

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

def parse_log(filepath):
    events = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.replace("\x00", "").strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) != len(FIELDS):
                continue
            if not DATE_RE.match(parts[0]):
                continue  # skip anything that isn't a real date, e.g. padding artifacts

            row = dict(zip(FIELDS, parts))

            events.append({
                "timestamp": f"{row['date']} {row['time']}",
                "source_ip": row["src_ip"],
                "dest_ip": row["dst_ip"],
                "dest_port": row["dst_port"],
                "protocol": row["protocol"],
                "action": row["action"],
                "direction": row["path"],
                "log_source": "windows_firewall",
            })
    return events

if __name__ == "__main__":
    events = parse_log("../data/pfirewall.log")
    print(f"Parsed {len(events)} events")
    with open("../data/firewall_parsed.jsonl", "w") as out:
        for e in events:
            out.write(json.dumps(e) + "\n")
