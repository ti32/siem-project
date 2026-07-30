import re
import json

def parse_ssh(filepath="../data/sample.log"):
    events = []
    pattern = re.compile(r"^(\w+ \d+ \d+:\d+:\d+) sshd\[\d+\]: (\w+) password for (\w+) from ([\d.]+)")
    with open(filepath) as f:
        for line in f:
            m = pattern.match(line)
            if m:
                ts, status, user, ip = m.groups()
                events.append({
                    "timestamp": ts, "source": "ssh", "src_ip": ip,
                    "event_type": "auth", "user": user, "status": status
                })
    return events

def parse_web(filepath="../data/web.log"):
    events = []
    pattern = re.compile(r'^([\d.]+) - - \[(.*?)\] "GET (.*?) HTTP.*?" (\d+)')
    attack_markers = ["<script>", "OR 1=1", "'--", "'1'='1"]
    with open(filepath) as f:
        for line in f:
            m = pattern.match(line)
            if m:
                ip, ts, path, status = m.groups()
                is_attack = any(marker in path for marker in attack_markers)
                events.append({
                    "timestamp": ts, "source": "web", "src_ip": ip,
                    "event_type": "web_attack" if is_attack else "web_request",
                    "user": None, "status": status
                })
    return events

def parse_firewall(filepath="../data/firewall.log"):
    events = []
    pattern = re.compile(r"^(\w+ \d+ \d+:\d+:\d+) firewall: (\w+) src=([\d.]+) dst=[\d.]+ dport=(\d+)")
    with open(filepath) as f:
        for line in f:
            m = pattern.match(line)
            if m:
                ts, action, ip, port = m.groups()
                events.append({
                    "timestamp": ts, "source": "firewall", "src_ip": ip,
                    "event_type": f"port_{port}", "user": None, "status": action
                })
    return events

def normalize_all(output="../data/events.jsonl"):
    all_events = parse_ssh() + parse_web() + parse_firewall()
    with open(output, "w") as f:
        for e in all_events:
            f.write(json.dumps(e) + "\n")
    print(f"Normalized {len(all_events)} events into {output}")

if __name__ == "__main__":
    normalize_all()
