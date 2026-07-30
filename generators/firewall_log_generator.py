import random
from datetime import datetime, timedelta

internal_ips = ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
normal_ports = [80, 443, 22, 53]
scanner_ip = "198.51.100.99"

def generate_normal_line(timestamp):
    src = random.choice(internal_ips)
    port = random.choice(normal_ports)
    return f"{timestamp} firewall: ALLOW src={src} dst=10.0.0.1 dport={port} proto=TCP"

def generate_scan_line(timestamp, port):
    return f"{timestamp} firewall: DENY src={scanner_ip} dst=10.0.0.1 dport={port} proto=TCP"

def generate_logs(num_lines=80, filename="../data/firewall.log"):
    start_time = datetime.now()
    lines = []

    for i in range(num_lines):
        timestamp = (start_time + timedelta(seconds=i*2)).strftime("%b %d %H:%M:%S")
        lines.append(generate_normal_line(timestamp))

    # port scan: same IP hitting many different ports rapidly
    scan_start = start_time + timedelta(seconds=num_lines*2)
    scanned_ports = random.sample(range(1, 1024), 15)
    for i, port in enumerate(scanned_ports):
        timestamp = (scan_start + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
        lines.append(generate_scan_line(timestamp, port))

    with open(filename, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"Generated {len(lines)} firewall log lines in {filename}")
    print(f"Injected port scan from {scanner_ip}")

if __name__ == "__main__":
    generate_logs()
