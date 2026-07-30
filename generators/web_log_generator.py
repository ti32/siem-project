import random
from datetime import datetime, timedelta

normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
paths = ["/index.html", "/about", "/products", "/login", "/contact", "/cart"]
attacker_ips = ["203.0.113.7"]
attack_paths = [
    "/login?user=admin'--",
    "/search?q=<script>alert(1)</script>",
    "/product?id=1 OR 1=1",
    "/admin' OR '1'='1",
]

def generate_normal_line(timestamp):
    ip = random.choice(normal_ips)
    path = random.choice(paths)
    status = random.choice([200, 200, 200, 200, 404])
    return f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" {status} 512'

def generate_attack_line(timestamp, ip):
    path = random.choice(attack_paths)
    return f'{ip} - - [{timestamp}] "GET {path} HTTP/1.1" 403 128'

def generate_logs(num_lines=100, filename="../data/web.log"):
    start_time = datetime.now()
    lines = []
    for i in range(num_lines):
        timestamp = (start_time + timedelta(seconds=i*2)).strftime("%d/%b/%Y:%H:%M:%S")
        lines.append(generate_normal_line(timestamp))

    attacker_ip = random.choice(attacker_ips)
    attack_start = start_time + timedelta(seconds=num_lines*2)
    for i in range(6):
        timestamp = (attack_start + timedelta(seconds=i*2)).strftime("%d/%b/%Y:%H:%M:%S")
        lines.append(generate_attack_line(timestamp, attacker_ip))

    with open(filename, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"Generated {len(lines)} web log lines in {filename}")
    print(f"Injected attack burst from {attacker_ip}")

if __name__ == "__main__":
    generate_logs()

