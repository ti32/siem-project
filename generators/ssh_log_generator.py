import random
from datetime import datetime, timedelta

# Normal users - mostly successful logins, occasional typo/failed attempt
normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
normal_users = ["alice", "bob", "carol", "dave", "erin"]

# Attacker IPs - repeated failed attempts, trying common usernames
attacker_ips = ["203.0.113.7", "198.51.100.23"]
attacker_users = ["root", "admin", "test", "user", "administrator"]

def generate_normal_line(timestamp):
    ip = random.choice(normal_ips)
    user = random.choice(normal_users)
    # 90% success, 10% honest typo/failed attempt
    status = "Accepted" if random.random() < 0.9 else "Failed"
    return f"{timestamp} sshd[1234]: {status} password for {user} from {ip} port 54321 ssh2"

def generate_attack_line(timestamp, ip):
    user = random.choice(attacker_users)
    # attackers almost always fail
    status = "Failed" if random.random() < 0.95 else "Accepted"
    return f"{timestamp} sshd[1234]: {status} password for {user} from {ip} port 54321 ssh2"

def generate_logs(num_lines=100, filename="../data/sample.log"):
    start_time = datetime.now()
    lines = []

    for i in range(num_lines):
        timestamp = (start_time + timedelta(seconds=i*2)).strftime("%b %d %H:%M:%S")
        lines.append(generate_normal_line(timestamp))

    # inject a burst of attack traffic from one attacker IP, close together in time
    attacker_ip = random.choice(attacker_ips)
    attack_start = start_time + timedelta(seconds=num_lines*2)
    for i in range(8):
        timestamp = (attack_start + timedelta(seconds=i*2)).strftime("%b %d %H:%M:%S")
        lines.append(generate_attack_line(timestamp, attacker_ip))

    with open(filename, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"Generated {len(lines)} log lines in {filename}")
    print(f"Injected attack burst from {attacker_ip}")

if __name__ == "__main__":
    generate_logs()
