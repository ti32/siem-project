import sqlite3
from collections import defaultdict

def brute_force_rule(conn, threshold=3):
    alerts = []
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) FROM events WHERE source='ssh' AND status='Failed' GROUP BY src_ip"
    ).fetchall()
    for ip, count in rows:
        if count >= threshold:
            alerts.append(f"[HIGH] Brute-force suspected from {ip}: {count} failed SSH logins")
    return alerts

def web_attack_rule(conn):
    alerts = []
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) FROM events WHERE event_type='web_attack' GROUP BY src_ip"
    ).fetchall()
    for ip, count in rows:
        alerts.append(f"[HIGH] Web attack pattern from {ip}: {count} malicious requests")
    return alerts

def port_scan_rule(conn, threshold=10):
    alerts = []
    rows = conn.execute(
        "SELECT src_ip, COUNT(DISTINCT event_type) FROM events WHERE source='firewall' AND status='DENY' GROUP BY src_ip"
    ).fetchall()
    for ip, distinct_ports in rows:
        if distinct_ports >= threshold:
            alerts.append(f"[MEDIUM] Port scan suspected from {ip}: {distinct_ports} distinct ports probed")
    return alerts

def run_all_rules(db_path="../data/siem.db", output="../data/alerts.log"):
    conn = sqlite3.connect(db_path)
    all_alerts = brute_force_rule(conn) + web_attack_rule(conn) + port_scan_rule(conn)
    with open(output, "w") as f:
        for a in all_alerts:
            f.write(a + "\n")
    conn.close()
    print(f"Generated {len(all_alerts)} alerts in {output}")
    for a in all_alerts:
        print(a)

if __name__ == "__main__":
    run_all_rules()
