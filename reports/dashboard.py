import sqlite3
from rich.console import Console
from rich.table import Table

def show_dashboard(db_path="../data/siem.db", alerts_path="../data/alerts.log"):
    console = Console()
    conn = sqlite3.connect(db_path)

    table = Table(title="Top Source IPs by Event Count")
    table.add_column("IP")
    table.add_column("Event Count")
    rows = conn.execute(
        "SELECT src_ip, COUNT(*) as cnt FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    for ip, cnt in rows:
        table.add_row(ip, str(cnt))
    console.print(table)

    console.print("\n[bold red]Alerts:[/bold red]")
    try:
        with open(alerts_path) as f:
            for line in f:
                console.print(line.strip())
    except FileNotFoundError:
        console.print("No alerts file found — run detectors/rules.py first.")

    conn.close()

if __name__ == "__main__":
    show_dashboard()
