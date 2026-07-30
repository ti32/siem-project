import sqlite3
import json

def load_events(jsonl_path="../data/events.jsonl", db_path="../data/siem.db"):
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS events (
        timestamp TEXT, source TEXT, src_ip TEXT,
        event_type TEXT, user TEXT, status TEXT)""")
    conn.execute("DELETE FROM events")  # reset on each load for simplicity

    with open(jsonl_path) as f:
        for line in f:
            e = json.loads(line)
            conn.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (e["timestamp"], e["source"], e["src_ip"], e["event_type"], e["user"], e["status"])
            )
    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Loaded {count} events into {db_path}")
    conn.close()

if __name__ == "__main__":
    load_events()
