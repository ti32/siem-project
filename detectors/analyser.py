from collections import defaultdict

def analyze_logs(filename="sample.log", threshold=3):
    failed_attempts = defaultdict(int)

    with open(filename, "r") as f:
        for line in f:
            if "Failed password" in line:
                # extract the IP - it's the word after "from"
                parts = line.split()
                ip_index = parts.index("from") + 1
                ip = parts[ip_index]
                failed_attempts[ip] += 1

    print("=== Failed Login Summary ===")
    for ip, count in failed_attempts.items():
        flag = "  <-- SUSPICIOUS" if count >= threshold else ""
        print(f"{ip}: {count} failed attempts{flag}")

if __name__ == "__main__":
    analyze_logs()
