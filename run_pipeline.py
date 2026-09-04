import subprocess

steps = [
    (["python3", "ssh_log_generator.py"], "generators"),
    (["python3", "web_log_generator.py"], "generators"),
    (["python3", "firewall_log_generator.py"], "generators"),
    (["python3", "firewall_win_parser.py"], "parsers"),
    (["python3", "normalize.py"], "parsers"),
    (["python3", "load_to_db.py"], "parsers"),
    (["python3", "rules.py"], "detectors"),
    (["python3", "dashboard.py"], "reports"),
]

for cmd, folder in steps:
    print(f"\n--- Running {' '.join(cmd)} (in {folder}/) ---")
    subprocess.run(cmd, cwd=folder, check=True)
