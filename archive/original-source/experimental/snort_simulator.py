import json
import time
import os
import random

SNORT_DIR = "logs/snort"
SNORT_FILE = f"{SNORT_DIR}/alert_fast.txt"
os.makedirs(SNORT_DIR, exist_ok=True)

alerts = [
    {"msg": "TCP Port Scan Detected", "rule": "1:1000002:1", "src_addr": "192.168.1.15", "dst_addr": "10.0.0.5"},
    {"msg": "Possible DoS Attack (SYN Flood)", "rule": "1:1000003:1", "src_addr": "172.16.0.8", "dst_addr": "10.0.0.5"},
    {"msg": "SSH Brute Force Attempt", "rule": "1:1000004:1", "src_addr": "192.168.1.50", "dst_addr": "10.0.0.5"},
    {"msg": "Critical Web Attack (SQLi)", "rule": "1:1000006:1", "src_addr": "11.22.33.44", "dst_addr": "10.0.0.5"},
]

print("🛡️ Starting Snort Simulator for Demo...")
print("Sending alerts to interact with the Hybrid IDS...\n")

try:
    while True:
        alert = random.choice(alerts)

        with open(SNORT_FILE, "a") as f:
            fast_alert = f'[**] [{alert["rule"]}] "{alert["msg"]}" [**] {alert["src_addr"]} -> {alert["dst_addr"]}\n'
            f.write(fast_alert)

        print(f" 🚨 Snort Rule Triggered [SID: {alert['rule'].split(':')[1]}] - {alert['msg']}")

        time.sleep(10)

except KeyboardInterrupt:
    print("\n🛑 Snort Simulator stopped manually.")
