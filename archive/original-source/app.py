import re
import os
import time
import json
from flask import Flask, render_template, jsonify
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
ML_FILE = BASE_DIR / "logs" / "ml_result.json"
SNORT_FILE = BASE_DIR / "logs" / "snort" / "alert_fast.txt"

history = [5, 5, 5, 5, 5]
IDLE_TIMEOUT_SEC = 10

def read_ml_result():
    if not ML_FILE.exists(): return None
    try:
        with open(ML_FILE, "r", errors="ignore") as f:
            return json.load(f)
    except: return None


def parse_snort_fast_line(line):
    try:
        msg_match = re.search(r'\"(.*?)\"', line)
        msg = msg_match.group(1) if msg_match else "-"
        
        sid_match = re.search(r'\[\d+:(\d+):\d+\]', line)
        sid = sid_match.group(1) if sid_match else "0"
        
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
        src = ips[0] if len(ips) > 0 else "-"
        dst = ips[1] if len(ips) > 1 else "-"
        
        return {
            "msg": msg,
            "rule": f"1:{sid}:1",
            "src_addr": src,
            "dst_addr": dst
        }
    except:
        return None



def read_latest_snort_alert():
    if not SNORT_FILE.exists(): return None
    try:
        with open(SNORT_FILE, "r", errors="ignore") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        if not lines: return None
        return parse_snort_fast_line(lines[-1])
    except: return None
def build_status():
    ml = read_ml_result()
    snort = read_latest_snort_alert()
    
    current_time = int(time.time())
    
    ml_active = False
    if ml and "timestamp" in ml:
        if (current_time - ml["timestamp"]) <= IDLE_TIMEOUT_SEC:
            ml_active = True

    snort_active = False
    if snort and SNORT_FILE.exists():
        if (current_time - os.path.getmtime(SNORT_FILE)) <= IDLE_TIMEOUT_SEC:
            snort_active = True

    if ml_active:
        attack_type = ml.get("attack_type", "BENIGN")
        risk_level = ml.get("risk_level", "Normal")
        risk_score = float(ml.get("risk_score", 5))
        class_probs = ml.get("class_probabilities", {})
        ml_features = ml.get("features", {})
        ml_source = ml.get("source", "ml_engine")
    else:
        attack_type, risk_level, risk_score = "BENIGN", "Normal", 5.0
        class_probs, ml_features = {}, {}
        ml_source = "system_idle"

    src_addr, dst_addr, sid, snort_msg = "-", "-", 0, "-"

    if snort_active:
        src_addr = snort.get("src_addr", snort.get("src_ap", "-"))
        dst_addr = snort.get("dst_addr", snort.get("dst_ap", "-"))
        snort_msg = snort.get("msg", "-")
        rule = str(snort.get("rule", "0:0:0"))
        parts = rule.split(":")
        if len(parts) >= 2:
            try: sid = int(parts[1])
            except: sid = 0

        snort_map = {
            1000001: ("BENIGN", "Normal", 5),
            1000002: ("PortScan", "Low", 25),
            1000003: ("Brute Force", "Medium", 50),
            1000004: ("DoS Attack", "High", 75),
            1000005: ("Web Attack", "Critical", 95)

        }

        if sid in snort_map:
            attack_type, risk_level, risk_score = snort_map[sid]
            ml_source = "snort_live_engine"
            class_probs, ml_features = {}, {}

    history.append(risk_score)
    if len(history) > 20: history.pop(0)

    probability = max(class_probs.values()) if class_probs else 1.0
    if not ml_active and not snort_active:
        probability = 0.99
        
    confidence = round(probability * 100, 2)

    events = [
        {"time": datetime.now().strftime("%H:%M:%S"), "title_en": f"Classified: {attack_type}", "level": risk_level},
        {"time": datetime.now().strftime("%H:%M:%S"), "title_en": f"Source: {ml_source}", "level": risk_level}
    ]
    
    if snort_active:
        events.append({"time": datetime.now().strftime("%H:%M:%S"), "title_en": f"Snort: {snort_msg}", "level": risk_level})

    return {
        "system_name_en": "Smart Threat Classifier",
        "attack_type": attack_type,
        "probability": round(probability, 4),
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "alerts_count": 0 if risk_level == "Normal" else 1,
        "avg_risk": round(sum(history[-6:]) / len(history[-6:]), 2),
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "history": history,
        "events": events,
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "sid": sid,
        "snort_msg": snort_msg,
        "ml_source": ml_source,
        "ml_features": ml_features,
        "snort_evidence": snort if snort_active else {}
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    return jsonify(build_status())

if __name__ == "__main__":
    (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "logs" / "snort").mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
