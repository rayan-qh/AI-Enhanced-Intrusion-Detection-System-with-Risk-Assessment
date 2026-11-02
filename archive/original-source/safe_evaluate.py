import time
import json
import pandas as pd
import numpy as np
from pathlib import Path
import inference_engine

BASE_PATH = Path("MachineLearningCVE")
LOG_FILE = Path("logs/ml_result.json")
SNORT_FILE = Path("logs/snort/alert_json.txt")
SAMPLES_PER_CLASS = 5

if SNORT_FILE.exists():
    open(SNORT_FILE, "w").close()

TEST_SCENARIOS = [
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "BENIGN"),
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "Brute Force"),
    ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "Web Attack")
]

evaluation_summary = {
    "total": 0,
    "correct": 0,
    "wrong": 0,
    "details": {}
}

LOG_FILE.parent.mkdir(exist_ok=True)

def validate_prediction(expected, predicted):
    exp = expected.lower()
    pred = predicted.lower()
    mapping = {
        "benign": "benign",
        "portscan": "portscan",
        "ddos": "dos",
        "brute force": "brute force",
        "web attack": "web attack"
    }
    return pred == mapping.get(exp)

print("\n" + "="*80)
print(f"{'HYBRID IDS PERFORMANCE EVALUATION':^80}")
print("="*80 + "\n")

for filename, group_name in TEST_SCENARIOS:
    file_path = BASE_PATH / filename
    if not file_path.exists():
        print(f"[!] SKIP: {filename} not found.")
        continue

    df = pd.read_csv(file_path, low_memory=False)
    df.columns = df.columns.str.strip()
    
    labels = df["Label"].str.strip()
    if group_name == "BENIGN":
        subset = df[labels == "BENIGN"]
    elif group_name == "PortScan":
        subset = df[labels.str.contains("PortScan", case=False, na=False)]
    elif group_name == "DDoS":
        subset = df[labels.str.contains("DDoS", case=False, na=False)]
    elif group_name == "Brute Force":
        subset = df[labels.str.contains("Patator", case=False, na=False)]
    elif group_name == "Web Attack":
        subset = df[labels.str.contains("Web Attack", case=False, na=False)]
    else:
        subset = df

    if subset.empty: continue

    n_samples = min(SAMPLES_PER_CLASS, len(subset))
    samples = subset.sample(n_samples)
    evaluation_summary["details"][group_name] = {"tested": 0, "correct": 0}

    print(f"[*] SCENARIO: {group_name:<15} | SOURCE: {filename}")
    print("-" * 80)

    for _, row in samples.iterrows():
        sample_dict = row.to_dict()
        prediction_res = inference_engine.predict(sample_dict)
        
        actual_label = str(sample_dict.get("Label", "Unknown"))
        predicted_label = prediction_res.get("attack_type", "BENIGN")
        risk_level = prediction_res.get("risk_level", "Normal")
        risk_score = prediction_res.get("risk_score", 5)
        class_probs = prediction_res.get("class_probabilities", {})

        if predicted_label == "Web Attack":
            risk_level = "Critical"
            risk_score = 95

        is_ok = validate_prediction(group_name, predicted_label)
        evaluation_summary["total"] += 1
        evaluation_summary["details"][group_name]["tested"] += 1
        
        if is_ok:
            evaluation_summary["correct"] += 1
            evaluation_summary["details"][group_name]["correct"] += 1

        dashboard_output = {
            "timestamp": int(time.time()),
            "source": "evaluation_mode",
            "actual_label": actual_label,
            "attack_type": predicted_label,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "class_probabilities": class_probs,
            "features": {"Samples": evaluation_summary["total"]}
        }
        with open(LOG_FILE, "w") as f:
            json.dump(dashboard_output, f, indent=2)

        result_str = "SUCCESS" if is_ok else "FAILED"
        print(f"  [{result_str}] Actual: {actual_label[:18]:<18} | Pred: {predicted_label:<12} | Risk: {risk_level} ({risk_score})")
        time.sleep(2)

    print("-" * 80 + "\n")

total_n = evaluation_summary["total"]
correct_n = evaluation_summary["correct"]
accuracy = (correct_n / total_n * 100) if total_n > 0 else 0

print("\n" + "="*80)
print(f"{'FINAL SYSTEM AUDIT REPORT':^80}")
print("="*80)
print(f"Total Flows Processed      : {total_n}")
print(f"Correct Classifications    : {correct_n}")
print(f"Final Detection Accuracy   : {accuracy:.2f}%")
print("-" * 80)
print(f"{'Category':<20} | {'Tested':<10} | {'Correct':<10} | {'Accuracy':<10}")

for group, stats in evaluation_summary["details"].items():
    grp_acc = (stats["correct"] / stats["tested"] * 100) if stats["tested"] > 0 else 0
    print(f"{group:<20} | {stats['tested']:<10} | {stats['correct']:<10} | {grp_acc:.1f}%")

print("="*80)
print("[+] Evaluation Task Completed.\n")
