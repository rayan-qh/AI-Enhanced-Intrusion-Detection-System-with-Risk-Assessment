import json
import joblib
import numpy as np
import pandas as pd

# Load required models and artifacts
model = joblib.load("model_multiclass.pkl")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Load feature structure
with open("feature_columns.json", "r") as f:
    feature_columns = json.load(f)

# Risk Intelligence Map
risk_map = {
    "BENIGN": (5, "Normal"),
    "PortScan": (25, "Low"),
    "Brute Force": (50, "Medium"),
    "DoS": (75, "High"),
    "Web Attack": (95, "Critical")
}

def predict(features_dict):
    # Prepare data row
    row = {col: features_dict.get(col, 0) for col in feature_columns}
    X = pd.DataFrame([row], columns=feature_columns)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Scale features
    X_scaled = scaler.transform(X.values)

    # Core Prediction
    pred_class = model.predict(X_scaled)[0]
    attack_type = label_encoder.inverse_transform([pred_class])[0]

    # Confidence Score
    probabilities = model.predict_proba(X_scaled)[0]
    confidence = max(probabilities)

    # Risk Logic Layer
    risk_score, risk_level = risk_map.get(attack_type, (0, "Unknown"))

    # Security Overrides (Criticality Logic)
    if attack_type == "Web Attack":
        risk_score = 95
        risk_level = "Critical"
    elif confidence < 0.6:
        # High uncertainty triggers high risk mode
        risk_score = 95
        risk_level = "Critical"

    # Export probabilities for UI charts
    class_probabilities = {
        label_encoder.inverse_transform([i])[0]: float(probabilities[i])
        for i in range(len(probabilities))
    }

    return {
        "attack_type": attack_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "class_probabilities": class_probabilities
    }

if __name__ == "__main__":
    # Test sample for validation
    sample = {}
    result = predict(sample)
    print(result)
