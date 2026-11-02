"""Strict inference contract for locally supplied, trusted model artifacts."""
import json
import os
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np

RISK = {'BENIGN': (5, 'طبيعي'), 'PortScan': (25, 'منخفض'),
        'Brute Force': (50, 'متوسط'), 'DoS': (75, 'مرتفع'),
        'Web Attack': (95, 'حرج')}


class Predictor:
    def __init__(self, directory):
        directory = Path(directory)
        self.features = json.loads((directory / 'feature_columns.json').read_text())
        self.model = joblib.load(directory / 'model_multiclass.pkl')
        self.scaler = joblib.load(directory / 'scaler.pkl')
        self.encoder = joblib.load(directory / 'label_encoder.pkl')
        if len(self.features) != len(set(self.features)):
            raise ValueError('Duplicate feature names')
        if self.model.n_features_in_ != len(self.features) or self.scaler.n_features_in_ != len(self.features):
            raise ValueError('Artifact feature mismatch')
        self.labels = self.encoder.inverse_transform(self.model.classes_.astype(int))

    def predict(self, row):
        missing = set(self.features) - row.keys()
        if missing:
            raise ValueError('Missing features: ' + ', '.join(sorted(missing)))
        values = np.asarray([[float(row[key]) for key in self.features]], dtype=float)
        if not np.isfinite(values).all():
            raise ValueError('Features must be finite numbers')
        probabilities = self.model.predict_proba(self.scaler.transform(values))[0]
        label = str(self.labels[int(np.argmax(probabilities))])
        score, level = RISK.get(label, (None, 'غير محدد'))
        return {'timestamp': time.time(), 'source': 'recorded_flow', 'attack_type': label,
                'risk_score': score, 'risk_level': level,
                'class_probabilities': dict(zip(map(str, self.labels), map(float, probabilities)))}


def save_prediction(result, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=target.parent, suffix='.tmp')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, allow_nan=False)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
