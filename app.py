"""Local dashboard for recorded flow inference and Snort evidence."""
import json
import os
import re
import time
from pathlib import Path

from flask import Flask, jsonify, render_template

PROJECT_NAME = 'AI-Enhanced Intrusion Detection System with Risk Assessment'
ROOT = Path(__file__).resolve().parent


def parse_snort(line):
    match = re.search(r'\[(\d+):(\d+):(\d+)\]\s*(.*?)\s*\[\*\*\]', line)
    if not match:
        return None
    return {'rule': ':'.join(match.group(i) for i in (1, 2, 3)),
            'message': match.group(4).strip('" '), 'confidence': None}


def read_status(runtime):
    result = {'state': 'idle', 'message': 'لا توجد بيانات حديثة',
              'prediction': None, 'snort': None}
    prediction_file = runtime / 'prediction.json'
    if prediction_file.exists():
        try:
            prediction = json.loads(prediction_file.read_text(encoding='utf-8'))
            timestamp = float(prediction['timestamp'])
            probabilities = prediction['class_probabilities']
            if not probabilities or any(not isinstance(v, (float, int)) or not 0 <= v <= 1 for v in probabilities.values()):
                raise ValueError('invalid probabilities')
            if abs(sum(probabilities.values()) - 1) > 0.001:
                raise ValueError('invalid total')
            if prediction['attack_type'] not in probabilities:
                raise ValueError('invalid class')
            result['prediction'] = prediction
            result['state'] = 'ready' if 0 <= time.time() - timestamp <= 60 else 'stale'
            result['message'] = 'نتيجة استدلال حديثة' if result['state'] == 'ready' else 'نتيجة محفوظة قديمة'
        except (ValueError, KeyError, TypeError, OSError):
            result.update(state='invalid', message='ملف النتيجة غير صالح')
    snort_file = runtime / 'alert_fast.txt'
    if snort_file.exists():
        try:
            with snort_file.open('rb') as stream:
                size = stream.seek(0, 2)
                start = max(0, size - 65536)
                stream.seek(start)
                lines = stream.read().decode('utf-8', errors='replace').splitlines()
            if start:
                lines = lines[1:]
            for line in reversed(lines):
                event = parse_snort(line)
                if event:
                    event['file_updated_at'] = snort_file.stat().st_mtime
                    event['fresh'] = 0 <= time.time() - event['file_updated_at'] <= 60
                    result['snort'] = event
                    break
        except OSError:
            result['snort_error'] = 'تعذرت قراءة سجل Snort'
    return result


def create_app(runtime=None):
    application = Flask(__name__)
    runtime = Path(runtime or os.environ.get('IDS_RUNTIME', ROOT / 'runtime'))

    @application.get('/')
    def index():
        return render_template('index.html', project_name=PROJECT_NAME)

    @application.get('/api/status')
    def status():
        return jsonify(read_status(runtime))

    @application.get('/api/health')
    def health():
        return jsonify(status='ok', model_loaded=False)

    return application


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
