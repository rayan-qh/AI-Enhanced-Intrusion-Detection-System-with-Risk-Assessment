"""Recover only the four model files from the original graduation ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    target = Path(__file__).parent / 'artifacts'
    names = ['model_multiclass.pkl', 'scaler.pkl', 'label_encoder.pkl', 'feature_columns.json']
    target.mkdir(exist_ok=True)
    with ZipFile(args.archive) as archive:
        payloads = {name: archive.read('ai_ids/' + name) for name in names}
    for name, payload in payloads.items():
        existing = target / name
        if existing.exists() and existing.read_bytes() != payload:
            parser.error('Different artifact already exists: ' + name)
    for name, payload in payloads.items():
        (target / name).write_bytes(payload)
    manifest = {name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()}
    (target / 'sha256.json').write_text(json.dumps(manifest, indent=2))
    print('تم استيراد ملفات النموذج محليًا والتحقق من عدم استبدال نسخة مختلفة.')


if __name__ == '__main__':
    main()
