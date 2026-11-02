"""Predict one recorded CSV row with local model artifacts."""
import argparse
import csv
from pathlib import Path
from inference import Predictor, save_prediction


def normalize_headers(headers):
    """Preserve duplicate CICIDS columns using pandas-compatible suffixes."""
    used = set()
    result = []
    for raw in headers:
        name = raw.strip()
        candidate = name
        suffix = 1
        while candidate in used:
            candidate = f'{name}.{suffix}'
            suffix += 1
        used.add(candidate)
        result.append(candidate)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_path', type=Path)
    parser.add_argument('--artifacts', type=Path, default=Path(__file__).parent / 'artifacts')
    parser.add_argument('--row', type=int, default=0)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'runtime/prediction.json')
    args = parser.parse_args()
    if args.row < 0:
        parser.error('--row must be nonnegative')
    with args.csv_path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            parser.error('CSV is empty')
        reader.fieldnames = normalize_headers(reader.fieldnames)
        for index, row in enumerate(reader):
            if index == args.row:
                result = Predictor(args.artifacts).predict({key.strip(): value for key, value in row.items()})
                save_prediction(result, args.output)
                print(result['attack_type'])
                return
    parser.error('Requested row does not exist')


if __name__ == '__main__':
    main()
