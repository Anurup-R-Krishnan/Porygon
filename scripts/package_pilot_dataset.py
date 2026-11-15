"""Build an offline, pilot-only trial metadata package without querying Docker or SQL."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.artifacts import reject_secrets

RUN = 'study-confirmatory-200-20260906t071234Z'
ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def build(source: Path, destination: Path):
    records = []
    provenance = {}
    files = {}
    for path in sorted((source / 'trials').glob('*.json')):
        raw = path.read_bytes()
        trial = json.loads(raw)
        reject_secrets(trial)
        if trial['run_id'] != RUN or trial['research_eligible'] is not False:
            raise ValueError('Unexpected run or evidence eligibility')
        if trial['status'] != 'completed' or trial['split'] != 'pilot':
            raise ValueError('Unexpected trial status or split')
        gt = trial['ground_truth']
        if not gt['simulation_only'] or gt['exploit_executed']:
            raise ValueError('Expected inert simulations only')
        record = {
            'trial_id': trial['trial_id'], 'run_id': trial['run_id'],
            'workload_id': trial['workload_id'], 'scenario_id': trial['scenario_id'],
            'context_variant': trial['context_variant'], 'replica_index': trial['replica_index'],
            'image_digest': gt['image_digest'], 'runtime_context_hash': trial['runtime_context_hash'],
            'source_split': trial['split'], 'release_split': 'pilot',
            'evidence_class': 'pilot', 'research_eligible': False,
            'label': 'controlled_attack_like' if gt['attack_like'] else 'controlled_non_attack_like',
            'simulation_only': True, 'exploit_executed': False,
        }
        records.append(record)
        files['trials/' + path.name] = raw
        provenance['trials/' + path.name] = hashlib.sha256(raw).hexdigest()
    if len(records) != 216 or len({r['trial_id'] for r in records}) != 216:
        raise ValueError('Expected exactly 216 unique trials')
    cells = Counter((r['workload_id'], r['scenario_id'], r['context_variant']) for r in records)
    if len(cells) != 18 or set(cells.values()) != {12}:
        raise ValueError('Expected 18 matrix cells with 12 replicas each')
    for name in ('run.json', 'study-manifest.json', 'images.json'):
        raw = (source / name).read_bytes()
        reject_secrets(json.loads(raw))
        files['provenance/' + name] = raw
        provenance['provenance/' + name] = hashlib.sha256(raw).hexdigest()
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(records[0]))
    writer.writeheader()
    writer.writerows(records)
    files['trial-index.csv'] = stream.getvalue().encode()
    files['source-checksums.json'] = encode(provenance)
    files['metadata.json'] = encode({
        'dataset_version': '1.0.0', 'status': 'release',
        'public_repository': 'https://github.com/Anurup-R-Krishnan/Porygon/tree/technical-enrichment/datasets/porygon-pilot-v1.0.0',
        'title': 'Porygon controlled-container pilot trial metadata',
        'source_run': RUN, 'evidence_class': 'pilot', 'research_eligible': False,
        'trial_count': len(records), 'raw_process_events_included': False,
        'label_counts': dict(Counter(r['label'] for r in records)),
        'license': 'CC-BY-4.0', 'license_status': 'owner_authorized_2026-10-25',
        'split_policy': 'All records are pilot; no confirmatory train/test split is claimed.',
        'historical_conflicts': [
            'Run identifier contains confirmatory despite pilot evidence class.',
            'Nested study stages retain historical confirmatory flags; release metadata overrides eligibility.',
            'Study stage reports fit/calibration/test counts but source trials all declare pilot.',
            'Analysis denominators (53 benign, 96 scenario) are subsets, not all 216 trials; membership is not provided here.',
        ],
    })
    # Validate every input before creating the output; refuse to alter existing payloads.
    for name, raw in files.items():
        target = destination / name
        if target.exists() and target.read_bytes() != raw:
            raise ValueError(f'Refusing to overwrite changed payload: {name}')
    for name, raw in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    checksums = {str(p.relative_to(destination)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(destination.rglob('*')) if p.is_file() and p.name != 'checksums.json' and '__pycache__' not in p.parts}
    (destination / 'checksums.json').write_bytes(encode(checksums))
    print(json.dumps({'trials': len(records), 'matrix_cells': len(cells), 'files': len(checksums),
                      'labels': dict(Counter(r['label'] for r in records))}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'artifacts/experiments/local' / RUN)
    parser.add_argument('--out', type=Path, default=ROOT / 'datasets/porygon-pilot-v1.0.0')
    args = parser.parse_args()
    build(args.source, args.out)
