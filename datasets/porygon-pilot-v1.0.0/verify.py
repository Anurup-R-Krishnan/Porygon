"""Verify this dataset offline; run with Python 3.11+."""
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


def verify(root):
    hashes = json.loads((root / 'checksums.json').read_text())
    actual = {str(p.relative_to(root)) for p in root.rglob('*')
              if p.is_file() and p.name != 'checksums.json' and '__pycache__' not in p.parts}
    if actual != set(hashes):
        raise ValueError('Package file inventory differs from checksum manifest')
    for name, expected in hashes.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f'Checksum mismatch: {name}')
    sources = json.loads((root / 'source-checksums.json').read_text())
    for name, expected in sources.items():
        if hashes.get(name) != expected:
            raise ValueError(f'Source provenance mismatch: {name}')
    with (root / 'trial-index.csv').open(newline='') as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 216 or len({r['trial_id'] for r in rows}) != 216:
        raise ValueError('Expected 216 unique index rows')
    if len(list((root / 'trials').glob('*.json'))) != 216:
        raise ValueError('Expected 216 source trial files')
    for row in rows:
        trial = json.loads((root / 'trials' / (row['trial_id'] + '.json')).read_text())
        gt = trial['ground_truth']
        label = 'controlled_attack_like' if gt['attack_like'] else 'controlled_non_attack_like'
        if row['label'] != label or row['release_split'] != 'pilot':
            raise ValueError('Label or split mismatch')
        if trial['research_eligible'] is not False or trial['split'] != 'pilot':
            raise ValueError('Unexpected source eligibility')
        if not gt['simulation_only'] or gt['exploit_executed']:
            raise ValueError('Unexpected scenario safety classification')
        for key in ('trial_id', 'run_id', 'workload_id', 'scenario_id', 'context_variant',
                    'replica_index', 'runtime_context_hash'):
            if row[key] != str(trial[key]):
                raise ValueError(f'Index mismatch: {key}')
        if row['image_digest'] != gt['image_digest']:
            raise ValueError('Image identity mismatch')
    cells = Counter((r['workload_id'], r['scenario_id'], r['context_variant']) for r in rows)
    labels = Counter(r['label'] for r in rows)
    meta = json.loads((root / 'metadata.json').read_text())
    if len(cells) != 18 or set(cells.values()) != {12}:
        raise ValueError('Collection matrix mismatch')
    if dict(labels) != meta['label_counts'] or meta['trial_count'] != len(rows):
        raise ValueError('Metadata count mismatch')
    if meta['evidence_class'] != 'pilot' or meta['research_eligible'] is not False:
        raise ValueError('Dataset must remain pilot evidence')
    print(f'PASS: {len(rows)} trials, {len(cells)} cells, {len(hashes)} file hashes; labels match source.')


if __name__ == '__main__':
    verify(Path(__file__).resolve().parent)
