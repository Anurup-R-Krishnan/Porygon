// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SCHEMA,
  md,
  buildEvidenceBundle,
  renderEvidenceMarkdown,
  exportFilename,
} = require('../src/evidence.js');

const incident = {
  incident_id: '0f2c9a1e-7b3d-4c55-9e10-2a6b8c4d1f00',
  title: '2 incident-eligible rule match(es)',
  status: 'open',
  severity_level: 'medium',
  severity_score: 0.62,
  confidence_level: 'high',
  confidence_score: 0.96,
  anomaly_score: 0.511,
  image_digest: 'sha256:688f',
  container_ids: ['abc123'],
  first_seen_at: '2026-09-24T10:45:12Z',
  last_seen_at: '2026-09-24T10:46:00Z',
  detection_run_id: 'run-1',
  summary: 'Shell spawned a miner.',
  findings: [{ rule_id: 'POR-DET-004' }, { rule_id: 'POR-DET-001' }],
};
const timeline = [
  { sequence_no: 2, occurred_at: '2026-09-24T10:45:13Z', evidence_type: 'process', rule_id: 'POR-DET-006', summary: 'second' },
  { sequence_no: 1, occurred_at: '2026-09-24T10:45:12Z', evidence_type: 'process', rule_id: null, summary: 'first' },
];
const score = {
  total_score: 0.511,
  score_band: 'high',
  window_start: '2026-09-24T10:45:00Z',
  window_end: '2026-09-24T10:50:00Z',
  process_event_count: 12,
  runtime_event_count: 3,
  profile_id: 'prof-1',
  profile_version: 2,
  profile_model_hash: 'deadbeef',
  algorithm_version: 'porygon.distance.v1',
  components: { categorical_distance: { families: { executable: { distance: 0.8123 }, user_uid: { distance: 0.1 } } } },
  explanation: { unseen_tokens: [{ feature: 'executable', token: '/usr/bin/xmrig', proportion: 0.25 }] },
};
const rules = {
  'POR-DET-001': { name: 'High Behavioral Distance', description: 'JS distance at least 0.5' },
  'POR-DET-004': { name: 'Unseen Non-Shell Executable', description: 'Absent from baseline' },
  'POR-DET-099': { name: 'Unrelated', description: 'Not referenced' },
};
const sources = [{ path: '/api/v1/incidents/x', status: 200, bytes: 512, sha256: 'a'.repeat(64), fetched_at: '2026-10-06T08:00:00Z' }];

function bundle(overrides = {}) {
  return buildEvidenceBundle({ incident, timeline, score, rules, sources, exportedAt: '2026-10-06T08:00:01Z', ...overrides });
}

test('the bundle is labelled operational, never research evidence', () => {
  const b = bundle();
  assert.equal(b.schema, SCHEMA);
  assert.equal(b.evidence_class, 'operational');
  assert.match(b.note, /not pilot or confirmatory/);
});

test('the timeline is ordered by sequence number', () => {
  assert.deepEqual(bundle().timeline.map((r) => r.sequence_no), [1, 2]);
});

test('only rules the incident references are included, with gaps marked', () => {
  const b = bundle();
  assert.deepEqual(Object.keys(b.rules), ['POR-DET-001', 'POR-DET-004', 'POR-DET-006']);
  assert.equal(b.rules['POR-DET-006'], null, 'referenced but unknown stays visible as null');
  assert.equal(b.rules['POR-DET-099'], undefined);
});

test('the bundle does not mutate the caller\'s timeline', () => {
  const copy = timeline.map((r) => r.sequence_no);
  bundle();
  assert.deepEqual(timeline.map((r) => r.sequence_no), copy);
});

test('markdown carries the incident, rules, distances, timeline and sources', () => {
  const text = renderEvidenceMarkdown(bundle());
  assert.match(text, /^# Incident evidence: 2 incident-eligible rule match\(es\)/);
  assert.match(text, /\| Severity \| medium \(0\.62\) \|/);
  assert.match(text, /\*\*POR-DET-001\*\* High Behavioral Distance/);
  assert.match(text, /\*\*POR-DET-006\*\* \(rule metadata unavailable\)/);
  assert.match(text, /\| executable \| 0\.812 \|/);
  assert.match(text, /- executable: \/usr\/bin\/xmrig \(25\.0%\)/);
  assert.match(text, /\| 1 \| 2026-09-24T10:45:12\.000Z \| process \| — \| first \|/);
  assert.match(text, new RegExp('`' + 'a'.repeat(64) + '`'));
});

test('timestamps in the export are UTC ISO, never locale formatted', () => {
  assert.match(renderEvidenceMarkdown(bundle()), /First seen \| 2026-09-24T10:45:12\.000Z/);
});

test('a missing score is stated, not silently omitted', () => {
  const text = renderEvidenceMarkdown(bundle({ score: null }));
  assert.match(text, /was not available at export time/);
});

test('attacker-controlled text cannot inject markup, links, or table structure', () => {
  const hostile = 'sh -c "<img src=x onerror=alert(1)> [click](http://evil) | x\n## Fake heading"';
  const text = renderEvidenceMarkdown(bundle({
    timeline: [{ sequence_no: 1, occurred_at: '2026-09-24T10:45:12Z', evidence_type: 'process', rule_id: null, summary: hostile }],
  }));
  const row = text.split('\n').find((line) => line.startsWith('| 1 |'));
  assert.ok(row, 'the row survives on one line');
  assert.ok(!row.includes('<img'), 'HTML is escaped');
  assert.ok(row.includes('&lt;img'));
  assert.ok(row.includes('\\[click\\]'), 'link syntax is escaped');
  assert.equal(row.split(/(?<!\\)\|/).length - 2, 5, 'the pipe inside the summary does not add a column');
  assert.ok(!text.includes('\n## Fake heading'), 'a newline cannot start a new block');
});

test('md escapes and folds, and renders empties as a dash', () => {
  assert.equal(md('a|b'), 'a\\|b');
  assert.equal(md('x\ny'), 'x y');
  assert.equal(md('`code`'), '\\`code\\`');
  assert.equal(md(null), '—');
  assert.equal(md(''), '—');
  assert.equal(md(0), '0');
});

test('export filenames are stable, short, and filesystem-safe', () => {
  assert.equal(
    exportFilename('0f2c9a1e-7b3d-4c55-9e10-2a6b8c4d1f00', '2026-10-06T08:00:01.250Z', 'md'),
    'porygon-incident-0f2c9a1e-20261006T080001Z.md',
  );
  assert.equal(exportFilename('../../etc', '2026-10-06T08:00:01Z', 'json'), 'porygon-incident-etc-20261006T080001Z.json');
});
