// Incident evidence export for the operator console.
//
// An operator who needed an incident in a report, a ticket, or a hand-off had
// nothing to export: the evidence lived only on screen. This builds a bundle
// from the exact API responses the console fetched -- each recorded with the
// sha256 of its bytes, in the spirit of the experiments/ artifact contract --
// and renders it as JSON for tooling and Markdown for people.
//
// Timeline summaries, process tokens and container names carry text an
// attacker controls (command lines, binary names). renderEvidenceMarkdown
// escapes HTML and link syntax so a crafted command line cannot inject
// markup or a link into a rendered report.
//
// Loaded as a plain script by index.html (window.PorygonEvidence) and as
// CommonJS by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonEvidence = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var SCHEMA = 'porygon.incident-evidence.v1';

  // Escape text for Markdown: entities for HTML, backslashes for the inline
  // syntax that could form links, emphasis or code, and newlines folded so a
  // value cannot break out of a table row or start a new block.
  function md(value) {
    if (value === null || value === undefined || value === '') return '—';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/([\\`*_[\]|#!])/g, '\\$1')
      .replace(/\r?\n|\r/g, ' ');
  }

  function utc(value) {
    if (!value) return '—';
    var date = new Date(value);
    return isNaN(date.getTime()) ? md(value) : date.toISOString();
  }

  function number(value, digits) {
    return typeof value === 'number' && isFinite(value) ? value.toFixed(digits) : '—';
  }

  function ruleIdsOf(incident, timeline) {
    var ids = [];
    function add(id) {
      if (typeof id === 'string' && id && ids.indexOf(id) === -1) ids.push(id);
    }
    ((incident && incident.findings) || []).forEach(function (f) { add(f && f.rule_id); });
    (timeline || []).forEach(function (row) { add(row && row.rule_id); });
    return ids.sort();
  }

  // sources: [{ path, status, bytes, sha256, fetched_at }], one per request.
  function buildEvidenceBundle(input) {
    var timeline = (input.timeline || []).slice().sort(function (a, b) {
      return (a.sequence_no || 0) - (b.sequence_no || 0);
    });
    var catalogue = input.rules || {};
    var rules = {};
    ruleIdsOf(input.incident, timeline).forEach(function (id) {
      rules[id] = catalogue[id] || null;
    });
    return {
      schema: SCHEMA,
      exported_at: input.exportedAt,
      // Not research evidence: docs/EXPERIMENT_ACCEPTANCE.md governs what a
      // pilot or confirmatory claim may rest on, and an operator export of a
      // live incident is neither.
      evidence_class: 'operational',
      note: 'Exported from the Porygon operator console. Each entry in sources records the sha256 of the exact API response bytes this bundle was built from. Operational evidence, not pilot or confirmatory research evidence.',
      incident: input.incident || null,
      anomaly_score: input.score || null,
      timeline: timeline,
      rules: rules,
      sources: input.sources || [],
    };
  }

  function familyRows(score) {
    var families = score && score.components && score.components.categorical_distance
      && score.components.categorical_distance.families;
    if (!families || typeof families !== 'object') return [];
    return Object.keys(families).sort().map(function (name) {
      var family = families[name] || {};
      return '| ' + md(name) + ' | ' + number(family.distance, 3) + ' |';
    });
  }

  function unseenTokens(score) {
    var tokens = score && score.explanation && score.explanation.unseen_tokens;
    if (!Array.isArray(tokens)) return [];
    return tokens.map(function (t) {
      if (t && typeof t === 'object') {
        return '- ' + md(t.feature) + ': ' + md(t.token)
          + (typeof t.proportion === 'number' ? ' (' + (t.proportion * 100).toFixed(1) + '%)' : '');
      }
      return '- ' + md(t);
    });
  }

  function renderEvidenceMarkdown(bundle) {
    var inc = bundle.incident || {};
    var score = bundle.anomaly_score;
    var out = [];

    out.push('# Incident evidence: ' + md(inc.title || inc.incident_id));
    out.push('');
    out.push('Exported ' + utc(bundle.exported_at) + ' · schema `' + bundle.schema + '` · evidence class: ' + md(bundle.evidence_class));
    out.push('');
    out.push('| Field | Value |');
    out.push('|---|---|');
    out.push('| Incident | ' + md(inc.incident_id) + ' |');
    out.push('| Status | ' + md(inc.status) + ' |');
    out.push('| Severity | ' + md(inc.severity_level) + ' (' + number(inc.severity_score, 2) + ') |');
    out.push('| Confidence | ' + md(inc.confidence_level) + ' (' + number(inc.confidence_score, 2) + ') |');
    out.push('| Anomaly score | ' + number(inc.anomaly_score, 3) + ' |');
    out.push('| Image digest | ' + md(inc.image_digest) + ' |');
    out.push('| Containers | ' + md((inc.container_ids || []).join(', ')) + ' |');
    out.push('| First seen | ' + utc(inc.first_seen_at) + ' |');
    out.push('| Last seen | ' + utc(inc.last_seen_at) + ' |');
    out.push('| Detection run | ' + md(inc.detection_run_id) + ' |');
    out.push('');
    out.push('## Summary');
    out.push('');
    out.push(md(inc.summary));
    out.push('');

    out.push('## Matched rules');
    out.push('');
    var ruleIds = Object.keys(bundle.rules || {});
    if (!ruleIds.length) {
      out.push('No rule matches recorded.');
    } else {
      ruleIds.forEach(function (id) {
        var rule = bundle.rules[id];
        out.push('- **' + md(id) + '**' + (rule ? ' ' + md(rule.name) + ': ' + md(rule.description) : ' (rule metadata unavailable)'));
      });
    }
    out.push('');

    out.push('## Behavioural distance');
    out.push('');
    if (!score) {
      out.push('The anomaly score behind this incident was not available at export time.');
    } else {
      out.push('| Field | Value |');
      out.push('|---|---|');
      out.push('| Score | ' + number(score.total_score, 3) + ' (' + md(score.score_band) + ') |');
      out.push('| Window | ' + utc(score.window_start) + ' to ' + utc(score.window_end) + ' |');
      out.push('| Events in window | ' + md(score.process_event_count) + ' process, ' + md(score.runtime_event_count) + ' runtime |');
      out.push('| Profile | ' + md(score.profile_id) + ' v' + md(score.profile_version) + ' |');
      out.push('| Profile model hash | ' + md(score.profile_model_hash) + ' |');
      out.push('| Algorithm | ' + md(score.algorithm_version) + ' |');
      var families = familyRows(score);
      if (families.length) {
        out.push('');
        out.push('Jensen-Shannon distance per feature family:');
        out.push('');
        out.push('| Family | Distance |');
        out.push('|---|---|');
        families.forEach(function (row) { out.push(row); });
      }
      var tokens = unseenTokens(score);
      if (tokens.length) {
        out.push('');
        out.push('Tokens absent from the trained baseline:');
        out.push('');
        tokens.forEach(function (row) { out.push(row); });
      }
    }
    out.push('');

    out.push('## Evidence timeline');
    out.push('');
    if (!bundle.timeline.length) {
      out.push('No timeline entries.');
    } else {
      out.push('| # | Occurred (UTC) | Type | Rule | Summary |');
      out.push('|---|---|---|---|---|');
      bundle.timeline.forEach(function (row) {
        out.push('| ' + md(row.sequence_no) + ' | ' + utc(row.occurred_at) + ' | ' + md(row.evidence_type)
          + ' | ' + md(row.rule_id) + ' | ' + md(row.summary) + ' |');
      });
    }
    out.push('');

    out.push('## Sources');
    out.push('');
    out.push('| Request | Status | Bytes | sha256 | Fetched (UTC) |');
    out.push('|---|---|---|---|---|');
    (bundle.sources || []).forEach(function (s) {
      out.push('| ' + md(s.path) + ' | ' + md(s.status) + ' | ' + md(s.bytes) + ' | '
        + (s.sha256 ? '`' + s.sha256 + '`' : 'unavailable') + ' | ' + utc(s.fetched_at) + ' |');
    });
    out.push('');
    out.push('_' + md(bundle.note) + '_');
    out.push('');
    return out.join('\n');
  }

  function exportFilename(incidentId, exportedAt, extension) {
    var stamp = new Date(exportedAt).toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
    var id = String(incidentId || 'unknown').replace(/[^A-Za-z0-9-]/g, '').slice(0, 8) || 'unknown';
    return 'porygon-incident-' + id + '-' + stamp + '.' + extension;
  }

  return {
    SCHEMA: SCHEMA,
    md: md,
    buildEvidenceBundle: buildEvidenceBundle,
    renderEvidenceMarkdown: renderEvidenceMarkdown,
    exportFilename: exportFilename,
  };
});
