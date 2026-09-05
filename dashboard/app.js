// Porygon Alpine.js State & Chart Controller — fully wired to backend (v0.8.0)
document.addEventListener('alpine:init', () => {
  Alpine.data('porygonApp', () => ({
    // Navigation
    activeTab: 'overview',
    navOpen: false,

    // System & Health Data
    systemInfo: {},
    services: [],
    containers: [],
    runtimeEvents: [],
    selectedContainer: null,

    // Telemetry & Events (process-level eBPF)
    events: [], // ProcessExecEventOut[]
    eventFilter: '',
    processSummary: null,
    runtimeSummary: null,

    // Behavioural Anomaly & Distance
    scores: [],
    anomalyConfig: null,
    activeProfile: null,
    currentAnomalyScore: 0.12,
    currentScoreBand: 'baseline_like',
    scoreContributors: [],
    unseenTokens: [],

    // Rules & Incidents
    rules: [],
    rulesMeta: {},
    incidents: [],
    selectedIncident: null,

    // Pipeline trace (raw event -> rule match -> incident)
    pipelineIncidentId: '',
    pipelineTimeline: [],
    pipelineLoading: false,
    pipelineError: '',

    // Vulnerability & Evidence Ladder
    vulnerabilityFindings: [],
    evidenceCounts: {
      package_present: 0,
      deployed: 0,
      runtime_observed: 0,
      runtime_observed_and_port_published: 0
    },

    // Simulator & Terminal Console
    terminalLogs: [
      { time: new Date().toLocaleTimeString(), tag: 'KERNEL', msg: 'modern-eBPF probe attached to sys_enter_execve', type: 'info' },
      { time: new Date().toLocaleTimeString(), tag: 'COLLECTOR', msg: 'Docker daemon outbox spool initialized', type: 'info' },
      { time: new Date().toLocaleTimeString(), tag: 'SYSTEM', msg: 'Porygon behavioral intelligence platform ready — gateway 127.0.0.1:8000', type: 'success' }
    ],
    isExecutingAttack: false,
    toasts: [],

    // Operator token (stored in localStorage)
    get operatorToken() {
      try { return localStorage.getItem('porygon_operator_token') || ''; } catch(e){ return ''; }
    },
    set operatorToken(v) {
      try {
        if (v) localStorage.setItem('porygon_operator_token', v);
        else localStorage.removeItem('porygon_operator_token');
      } catch(e){}
    },

    // Chart References
    charts: {},

    async init() {
      console.log('Initializing Porygon Dashboard with Alpine.js — ethreal glass');
      // expose reveal
      if (typeof window.initReveal === 'function') window.initReveal();
      await this.fetchRules();
      await this.refreshAllData();
      this.initCharts();
      // after DOM for charts, init reveal again for bento
      if (typeof window.initReveal === 'function') window.initReveal();

      // Auto-refresh interval every 3 seconds
      setInterval(() => {
        this.pollLiveTelemetry();
      }, 3000);
      // heavier refresh for system info every 10s
      setInterval(() => { this.fetchSystemInfo(); this.fetchAnomalyScores(); }, 10000);
    },

    // helpers
    _apiFetch(path, opts={}) {
      // attach operator token if present for operator routes
      const headers = Object.assign({}, opts.headers || {});
      const token = this.operatorToken;
      if (token && path.includes('/operator/')) {
        headers['X-Porygon-Operator-Token'] = token;
      }
      // for demo route via dashboard server, keep same host
      return fetch(path, Object.assign({}, opts, { headers }));
    },

    showToast(message, type = 'info') {
      const id = Date.now() + Math.random();
      this.toasts.push({ id, message, type });
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 4500);
    },

    logTerminal(tag, msg, type = 'info') {
      const time = new Date().toLocaleTimeString();
      this.terminalLogs.unshift({ time, tag, msg, type });
      if (this.terminalLogs.length > 120) this.terminalLogs.pop();
    },

    // ---- Backend wiring ----

    async fetchRules() {
      try {
        const res = await fetch('/api/v1/detection-rules/config');
        if (res.ok) {
          const data = await res.json();
          this.rules = data.rules || [];
          this.rulesMeta = data;
        } else {
          console.warn('detection-rules/config non-200', res.status);
        }
      } catch (err) {
        console.warn('Could not load detection rules config:', err);
      }
      try {
        const cfg = await fetch('/api/v1/anomaly-scores/config');
        if (cfg.ok) this.anomalyConfig = await cfg.json();
      } catch(e){}
    },

    async fetchSystemInfo() {
      try {
        const res = await fetch('/api/v1/system/info');
        if (res.ok) {
          this.systemInfo = await res.json();
          // sync counters that were previously hardcoded
          // keep in terminal
        }
      } catch(e){ console.warn('system/info failed', e); }
    },

    async fetchServices() {
      try {
        const res = await fetch('/api/v1/services');
        if (res.ok) {
          this.services = await res.json();
        } else throw new Error('non-200');
      } catch (err) {
        this.services = [
          { service_name: 'collector', status: 'healthy', service_metadata: {} },
          { service_name: 'telemetry', status: 'healthy', service_metadata: {} },
          { service_name: 'scanner', status: 'healthy', service_metadata: {} },
          { service_name: 'responder', status: 'healthy', service_metadata: {} },
        ];
      }
    },

    async fetchContainers() {
      try {
        const res = await fetch('/api/v1/containers?limit=100');
        if (res.ok) {
          const data = await res.json();
          this.containers = Array.isArray(data) ? data : (data.items || []);
        }
      } catch (err) {
        console.warn('Could not fetch containers:', err);
      }
    },

    async fetchEvents() {
      // Prefer process-events (eBPF) for telemetry tab; also fetch runtime summary
      try {
        const res = await fetch('/api/v1/process-events?limit=40');
        if (res.ok) {
          this.events = await res.json();
        } else {
          // fallback to older /events if process-events not yet
          const r2 = await fetch('/api/v1/events?limit=40');
          if (r2.ok) this.runtimeEvents = await r2.json();
        }
      } catch (err) {
        console.warn('Could not fetch process-events:', err);
      }
      // also fetch summaries for context
      try {
        const s = await fetch('/api/v1/process-events/summary');
        if (s.ok) this.processSummary = await s.json();
        const rs = await fetch('/api/v1/events/summary');
        if (rs.ok) this.runtimeSummary = await rs.json();
      } catch(e){}
    },

    async fetchAnomalyScores() {
      try {
        const res = await fetch('/api/v1/anomaly-scores?limit=20');
        if (res.ok) {
          const list = await res.json();
          if (Array.isArray(list) && list.length) {
            this.scores = list;
            // use most recent scored window
            const latest = list.find(s => s.status === 'scored') || list[0];
            if (latest && latest.total_score != null) {
              this.currentAnomalyScore = latest.total_score;
              this.currentScoreBand = latest.score_band || this._bandForScore(latest.total_score);
              // extract unseen tokens / contributors from explanation if present
              const exp = latest.explanation || {};
              const families = (latest.components && latest.components.categorical_distance && latest.components.categorical_distance.families) || {};
              // fallback: explanation.novel_executables etc.
              if (exp.unseen_tokens) this.unseenTokens = exp.unseen_tokens.slice(0,12);
              else if (exp.novel_tokens) this.unseenTokens = exp.novel_tokens.slice(0,12);
              else {
                // synthesize from categorical families top_observed where baseline_support small
                const toks = [];
                Object.values(families).forEach(f=>{
                  if (f.distance > 0.5 && f.top_observed) {
                    f.top_observed.slice(0,2).forEach(t=> toks.push(t.token));
                  }
                });
                if (toks.length) this.unseenTokens = [...new Set(toks)].slice(0,10);
              }
              this.scoreContributors = latest.components ? Object.entries(latest.components).map(([k,v])=>({token:k, weight: v.score||0})) : [];
              this.activeProfile = { profile_id: latest.profile_id, version: latest.profile_version };
              this.updateTimelineChart();
              this.updateScoreFromLatest();
            }
          }
        }
      } catch (err) {
        console.warn('Could not fetch anomaly-scores:', err);
      }
    },

    _bandForScore(s) {
      if (s >= 0.75) return 'extreme';
      if (s >= 0.50) return 'high';
      if (s >= 0.25) return 'elevated';
      return 'baseline_like';
    },

    updateScoreFromLatest(){
      // no-op, kept for reveal
    },

    async fetchIncidents() {
      try {
        const res = await fetch('/api/v1/incidents?limit=50');
        if (res.ok) {
          const fetched = await res.json();
          // Preserve synthetic demo incidents that are not yet in DB (identified by inc- prefix not uuid)
          const synthetic = this.incidents.filter(i => i.incident_id && i.incident_id.startsWith('inc-'));
          // merge: real incidents first, then synthetic on top already inserted via trigger
          // dedupe by incident_id
          const byId = new Map();
          [...fetched, ...synthetic].forEach(i=> byId.set(i.incident_id, i));
          this.incidents = Array.from(byId.values()).sort((a,b)=> new Date(b.created_at || b.first_seen_at) - new Date(a.created_at || a.first_seen_at));
          if (this.incidents.length > 0 && !this.selectedIncident) {
            this.selectedIncident = this.incidents[0];
          }
        }
      } catch (err) {
        console.warn('Could not fetch incidents:', err);
      }
    },

    async fetchScans() {
      try {
        const res = await fetch('/api/v1/image-scans?limit=20');
        if (res.ok) {
          const scans = await res.json();
          if (Array.isArray(scans) && scans.length > 0) {
            // find latest completed, fallback to first
            const latest = scans.find(s=> s.status==='completed') || scans[0];
            const detailRes = await fetch(`/api/v1/image-scans/${latest.scan_id}`);
            if (detailRes.ok) {
              const detail = await detailRes.json();
              this.vulnerabilityFindings = detail.vulnerabilities || [];
              this.calculateEvidenceCounts();
            }
          } else {
            // no scans yet — keep placeholder counts but zero
            this.vulnerabilityFindings = [];
            this.calculateEvidenceCounts();
          }
        }
      } catch (err) {
        console.warn('Could not fetch scans:', err);
      }
    },

    calculateEvidenceCounts() {
      const counts = {
        package_present: 0,
        deployed: 0,
        runtime_observed: 0,
        runtime_observed_and_port_published: 0
      };
      this.vulnerabilityFindings.forEach(f => {
        if (counts[f.evidence_stage] !== undefined) {
          counts[f.evidence_stage]++;
        }
      });
      // if DB counts zero, keep dashboard live-ish by using systemInfo? but keep as is
      this.evidenceCounts = counts;
      this.updateEvidenceLadderChart();
    },

    async refreshAllData() {
      await this.fetchSystemInfo();
      await Promise.all([
        this.fetchServices(),
        this.fetchContainers(),
        this.fetchEvents(),
        this.fetchIncidents(),
        this.fetchScans(),
        this.fetchAnomalyScores()
      ]);
    },

    async pollLiveTelemetry() {
      await Promise.all([
        this.fetchContainers(),
        this.fetchEvents(),
        this.fetchIncidents(),
        this.fetchAnomalyScores()
      ]);
      this.updateTimelineChart();
    },

    // Chart Initializations — ethereal glass tuned
    initCharts() {
      Chart.defaults.font.family = 'JetBrains Mono';
      Chart.defaults.color = '#9A9A9A';
      Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';

      // 1. Behavioural Distance Timeline Chart
      const timelineCtx = document.getElementById('anomalyTimelineChart');
      if (timelineCtx) {
        // build labels from scores if available else static
        const labels = this.scores && this.scores.length ? this.scores.slice(0,7).reverse().map(s => new Date(s.window_start).toLocaleTimeString().slice(0,5)) : ['-30m', '-25m', '-20m', '-15m', '-10m', '-5m', 'Now'];
        const dataPoints = this.scores && this.scores.length ? this.scores.slice(0,7).reverse().map(s => s.total_score || 0) : [0.03, 0.04, 0.02, 0.05, 0.03, 0.08, this.currentAnomalyScore];
        // ensure last point reflects current
        if (dataPoints.length) dataPoints[dataPoints.length-1] = this.currentAnomalyScore;
        this.charts.timeline = new Chart(timelineCtx, {
          type: 'line',
          data: {
            labels,
            datasets: [
              {
                label: 'JENSEN-SHANNON D_JS',
                data: dataPoints,
                borderColor: '#FFFFFF',
                backgroundColor: 'rgba(124,58,237,0.10)',
                borderWidth: 2.5,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#FFFFFF',
                pointBorderColor: '#0A0A0F',
                pointBorderWidth: 1,
                pointRadius: 3,
                pointHoverRadius: 4,
                stepped: false
              },
              {
                label: 'DEVIATION 0.50 [POR-DET-001]',
                data: Array(labels.length).fill(0.50),
                borderColor: '#FFB000',
                borderWidth: 1,
                borderDash: [4, 4],
                pointRadius: 0,
                fill: false
              },
              {
                label: 'EXTREME 0.75',
                data: Array(labels.length).fill(0.75),
                borderColor: '#E11D48',
                borderWidth: 1,
                borderDash: [2, 4],
                pointRadius: 0,
                fill: false
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                min: 0.0,
                max: 1.0,
                grid: { color: 'rgba(255,255,255,0.06)', lineWidth: 1 },
                ticks: { color: 'rgba(255,255,255,0.45)', font: { family: 'JetBrains Mono', size: 10 } },
                border: { color: 'rgba(255,255,255,0.08)' }
              },
              x: {
                grid: { color: 'rgba(255,255,255,0.04)', lineWidth: 1 },
                ticks: { color: 'rgba(255,255,255,0.45)', font: { family: 'JetBrains Mono', size: 10 } },
                border: { color: 'rgba(255,255,255,0.08)' }
              }
            },
            plugins: {
              legend: {
                labels: { color: 'rgba(255,255,255,0.6)', font: { family: 'JetBrains Mono', size: 10 }, boxWidth: 10, usePointStyle: true, pointStyle: 'rect' }
              },
              tooltip: {
                backgroundColor: 'rgba(10,10,12,0.92)',
                titleColor: '#FFFFFF',
                bodyColor: 'rgba(255,255,255,0.7)',
                titleFont: { family: 'JetBrains Mono', weight: 'bold' },
                bodyFont: { family: 'JetBrains Mono' },
                borderColor: 'rgba(255,255,255,0.10)',
                borderWidth: 1,
                cornerRadius: 12,
                padding: 10,
                displayColors: true
              }
            }
          }
        });
      }

      // 2. Score Composition Doughnut Chart — ethereal violet/emerald
      const compCtx = document.getElementById('anomalyCompositionChart');
      if (compCtx) {
        this.charts.composition = new Chart(compCtx, {
          type: 'doughnut',
          data: {
            labels: ['CATEGORICAL 50%', 'NOVELTY 30%', 'NUMERIC 20%'],
            datasets: [{
              data: [50, 30, 20],
              backgroundColor: [
                '#7C3AED',
                '#10B981',
                '#F59E0B'
              ],
              borderColor: '#0A0A0F',
              borderWidth: 2,
              hoverOffset: 6
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: 'rgba(255,255,255,0.55)', font: { family: 'Plus Jakarta Sans', size: 11, weight: '600' }, boxWidth: 10, usePointStyle: true, pointStyle: 'circle', padding: 14 }
              },
              tooltip: {
                backgroundColor: 'rgba(10,10,15,0.9)',
                titleColor: '#FFFFFF',
                bodyColor: 'rgba(255,255,255,0.7)',
                borderColor: 'rgba(255,255,255,0.10)',
                borderWidth: 1,
                cornerRadius: 12,
                padding: 12,
                displayColors: true
              }
            }
          }
        });
      }

      // 3. Evidence Ladder Bar Chart
      const ladderCtx = document.getElementById('evidenceLadderChart');
      if (ladderCtx) {
        this.charts.ladder = new Chart(ladderCtx, {
          type: 'bar',
          data: {
            labels: ['[01] PACKAGE_PRESENT', '[02] DEPLOYED', '[03] RUNTIME_OBSERVED', '[04] PORT_PUBLISHED'],
            datasets: [{
              label: 'FINDINGS',
              data: [
                this.evidenceCounts.package_present,
                this.evidenceCounts.deployed,
                this.evidenceCounts.runtime_observed,
                this.evidenceCounts.runtime_observed_and_port_published
              ],
              backgroundColor: [
                'rgba(255,255,255,0.18)',
                'rgba(255,255,255,0.32)',
                '#FFB000',
                '#E11D48'
              ],
              borderColor: 'rgba(255,255,255,0.0)',
              borderWidth: 0,
              borderSkipped: false,
              borderRadius: 12
            }]
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              x: {
                grid: { color: 'rgba(255,255,255,0.06)', lineWidth: 1 },
                ticks: { color: 'rgba(255,255,255,0.45)', font: { family: 'JetBrains Mono', size: 10 } },
                border: { color: 'rgba(255,255,255,0.08)' }
              },
              y: {
                grid: { display: false },
                ticks: { color: '#FFFFFF', font: { family: 'JetBrains Mono', weight: '700', size: 10 } },
                border: { color: 'rgba(255,255,255,0.08)' }
              }
            },
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: 'rgba(10,10,12,0.92)',
                titleColor: '#FFFFFF',
                bodyColor: 'rgba(255,255,255,0.7)',
                borderColor: 'rgba(255,255,255,0.10)',
                borderWidth: 1,
                cornerRadius: 12
              }
            }
          }
        });
      }

      // 4. Live Radar Flow Chart (if present)
      const radarCtx = document.getElementById('syscallRadarChart');
      if (radarCtx) {
        this.charts.radar = new Chart(radarCtx, {
          type: 'radar',
          data: {
            labels: ['epoll_wait', 'read', 'write', 'sendto', 'recvfrom', 'execve', 'connect', 'mmap', 'ptrace'],
            datasets: [
              {
                label: 'BASELINE',
                data: [90, 85, 80, 70, 70, 0, 0, 5, 0],
                backgroundColor: 'rgba(16, 185, 129, 0.15)',
                borderColor: '#10B981',
                pointBackgroundColor: '#10B981',
                borderWidth: 2,
              },
              {
                label: 'LIVE TRACE',
                data: [90, 85, 80, 70, 70, 0, 0, 5, 0],
                backgroundColor: 'rgba(239, 68, 68, 0.28)',
                borderColor: '#EF4444',
                pointBackgroundColor: '#EF4444',
                borderWidth: 2,
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              r: {
                angleLines: { color: 'rgba(255,255,255,0.08)' },
                grid: { color: 'rgba(255,255,255,0.08)' },
                pointLabels: { color: 'rgba(255,255,255,0.55)', font: { family: 'JetBrains Mono', size: 10 } },
                ticks: { display: false, max: 100, min: 0 }
              }
            },
            plugins: {
              legend: { display: false },
              tooltip: { backgroundColor: 'rgba(10,10,12,0.9)', titleColor:'#fff', bodyColor:'rgba(255,255,255,0.7)', borderColor:'rgba(255,255,255,0.1)', borderWidth:1, cornerRadius:12, padding:10 }
            }
          }
        });
      }
    },

    updateTimelineChart() {
      if (!this.charts.timeline) return;
      const chart = this.charts.timeline;
      // if we have real scores, rebuild labels+data from this.scores
      if (this.scores && this.scores.length) {
        const recent = this.scores.slice(0,7).reverse();
        chart.data.labels = recent.map(s => new Date(s.window_start).toLocaleTimeString().slice(0,5));
        chart.data.datasets[0].data = recent.map(s => s.total_score != null ? s.total_score : 0);
        // overlay current if newer
        chart.data.datasets[0].data[chart.data.datasets[0].data.length-1] = this.currentAnomalyScore;
        const n = chart.data.labels.length;
        chart.data.datasets[1].data = Array(n).fill(0.50);
        chart.data.datasets[2].data = Array(n).fill(0.75);
      } else {
        const idx = chart.data.datasets[0].data.length - 1;
        chart.data.datasets[0].data[idx] = this.currentAnomalyScore;
      }
      chart.update('none');
    },

    updateEvidenceLadderChart() {
      if (!this.charts.ladder) return;
      const chart = this.charts.ladder;
      chart.data.datasets[0].data = [
        this.evidenceCounts.package_present,
        this.evidenceCounts.deployed,
        this.evidenceCounts.runtime_observed,
        this.evidenceCounts.runtime_observed_and_port_published
      ];
      chart.update();
    },

    updateRadarChart(detectedProcess) {
      if (!this.charts.radar) return;
      const chart = this.charts.radar;
      let liveData = [92, 83, 81, 75, 72, 0, 0, 5, 0];
      if (detectedProcess) {
        liveData = [40, 30, 30, 20, 20, 95, 85, 90, 60];
      }
      chart.data.datasets[1].data = liveData;
      chart.update();
      if (detectedProcess) {
        setTimeout(() => {
          if (!this.isExecutingAttack && this.charts.radar) {
            this.charts.radar.data.datasets[1].data = [90, 85, 80, 70, 70, 0, 0, 5, 0];
            this.charts.radar.update();
          }
        }, 8000);
      }
    },

    // Interactive Attack Scenario Execution — wired to dashboard server + fallback simulation
    async triggerAttackScenario(scenario) {
      this.isExecutingAttack = true;
      this.logTerminal('SIMULATOR', `Triggering scenario: ${scenario.name} (${scenario.id})...`, 'info');
      this.showToast(`Launching ${scenario.name}...`, 'info');

      // helper to finalize client-side animation
      const finalizeClient = (data) => {
        this.logTerminal('EXEC', data.command || scenario.id, 'success');
        if (data.output) this.logTerminal('OUTPUT', String(data.output).slice(0, 400), 'info');
        if (data.detected_process) this.logTerminal('EBPF', `Kernel detected sys_enter_execve: ${data.detected_process}`, 'error');
        this.currentAnomalyScore = data.simulated_score || 0.84;
        this.currentScoreBand = this._bandForScore(this.currentAnomalyScore);
        this.scoreContributors = data.contributors || [{ token: data.detected_process || 'unknown', weight: 0.82 }];
        this.unseenTokens = data.unseen_tokens || [data.detected_process || 'unknown'];
        this.updateTimelineChart();
        this.updateRadarChart(data.detected_process);
        this.showToast(`Deviation Detected! Score spiked to ${this.currentAnomalyScore.toFixed(2)} [${this.currentScoreBand.toUpperCase()}]`, 'danger');
        // synthetic incident (will be merged with real ones on next poll)
        this.incidents.unshift({
          incident_id: 'inc-' + Math.random().toString(36).substring(2, 9),
          detection_run_id: 'demo-run-' + Date.now(),
          score_id: 'demo-score-' + Date.now(),
          image_digest: this.containers[0]?.image_digest || 'demo@sha256:'+'0'.repeat(64),
          title: `Automated detection: ${scenario.name}`,
          status: 'open',
          severity_score: scenario.id === 'cryptominer' ? 0.96 : 0.90,
          severity_level: 'critical',
          confidence_score: 0.95,
          confidence_level: 'high',
          anomaly_score: this.currentAnomalyScore,
          summary: `Automated detection: ${scenario.name} — rules ${ (scenario.rules||[]).join(', ')}`,
          findings: (scenario.rules||[]).map(r=> ({rule_id:r})),
          container_ids: [this.containers[0]?.container_id || 'demo'],
          first_seen_at: new Date().toISOString(),
          last_seen_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          target_container_name: this.containers[0]?.container_name || 'porygon-demo-test',
          recommended_action: 'pause_container',
          rules_triggered: scenario.rules || ['POR-DET-001', 'POR-DET-002']
        });
      };

      try {
        // Primary: dashboard server (port 3000) serves /api/demo/run-scenario and proxies backend
        // When served via gateway (port 8000), this path will 404 — fallback to client sim
        const res = await fetch('/api/demo/run-scenario', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario_id: scenario.id })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.success) {
            finalizeClient(data);
          } else {
            this.logTerminal('ERROR', data.error || 'Execution failed', 'error');
            this.showToast('Attack execution failed — falling back to trace replay', 'danger');
            // fallback sim
            finalizeClient({ command: scenario.id, detected_process: (scenario.rules||[]).join(','), simulated_score: 0.84, output: 'fallback trace', contributors: [], unseen_tokens: scenario.rules||[] });
          }
        } else if (res.status === 404) {
          // gateway deployment: simulate client-side
          this.logTerminal('SIMULATOR', 'Demo runner not reachable via gateway — replaying local trace', 'info');
          const simMap = {
            unseen_shell: { detected_process: '/bin/sh', simulated_score: 0.82, output: 'id\nuid=0(root) gid=0(root)' },
            shell_to_tool: { detected_process: '/usr/bin/wget', simulated_score: 0.91, output: 'Connecting to example.com' },
            cryptominer: { detected_process: 'xmrig', simulated_score: 0.96, output: 'cryptominer trace' },
            priv_esc: { detected_process: 'cat', simulated_score: 0.78, output: 'Uid: 0' },
            network_scan: { detected_process: 'nc', simulated_score: 0.86, output: 'network_discovery_probes_dispatched' },
            file_evasion: { detected_process: 'chmod', simulated_score: 0.79, output: 'file_integrity_test_complete' },
            defense_evasion: { detected_process: 'sh', simulated_score: 0.76, output: 'log_cleared' },
            juice_shop_toggle: { detected_process: 'node', simulated_score: 0.35, output: 'juice shop toggle (requires docker)' },
          };
          const sim = simMap[scenario.id] || { detected_process: scenario.id, simulated_score: 0.82, output: 'simulated' };
          finalizeClient({ command: sim.detected_process, detected_process: sim.detected_process, simulated_score: sim.simulated_score, output: sim.output, contributors: [{token: sim.detected_process, weight:0.82}], unseen_tokens: [sim.detected_process] });
        } else {
          const txt = await res.text();
          throw new Error(`HTTP ${res.status}: ${txt.slice(0,200)}`);
        }
      } catch (err) {
        this.logTerminal('ERROR', err.message, 'error');
        this.showToast('Demo runner unreachable — replayed synthetic trace', 'danger');
        // still show synthetic spike so UI not dead
        finalizeClient({ command: scenario.id, detected_process: scenario.id, simulated_score: 0.84, output: String(err).slice(0,200), contributors: [], unseen_tokens: [scenario.id] });
      } finally {
        this.isExecutingAttack = false;
        await this.pollLiveTelemetry();
      }
    },

    // Containment Action Approval — handles synthetic vs real incidents
    async approveContainment(incident, action) {
      const isSynthetic = incident.incident_id.startsWith('inc-');
      this.logTerminal('RESPONDER', `Operator approving ${action} for ${incident.target_container_name || incident.container_ids?.[0] || incident.incident_id}`, 'info');
      this.showToast(`Containment '${action}' requested`, isSynthetic ? 'warn' : 'info');

      if (isSynthetic) {
        // local-only: no backend call, just mutate UI
        incident.status = 'acknowledged';
        incident.approved_action = action;
        incident.updated_at = new Date().toISOString();
        this.logTerminal('RESPONDER', `Synthetic incident ${incident.incident_id} marked acknowledged locally (no backend)`, 'success');
        this.showToast(`Demo containment ${action} applied locally`, 'warn');
        return;
      }

      // Real incident: need to generate recommendation then approve via operator token
      try {
        if (!this.operatorToken) {
          const t = prompt('Operator token required for containment approval.\nPaste X-Porygon-Operator-Token from .env (PORYGON_OPERATOR_API_TOKEN):');
          if (!t) { this.showToast('Operator token required — approval cancelled', 'danger'); return; }
          this.operatorToken = t.trim();
        }

        // 1) Generate recommendation for this incident (idempotent)
        this.logTerminal('RESPONDER', `Generating recommendation for incident ${incident.incident_id}...`, 'info');
        const genRes = await this._apiFetch(`/operator/v1/incidents/${incident.incident_id}/response-recommendations`, { method: 'POST', headers: { 'Content-Type':'application/json' } });
        let recommendationId = null;
        if (genRes.ok) {
          const genData = await genRes.json();
          const recs = genData.recommendations || genData.items || [];
          // pick proposed or most recent matching allowed_actions includes desired action
          const match = recs.find(r => r.allowed_actions && r.allowed_actions.includes(action) && r.status==='proposed') || recs.find(r=> r.status==='proposed') || recs[0];
          recommendationId = match?.recommendation_id;
        } else {
          // if already generated, list existing
          const listRes = await fetch(`/api/v1/response-recommendations?incident_id=${incident.incident_id}`);
          if (listRes.ok) {
            const list = await listRes.json();
            const match = list.find(r=> r.incident_id===incident.incident_id && r.status==='proposed');
            recommendationId = match?.recommendation_id;
          }
          if (!recommendationId) {
            const txt = await genRes.text();
            throw new Error(`Recommendation generation failed ${genRes.status}: ${txt.slice(0,300)}`);
          }
        }

        if (!recommendationId) throw new Error('No recommendation available for approval');

        // 2) Approve with exact action
        this.logTerminal('RESPONDER', `Approving recommendation ${recommendationId} as ${action}...`, 'info');
        const approveRes = await this._apiFetch(`/operator/v1/response-recommendations/${recommendationId}/approve`, {
          method: 'POST',
          headers: { 'Content-Type':'application/json' },
          body: JSON.stringify({ actor: 'operator-dashboard', note: `Approved via dashboard as ${action}`, action_type: action, acknowledge_disruption: action !== 'observe_only' })
        });

        if (approveRes.ok) {
          const approved = await approveRes.json();
          incident.status = 'acknowledged';
          incident.approved_action = approved.approved_action || action;
          this.logTerminal('RESPONDER', `Containment approved — execution ${approved.recommendation_id} now pending responder`, 'success');
          this.showToast(`Containment ${action} approved — responder will execute`, 'success');
          await this.fetchIncidents();
        } else {
          const txt = await approveRes.text();
          if (approveRes.status === 401) {
            this.operatorToken = '';
            throw new Error('Operator token invalid — cleared, try again');
          }
          throw new Error(`Approve failed ${approveRes.status}: ${txt.slice(0,400)}`);
        }
      } catch (err) {
        console.warn('Containment approve error', err);
        this.logTerminal('ERROR', err.message, 'error');
        this.showToast(`Approval failed: ${err.message.slice(0,120)}`, 'danger');
        // do not mutate incident on failure
      }
    },

    // quick helper to clear stored token
    clearOperatorToken() {
      this.operatorToken = '';
      this.showToast('Operator token cleared', 'info');
    },

    // Pipeline trace: raw event -> deterministic rule match -> incident.
    // Pulls the exact ordered evidence chain for one incident from
    // GET /api/v1/incidents/{id}/timeline (backend main.py: get_incident_timeline),
    // which returns IncidentEvidence rows in sequence_no order — the same
    // rows the detection engine (backend/detection.py) recorded when a rule
    // matched. This is real data, not a mock: every node in the rendered
    // graph is a row that exists in Postgres right now for that incident.
    openPipelineForIncident(incident) {
      if (!incident || !incident.incident_id) return;
      this.activeTab = 'pipeline';
      this.pipelineIncidentId = incident.incident_id;
      this.fetchPipelineTimeline(incident.incident_id);
    },

    async fetchPipelineTimeline(incidentId) {
      if (!incidentId) { this.pipelineTimeline = []; return; }
      if (incidentId.startsWith('inc-')) {
        // synthetic demo incident has no backend row; show a clearly-labelled
        // synthetic trace instead of silently fetching nothing.
        this.pipelineTimeline = this._syntheticPipelineTrace(incidentId);
        this.pipelineError = '';
        return;
      }
      this.pipelineLoading = true;
      this.pipelineError = '';
      try {
        const res = await fetch(`/api/v1/incidents/${incidentId}/timeline`);
        if (!res.ok) throw new Error(`timeline fetch failed: ${res.status}`);
        const rows = await res.json();
        this.pipelineTimeline = rows;
      } catch (err) {
        console.warn('Pipeline timeline fetch error', err);
        this.pipelineError = err.message;
        this.pipelineTimeline = [];
      } finally {
        this.pipelineLoading = false;
      }
    },

    // Only used when a demo/simulator incident (client-side only, never
    // written to Postgres) is opened in the pipeline view, so the graph
    // still renders something coherent and is clearly marked as synthetic.
    _syntheticPipelineTrace(incidentId) {
      const inc = this.incidents.find(i => i.incident_id === incidentId) || {};
      const rules = inc.rules_triggered || ['POR-DET-002'];
      const now = new Date();
      return rules.map((ruleId, i) => ({
        evidence_id: `synthetic-${i}`,
        incident_id: incidentId,
        sequence_no: i,
        source_type: 'process_event',
        source_id: `synthetic-event-${i}`,
        rule_id: ruleId,
        occurred_at: new Date(now.getTime() - (rules.length - i) * 1000).toISOString(),
        summary: (this.rulesMeta[ruleId] || {}).description || 'Simulated evidence (not persisted)',
        _synthetic: true,
      }));
    },

    pipelineStageLabel(row) {
      if (row.source_type === 'process_event') return 'Falco → process_exec_events';
      if (row.source_type === 'runtime_event') return 'Falco → runtime_events';
      if (row.source_type === 'anomaly_score') return 'Scoring engine → anomaly_scores';
      if (row.source_type === 'derived_correlation') return 'Correlation window → derived match';
      return row.source_type || 'evidence';
    }
  }));
});

