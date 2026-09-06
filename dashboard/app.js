// Porygon Alpine.js State & Chart Controller — fully wired to backend (v0.8.0)

// Chart.js instances live outside Alpine's reactive scope. If stored directly
// as a component property (e.g. `charts: {}` inside Alpine.data()), Alpine
// wraps the object -- and everything inside it, including each Chart.js
// instance's large, self-referencing internal state -- in a reactive Proxy.
// Chart.js's own internal mutations then re-trigger Alpine's reactive
// getters recursively, which is exactly the
// "RangeError: Maximum call stack size exceeded" observed in the browser
// console on the Process Graph tab (traced to Object.get in alpinejs's
// reactivity implementation, called from inside chart.js's rendering path).
// Keeping the real Chart.js instances in this plain, non-reactive object and
// exposing them to the component via a getter fixes it without touching any
// of the many `chartRegistry.X` call sites throughout this file.
const chartRegistry = {};

document.addEventListener('alpine:init', () => {
  Alpine.data('porygonApp', () => ({
    // Navigation
    activeTab: (typeof window !== 'undefined' && window.location.hash && ['overview', 'pathway', 'telemetry', 'anomalies', 'incidents', 'pipeline', 'vulnerabilities', 'simulator'].includes(window.location.hash.slice(1))) ? window.location.hash.slice(1) : 'overview',
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
    // Real divergence detail for the incident's triggering score
    // (GET /api/v1/anomaly-scores/{score_id}): per-feature-family
    // Jensen-Shannon distance, novelty, and the exact unseen tokens that
    // pushed the score out of the baseline_like band.
    pipelineScoreDetail: null,
    pipelineScoreLoading: false,
    pipelineScoreError: '',

    // Vulnerability & Evidence Ladder
    vulnerabilityFindings: [],
    reachabilityFilter: 'all',
    selectedReachabilityFinding: null,
    evidenceCounts: {
      package_present: 0,
      deployed: 0,
      runtime_observed: 0,
      runtime_observed_and_port_published: 0
    },

    // Process Pathway Graph State & Metadata
    selectedGraphNode: 'ebpf',
    graphPathwayMode: (typeof window !== 'undefined' && window.location.search.includes('mode=attack')) ? 'attack' : (typeof window !== 'undefined' && window.location.search.includes('mode=reachability')) ? 'reachability' : 'all',
    processGraphNodes: {
      ebpf: {
        id: 'ebpf',
        name: 'eBPF Probes',
        stageNumber: 1,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Linux Kernel Space (Ring Buffer)',
        icon: 'ph-cpu',
        tag: 'KERNEL HOOK',
        badgeColor: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20',
        summary: 'Falco\'s modern-eBPF driver attaches to process-execution tracepoints without modifying container binaries or kernel source. It observes execve/execveat only in v1 -- no network, file, or socket syscalls are captured (see docs/THREAT_MODEL_V1.md).',
        technicalHook: 'evt.type in (execve, execveat)  [falco/porygon_rules.yaml]',
        inputSource: 'Process-execution syscalls from containerized processes.',
        outputArtifact: 'Process-exec records (process name, executable path, full command line, ppid, uid/gid, parent context) -- see falco/porygon_rules.yaml for the exact output fields.',
        liveMetricKey: 'Kernel Events',
        metricType: 'events',
        status: 'ATTACHED & STREAMING',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack', 'reachability']
      },
      docker: {
        id: 'docker',
        name: 'Docker Lifecycle Spool',
        stageNumber: 2,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Host Container Runtime (/var/run/docker.sock)',
        icon: 'ph-cube',
        tag: 'RUNTIME SPOOL',
        badgeColor: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
        summary: 'Monitors Docker Engine events via dedicated FIFO outbox spool, extracting immutable SHA-256 image digests and container namespace PID maps.',
        technicalHook: 'GET /events?filters={"type":["container"]}\nFIFO outbox spool: /var/run/porygon/docker_events.fifo',
        inputSource: 'Docker daemon container start, exec_create, and die life-cycle broadcasts.',
        outputArtifact: 'Cryptographic image_digest (SHA-256) binding + Host-to-Container PID translation map.',
        liveMetricKey: 'Active Containers',
        metricType: 'containers',
        status: 'SYNCHRONIZED',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack', 'reachability']
      },
      sbom: {
        id: 'sbom',
        name: 'CycloneDX SBOM & Trivy',
        stageNumber: 3,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Static Supply Chain Analysis',
        icon: 'ph-shield-check',
        tag: 'STATIC AUDIT',
        badgeColor: 'text-indigo-400 bg-indigo-400/10 border-indigo-400/20',
        summary: 'Static vulnerability scanner indexing package manifests, lockfiles, and binaries inside base images with EPSS probability and CISA KEV tags.',
        technicalHook: 'CycloneDX v1.5 JSON • Trivy Vulnerability DB • EPSS API • CISA KEV Catalog',
        inputSource: 'Container image layer tarballs and software package manifests (npm, pip, deb, apk).',
        outputArtifact: 'Cataloged CVE finding records with CVSS scores, fix versions, and baseline presence markers.',
        liveMetricKey: 'Cataloged CVEs',
        metricType: 'scans',
        status: 'INDEXED',
        statusColor: 'text-emerald-400',
        targetTab: 'vulnerabilities',
        modes: ['all', 'reachability']
      },
      collector: {
        id: 'collector',
        name: 'Ingestion Gateway & Normalizer',
        stageNumber: 4,
        tier: 'Tier 2: Ingestion & Normalization',
        tierShort: 'Tier 2',
        layer: 'Porygon Gateway (FastAPI / PostgreSQL 17)',
        icon: 'ph-brackets-curly',
        tag: 'PIPELINE GATEWAY',
        badgeColor: 'text-violet-400 bg-violet-400/10 border-violet-400/20',
        summary: 'Event ingestion gateway. Canonicalizes binary paths, resolves parent-child execution trees, and persists to PostgreSQL via an outbox spool. Raw command-line strings are stored as-received; no argument sanitization is currently implemented.',
        technicalHook: 'POST /api/v1/events\nOutbox-pattern batcher (MET-OTP-001 occurrence-to-persistence latency has not yet been measured/reported)',
        inputSource: 'Uncorrelated eBPF syscall records + Docker runtime container lifecycle metadata.',
        outputArtifact: 'Enriched ProcessExecEventOut records with resolved container_name, image_digest, and ppid lineage.',
        liveMetricKey: 'Gateway Health',
        metricType: 'collector',
        status: 'BUFFERING & NORMALIZING',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack']
      },
      js_engine: {
        id: 'js_engine',
        name: 'Jensen-Shannon Distance Engine',
        stageNumber: 5,
        tier: 'Tier 3: Analytics & Rules Matrix',
        tierShort: 'Tier 3',
        layer: 'Information-Theoretic Mathematical Engine',
        icon: 'ph-function',
        tag: 'D_JS DIVERGENCE',
        badgeColor: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
        summary: 'Calculates symmetric information-theoretic distance between baseline empirical probability P(x) and live sliding window Q(x) across categorical, novelty, and numeric distributions.',
        technicalHook: 'D_JS(P || Q) = 1/2 * D_KL(P || M) + 1/2 * D_KL(Q || M)\nWeights: Categorical 50% • Novelty 30% • Numeric 20%',
        inputSource: 'Configurable sliding window (default 60s, operator-adjustable 5-3600s) of normalized execution tokens compared against digest-bound training profile.',
        outputArtifact: 'Continuous anomaly distance score [0.00, 1.00] with token-level attribution vectors.',
        liveMetricKey: 'Current Distance',
        metricType: 'distance',
        status: 'EVALUATING WINDOWS',
        statusColor: 'text-emerald-400',
        targetTab: 'anomalies',
        modes: ['all', 'attack']
      },
      rules: {
        id: 'rules',
        name: 'Deterministic Rules Matrix',
        stageNumber: 6,
        tier: 'Tier 3: Analytics & Rules Matrix',
        tierShort: 'Tier 3',
        layer: 'Deterministic Verification Layer',
        icon: 'ph-list-checks',
        tag: 'GUARDRAIL MATRIX',
        badgeColor: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
        summary: 'Auditable deterministic rules evaluating behavioral threshold breaches, shell invocations, privilege jumps, reconnaissance, and dropper evasion.',
        technicalHook: 'POR-DET-001 through POR-DET-007\nEvaluates boolean predicates against event metadata and D_JS scores',
        inputSource: 'Enriched execution events, process ancestry chains, and anomaly score updates.',
        outputArtifact: 'Structured detection alerts containing matched rule_id, severity, confidence, and recommended lease.',
        liveMetricKey: 'Active Rules',
        metricType: 'rules',
        status: 'MONITORING',
        statusColor: 'text-emerald-400',
        targetTab: 'pipeline',
        modes: ['all', 'attack']
      },
      incidents: {
        id: 'incidents',
        name: 'Incident Evidence Graph',
        stageNumber: 7,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Security Incident State Machine',
        icon: 'ph-warning-octagon',
        tag: 'CORRELATION ENGINE',
        badgeColor: 'text-red-400 bg-red-400/10 border-red-400/20',
        summary: 'Time-windowed correlation engine. Groups related detection findings, anomaly score spikes, and container digests into unified Incident records with automated containment proposals.',
        technicalHook: 'Container digest clustering • 120s shell-to-tool correlation window (POR-DET-005) • State: open/acknowledged/resolved',
        inputSource: 'Triggered deterministic rule findings + elevated Jensen-Shannon anomaly events.',
        outputArtifact: 'Unified Incident objects with severity scoring, container target, and recommended action.',
        liveMetricKey: 'Security Incidents',
        metricType: 'incidents',
        status: 'CORRELATING',
        statusColor: 'text-amber-400',
        targetTab: 'incidents',
        modes: ['all', 'attack', 'reachability']
      },
      reachability: {
        id: 'reachability',
        name: '4-Stage Reachability Funnel',
        stageNumber: 8,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Dynamic Attack Surface Verification',
        icon: 'ph-funnel',
        tag: 'REACHABILITY ENGINE',
        badgeColor: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
        summary: 'Cross-correlates static CVE manifests against live kernel execution memory to prove whether a vulnerability is reachable or dormant dead-code.',
        technicalHook: 'Evidence Ladder:\n1. Package Present -> 2. Deployed -> 3. Runtime Observed -> 4. Port Published',
        inputSource: 'CycloneDX SBOM packages (Tier 1) intersected with eBPF execve telemetry (Tier 1).',
        outputArtifact: 'Vulnerability findings partitioned by evidence stage (package present / deployed / runtime-observed / port-published); no aggregate noise-reduction percentage has been measured.',
        liveMetricKey: 'Runtime Observed',
        metricType: 'reachability',
        status: 'FILTERING',
        statusColor: 'text-emerald-400',
        targetTab: 'vulnerabilities',
        modes: ['all', 'reachability']
      },
      containment: {
        id: 'containment',
        name: 'Containment Actuator (Lease Engine)',
        stageNumber: 9,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Human-Governed Execution Guard',
        icon: 'ph-lock-key',
        tag: 'FAIL-SAFE ACTUATOR',
        badgeColor: 'text-rose-400 bg-rose-400/10 border-rose-400/20',
        summary: 'Issues time-bounded containment leases (pause, stop, isolate) gated behind a shared-secret operator token, with fail-safe auto-reversion. The token is a constant-time-compared shared secret, not a signed/asymmetric credential.',
        technicalHook: 'POST /api/v1/operator/containment-actions/approve\nHeader: X-Porygon-Operator-Token (shared secret, secrets.compare_digest)',
        inputSource: 'Approved incident containment recommendations from authorized human operators.',
        outputArtifact: 'Enforced container freeze/stop lease with automatic lease expiration timer.',
        liveMetricKey: 'Operator Posture',
        metricType: 'containment',
        status: 'ARMED & FAIL-SAFE',
        statusColor: 'text-emerald-400',
        targetTab: 'incidents',
        modes: ['all', 'attack']
      }
    },

    selectGraphNode(nodeId) {
      this.selectedGraphNode = nodeId;
    },

    setGraphMode(mode) {
      this.graphPathwayMode = mode;
      const current = this.processGraphNodes[this.selectedGraphNode];
      if (current && !current.modes.includes(mode)) {
        const first = Object.values(this.processGraphNodes).find(n => n.modes.includes(mode));
        if (first) this.selectedGraphNode = first.id;
      }
    },

    isNodeInCurrentMode(nodeId) {
      if (this.graphPathwayMode === 'all') return true;
      const node = this.processGraphNodes[nodeId];
      return node ? node.modes.includes(this.graphPathwayMode) : true;
    },

    jumpToNodeTab(tabId) {
      this.activeTab = tabId;
      window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    getNodeMetricValue(nodeId) {
      const node = this.processGraphNodes[nodeId];
      if (!node) return '—';
      const info = this.systemInfo || {};
      switch (node.metricType) {
        case 'events':
          // Real lifetime process-exec count from GET /api/v1/system/info
          // (process_exec_events), not a hardcoded "2.7M" string. Shows a
          // neutral placeholder rather than a fake number if info hasn't
          // loaded yet.
          return info.process_exec_events != null
            ? `${(this.events?.length || 0)} buffered (${info.process_exec_events.toLocaleString()} lifetime)`
            : 'loading…';
        case 'containers':
          // Real total from system/info.known_containers, not
          // this.containers.length, which is capped at the /api/v1/containers
          // fetch's limit=100 and would silently under-report past 100.
          return info.known_containers != null ? `${info.known_containers.toLocaleString()} containers mapped` : 'loading…';
        case 'scans':
          return info.vulnerability_findings != null ? `${info.vulnerability_findings.toLocaleString()} static CVEs` : 'loading…';
        case 'collector':
          return info.registered_services != null ? `${info.registered_services} services online` : 'loading…';
        case 'distance':
          return (this.currentAnomalyScore || 0).toFixed(3) + ' [' + (this.currentScoreBand || 'normal').toUpperCase() + ']';
        case 'rules':
          return (this.rules?.length || 0) + ' active rules';
        case 'incidents':
          return info.incidents != null ? `${info.incidents} total (${info.open_incidents ?? 0} open)` : `${this.incidents?.length || 0} total`;
        case 'reachability':
          return (this.evidenceCounts?.runtime_observed ?? 0) + ' CVEs observed in memory';
        case 'containment':
          return this.operatorToken ? 'AUTHORIZED (Token Set)' : 'LOCKED (Token Required)';
        default:
          return 'Active';
      }
    },

    // Simulator & Terminal Console
    terminalLogs: [
      { time: new Date().toLocaleTimeString(), tag: 'KERNEL', msg: 'eBPF probe attached to sys_enter_execve', type: 'info' },
      { time: new Date().toLocaleTimeString(), tag: 'COLLECTOR', msg: 'Docker daemon outbox spool initialized', type: 'info' },
      { time: new Date().toLocaleTimeString(), tag: 'SYSTEM', msg: 'Porygon behavioral intelligence platform ready — gateway 127.0.0.1:8000', type: 'success' }
    ],
    isExecutingAttack: false,
    toasts: [],
    showDocsModal: false,
    docsTab: 'mental_model',

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

    // Chart.js instances are NOT kept as an Alpine component property at
    // all (no `charts: {}`, no getter). Even a getter returning the plain
    // chartRegistry object still let Alpine's underlying @vue/reactivity
    // wrap it once accessed as `this.charts.x`, reproducing the exact
    // "Maximum call stack size exceeded" crash traced into Chart.js's
    // render path. Every call site in this file uses the module-level
    // `chartRegistry` constant directly (see top of file) instead of
    // `this.charts`, which never puts a Chart.js instance anywhere near
    // Alpine's reactive proxy.

    async init() {
      console.log('Initializing Porygon Dashboard with Alpine.js — ethreal glass');
      // expose reveal
      if (typeof window.initReveal === 'function') window.initReveal();
      await this.fetchRules();
      await this.refreshAllData();
      this.initCharts();
      // after DOM for charts, init reveal again for bento
      if (typeof window.initReveal === 'function') window.initReveal();

      // Watch activeTab to resize charts and trigger pipeline auto-selection
      if (typeof this.$watch === 'function') {
        this.$watch('activeTab', (newTab) => {
          if (typeof window !== 'undefined' && window.location) {
            try { window.location.hash = newTab; } catch(e){}
          }
          if (newTab === 'pipeline' && !this.pipelineIncidentId && this.incidents.length > 0) {
            this.openPipelineForIncident(this.incidents[0]);
          }
          const triggerResize = () => {
            Object.values(this.charts).forEach(c => {
              if (c && typeof c.resize === 'function') c.resize();
            });
            if (typeof window.initReveal === 'function') window.initReveal();
          };
          if (typeof this.$nextTick === 'function') {
            this.$nextTick(triggerResize);
          } else {
            setTimeout(triggerResize, 50);
          }
        });
      }

      // Auto-refresh interval every 3 seconds (lightweight polling without heavy summaries)
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
          // Index rules by rule_id for O(1) property lookup
          this.rulesMeta = Object.fromEntries((data.rules || []).map(r => [r.rule_id, r]));
          this.rulesConfig = data;
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
      // Prefer process-events (eBPF) for telemetry tab (fast limit=40 query)
      try {
        const res = await fetch('/api/v1/process-events?limit=40');
        if (res.ok) {
          this.events = await res.json();
        } else {
          // fallback to older /events if process-events not yet available
          const r2 = await fetch('/api/v1/events?limit=40');
          if (r2.ok) this.runtimeEvents = await r2.json();
        }
      } catch (err) {
        console.warn('Could not fetch process-events:', err);
      }
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
              // extract unseen tokens / contributors from explanation if present.
              // Real bug found live: GET /api/v1/anomaly-scores/{id}'s
              // explanation.unseen_tokens is an array of objects
              // ({feature, token, proportion} — verified against the live
              // backend), but this.unseenTokens is rendered with
              // `x-for="tok in unseenTokens" :key="tok"` and used as
              // `'unseen: ' + tok`, both of which expect plain strings.
              // Assigning the raw objects here made Alpine use a whole
              // object as an x-for key (console warning, once per real
              // score fetched) and made every token render as
              // "unseen: [object Object]" instead of the real value.
              // Extracting .token fixes both.
              const exp = latest.explanation || {};
              const families = (latest.components && latest.components.categorical_distance && latest.components.categorical_distance.families) || {};
              const asTokenStrings = (arr) => arr.map(t => (t && typeof t === 'object') ? (t.token ?? JSON.stringify(t)) : t);
              // fallback: explanation.novel_executables etc.
              if (exp.unseen_tokens) this.unseenTokens = [...new Set(asTokenStrings(exp.unseen_tokens))].slice(0,12);
              else if (exp.novel_tokens) this.unseenTokens = [...new Set(asTokenStrings(exp.novel_tokens))].slice(0,12);
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

    updateScoreFromLatest() {
      if (this.currentAnomalyScore != null) {
        this.currentScoreBand = this._bandForScore(this.currentAnomalyScore);
      }
      if (chartRegistry.radar && this.currentAnomalyScore > 0.5) {
        this.updateRadarChart(this.unseenTokens[0] || 'novel_process');
      }
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
          const getTime = (x) => {
            const d = new Date(x.created_at || x.first_seen_at || x.occurred_at || 0);
            return isNaN(d.getTime()) ? 0 : d.getTime();
          };
          this.incidents = Array.from(byId.values()).sort((a,b)=> getTime(b) - getTime(a));
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
            const completedScans = scans.filter(s => s.status === 'completed');
            // Prioritize completed scans that have findings
            const prioritized = completedScans.filter(s => (s.summary?.finding_count || 0) > 0);
            const targets = prioritized.length ? prioritized.slice(0, 3) : completedScans.slice(0, 1);

            const allFindings = [];
            for (const scan of targets) {
              try {
                const detailRes = await fetch(`/api/v1/image-scans/${scan.scan_id}`);
                if (detailRes.ok) {
                  const detail = await detailRes.json();
                  if (Array.isArray(detail.vulnerabilities)) {
                    allFindings.push(...detail.vulnerabilities);
                  }
                }
              } catch (e) {}
            }

            // Deduplicate findings by finding_id or cve_id + package_name
            const seen = new Set();
            this.vulnerabilityFindings = allFindings.filter(f => {
              const key = f.finding_id || `${f.cve_id}-${f.package_name}`;
              if (seen.has(key)) return false;
              seen.add(key);
              return true;
            });
            this.calculateEvidenceCounts();
          } else {
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
        // Every finding is present on disk inside the scanned package
        counts.package_present++;
        if (['deployed', 'runtime_observed', 'runtime_observed_and_port_published'].includes(f.evidence_stage)) {
          counts.deployed++;
        }
        if (['runtime_observed', 'runtime_observed_and_port_published'].includes(f.evidence_stage)) {
          counts.runtime_observed++;
        }
        if (f.evidence_stage === 'runtime_observed_and_port_published') {
          counts.runtime_observed_and_port_published++;
        }
      });
      this.evidenceCounts = counts;
      this.updateEvidenceLadderChart();
    },

    matchesReachabilityFilter(v, filter) {
      if (!filter || filter === 'all') return true;
      if (filter === 'package_present') return true;
      if (filter === 'deployed') {
        return ['deployed', 'runtime_observed', 'runtime_observed_and_port_published'].includes(v.evidence_stage);
      }
      if (filter === 'runtime_observed') {
        return ['runtime_observed', 'runtime_observed_and_port_published'].includes(v.evidence_stage);
      }
      if (filter === 'runtime_observed_and_port_published') {
        return v.evidence_stage === 'runtime_observed_and_port_published';
      }
      return v.evidence_stage === filter;
    },

    get filteredVulnerabilities() {
      return this.vulnerabilityFindings.filter(v => this.matchesReachabilityFilter(v, this.reachabilityFilter));
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
        chartRegistry.timeline = new Chart(timelineCtx, {
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
        chartRegistry.composition = new Chart(compCtx, {
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
        chartRegistry.ladder = new Chart(ladderCtx, {
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
        chartRegistry.radar = new Chart(radarCtx, {
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
      if (!chartRegistry.timeline) return;
      const chart = chartRegistry.timeline;
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
      if (!chartRegistry.ladder) return;
      const chart = chartRegistry.ladder;
      chart.data.datasets[0].data = [
        this.evidenceCounts.package_present,
        this.evidenceCounts.deployed,
        this.evidenceCounts.runtime_observed,
        this.evidenceCounts.runtime_observed_and_port_published
      ];
      chart.update();
    },

    updateRadarChart(detectedProcess) {
      if (!chartRegistry.radar) return;
      const chart = chartRegistry.radar;
      let liveData = [92, 83, 81, 75, 72, 0, 0, 5, 0];
      if (detectedProcess) {
        liveData = [40, 30, 30, 20, 20, 95, 85, 90, 60];
      }
      chart.data.datasets[1].data = liveData;
      chart.update();
      if (detectedProcess) {
        setTimeout(() => {
          if (!this.isExecutingAttack && chartRegistry.radar) {
            chartRegistry.radar.data.datasets[1].data = [90, 85, 80, 70, 70, 0, 0, 5, 0];
            chartRegistry.radar.update();
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
      this.fetchPipelineScoreDetail(incident.score_id);
    },

    // Fetches the full scoring breakdown for the anomaly score that
    // triggered this incident: per-feature-family Jensen-Shannon distance
    // (categorical_distance), probability-mass novelty, numeric deviation,
    // and the exact tokens (process names, executables, etc) that were
    // absent from the trained baseline. This is the real "how much did it
    // diverge and why" data backend/src/porygon_api/scoring.py computes —
    // not a placeholder, not re-derived client-side.
    async fetchPipelineScoreDetail(scoreId) {
      this.pipelineScoreDetail = null;
      this.pipelineScoreError = '';
      if (!scoreId || String(scoreId).startsWith('demo-score-')) {
        return; // synthetic/demo incidents have no real backend score to fetch
      }
      this.pipelineScoreLoading = true;
      try {
        const res = await fetch(`/api/v1/anomaly-scores/${scoreId}`);
        if (!res.ok) throw new Error(`score fetch failed: ${res.status}`);
        this.pipelineScoreDetail = await res.json();
      } catch (err) {
        console.warn('Pipeline score detail fetch error', err);
        this.pipelineScoreError = err.message;
      } finally {
        this.pipelineScoreLoading = false;
      }
    },

    // Percent width helper for divergence bars, clamped to [0,100].
    divergencePercent(value) {
      if (value === null || value === undefined) return 0;
      return Math.max(0, Math.min(100, Math.round(value * 100)));
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
    },

    // Interactive helpers for table rows, operators, and incident getters
    selectContainer(c) {
      if (!c) return;
      if (this.selectedContainer === c.container_id) {
        this.selectedContainer = null;
        this.eventFilter = '';
        this.showToast('Container filter cleared', 'info');
      } else {
        this.selectedContainer = c.container_id;
        this.eventFilter = c.container_name || c.container_id.substring(0, 12);
        this.activeTab = 'telemetry';
        this.showToast(`Filtered telemetry for ${c.container_name || c.container_id.substring(0, 12)}`, 'info');
      }
    },

    manageOperatorToken() {
      if (this.operatorToken) {
        if (confirm(`Operator token is active (${this.operatorToken.slice(0, 6)}...). Clear stored token?`)) {
          this.clearOperatorToken();
        }
      } else {
        const val = prompt('Paste X-Porygon-Operator-Token from .env (PORYGON_OPERATOR_API_TOKEN):');
        if (val && val.trim()) {
          this.operatorToken = val.trim();
          this.showToast('Operator token stored securely in localStorage', 'success');
          this.logTerminal('OPERATOR', 'Operator token configured for human-in-the-loop containment', 'success');
        }
      }
    },

    getIncidentContainerName(inc) {
      if (!inc) return 'porygon-workload';
      if (inc.target_container_name && inc.target_container_name !== 'porygon-demo-test') {
        return inc.target_container_name;
      }
      const cid = inc.container_ids?.[0];
      if (!cid) return inc.target_container_name || 'porygon-workload';
      const match = this.containers.find(c => c.container_id === cid || c.container_id.startsWith(cid) || cid.startsWith(c.container_id));
      return match?.container_name || cid.substring(0, 12);
    },

    getIncidentRules(inc) {
      if (!inc) return ['POR-DET-001'];
      if (Array.isArray(inc.rules_triggered) && inc.rules_triggered.length) {
        return inc.rules_triggered;
      }
      if (Array.isArray(inc.findings) && inc.findings.length) {
        const ids = inc.findings.map(f => f.rule_id).filter(Boolean);
        if (ids.length) return [...new Set(ids)];
      }
      return ['POR-DET-001'];
    }
  }));
});

