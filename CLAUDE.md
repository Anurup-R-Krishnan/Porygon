# Porygon

Docker-first runtime security research platform: eBPF/Falco kernel telemetry + Docker
lifecycle events → behavioural anomaly baselines (Jensen-Shannon distance) → deterministic
detection/incident correlation → human-approved containment → SBOM/vuln intelligence
(Trivy, EPSS, CISA KEV). See [README.md](README.md) for full architecture and
[PORYGON_EXPLAINED.md](PORYGON_EXPLAINED.md) for a narrative walkthrough.

## Services (each an independent Python package under its own dir)

- `backend/` — FastAPI + SQLAlchemy + Alembic, the only service with a DB connection.
- `collector/` — reads `/var/run/docker.sock` (ro), ships lifecycle events to backend.
- `telemetry/` — parses Falco JSONL syscall stream, ships to backend.
- `responder/` — executes human-approved containment actions via the Docker socket.
- `scanner/` — Trivy-based SBOM/vuln scanning, cross-references EPSS/KEV feeds.
- `gateway/` — nginx reverse proxy, the only ingress-network component.
- `falco/porygon_rules.yaml` — deterministic detection rules (validated by `falco --validate`).
- `experiments/` — reproducible experiment harness (`python3 -m experiments.run ...`),
  stdlib-only and run on the host, not in a container: `artifacts.py` (immutable artifact
  contract, hashing, split-leakage checks), `context.py` (runtime-context fingerprint),
  `real.py` (real-container pilot runner), `run.py` (CLI: smoke / pilot / replay /
  confirmatory). Evidence classes are not interchangeable — smoke is synthetic, pilot is
  real but `research_eligible: false`, and confirmatory is refused until the protocol is
  frozen. See `docs/EXPERIMENT_ACCEPTANCE.md`.
- `scripts/` — operator CLI (`porygon_baseline.py`, `porygon_scan.py`, `porygon_detect.py`,
  `porygon_respond.py`, `porygon_score.py`) and `verify_*.sh` gate scripts.
- `docs/` — per-milestone architecture and acceptance docs and the frozen `RESEARCH_PROTOCOL_V1.md`.
- `plans/` — numbered implementation plans; `plans/README.md` tracks status/order. Read a
  plan fully, run every gate, and honor STOP conditions before touching related code.

Every service has its own `pyproject.toml`, `src/`, `tests/`, and Dockerfile — they are not
a shared package and don't share a virtualenv. `pythonpath = ["src"]`, `testpaths = ["tests"]`.

## Setup

```bash
make init   # copies .env.example -> .env, generates local secrets, chmod 0600
make build  # docker compose build backend collector telemetry responder scanner
make up     # docker compose up --detach --build --wait
```

`.env` is git-ignored and holds real local credentials — never read, print, or commit it;
`.env.example` is the safe template. `PORYGON_RESPONSE_EXECUTION_MODE` must stay `disabled`
for anything except the explicit disruptive gate below.

## Verification gates (`scripts/verify_all.sh`, wired through `make`)

- `make verify-static` — ruff (`E4,E7,E9,F`) locally via `.venv`, compose config validation,
  AST/TOML/YAML parse + invariant checks (network isolation, digest-pinned images, Falco
  rule shape), builds backend, checks OpenAPI schema size, Alembic `--sql` dry run, Falco
  rule validation. Fast, no live containers.
- `make verify-unit` — runs `pytest -q` inside a built container per service
  (`docker compose run --rm --no-deps --build --entrypoint pytest <service> -q`), then the
  stdlib-only `experiments/tests` on the host.
- `make verify-live-safe` — `verify_phase2.sh` + `verify_phase6.sh`, needs the stack up.
- `make verify-scanner-live` — `verify_phase8.sh`, needs network egress to threat feeds.
- `make verify-experiment-live` — `verify_phase9.sh`, needs the stack up. Non-disruptive:
  pulls a pinned digest, exercises one disposable labelled container, and asserts the
  canaries reconcile from the generator through Falco to PostgreSQL with zero measured loss.
- `make verify` — `all`, runs every non-disruptive gate above.
- `make verify-response-live` — **DISRUPTIVE**: requires
  `PORYGON_RESPONSE_EXECUTION_MODE=live` and may pause/stop the disposable containment target.
  Never part of `make verify`; never run without explicit user request.

Run `make verify-static` and the relevant service's unit tests after any code change before
calling work done. Prefer the narrowest gate that covers the change; only run `make verify`
end-to-end when asked or before a milestone.

## Conventions

- Ruff is the only configured linter/formatter gate (`ruff check --select E4,E7,E9,F`); no
  repo-wide `[tool.ruff]` config exists, so don't assume line-length/style rules beyond that.
- Tests run inside Docker per service, not against a shared local install — don't `pip
  install` service deps globally; use `docker compose run --rm --no-deps --build --entrypoint
  pytest <service>` or point at the service's own `.venv`/toolchain if one exists.
- Digest-pinned images and strict network segregation (`porygon_ingress` /
  `porygon_internal` / `porygon_egress`) are load-bearing security invariants checked by
  `verify-static` — don't relax them without updating the corresponding assertion.
- This is a research platform with frozen protocol docs (`docs/RESEARCH_PROTOCOL_V1.md`,
  `plans/README.md` status table). Changes to scoring/profiling semantics should reconcile
  with the active plan in `plans/` rather than diverging silently.
