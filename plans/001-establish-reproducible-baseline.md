# Plan 001: Establish a reproducible and honest repository baseline

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before continuing. If a STOP condition occurs, stop and report; do not improvise. When done, update Plan 001 in `plans/README.md`.
>
> **Drift check (run first)**: the repository was unborn when this plan was written. Run:
>
> `test "$(sha256sum Makefile README.md scripts/verify_phase7.sh scripts/verify_phase8.sh | sha256sum | cut -d' ' -f1)" = fdae6b9eb24cdacd4bb7d6fe26ebc9d42fb1cdaf8e91723fef405eee346d7228`
>
> Expected: exit 0. Any failure means the in-scope baseline changed; compare this plan with the live files and stop on a semantic mismatch.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx, tests, docs
- **Planned at**: `UNBORN`, workspace manifest `632c19fc254d`, 2026-08-16

## Why this matters

A clean checkout cannot currently follow the README: `.env.example` is missing, Compose cannot resolve its required environment, and there is no commit to identify the audited source. The main `make verify` command runs only Phase 8 even though the README presents Phases 1–8 as implemented. This plan creates a recoverable baseline, makes verification claims evidence-backed, and establishes the first trusted commit before research changes begin.

## Current state

- `Makefile:5-6` copies `.env.example`, which does not exist.
- `Makefile:29-30` maps `verify` only to `scripts/verify_phase8.sh`.
- `scripts/verify_phase8.sh:38-41` starts the stack and validates Phase 8, but never invokes the earlier cumulative verifier.
- `scripts/verify_phase7.sh:42-43` demonstrates the existing cumulative convention by invoking Phase 6 first. Phase 7 is disruptive and must remain explicit opt-in.
- `README.md:11-18` labels every phase “Implemented”, while `README.md:289` states the live acceptance tests were not run in the packaging environment.
- Git reports `No commits yet on main`; all 146 project files are untracked.
- Recoverable bootstrap-file copies exist outside the repository, but the implementation must not depend on those paths. Reconstruct and review the files in the repository itself.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Inventory Compose variables | `rg -o '\$\{[A-Z0-9_]+' compose.yaml | sed 's/^${//' | sort -u` | variable names only; no values |
| Shell syntax | `for f in scripts/*.sh; do bash -n "$f"; done` | exit 0 |
| Compose parse | `docker compose config --quiet` | exit 0 with a local `.env` |
| Unit suites | `make test` | all five service suites pass; at least the existing 69 tests |
| Safe aggregate | `make verify` | static, unit, Phase 1–6 safe-live, and Phase 8 gates recorded; disruptive response is not run |
| Worktree state | `git status --short` | empty except local ignored `.env`/runtime artifacts |

## Scope

**In scope**:

- `.gitignore` (create)
- `.dockerignore` (create)
- `.env.example` (create; placeholders and non-secret defaults only)
- `Makefile`
- `README.md`
- `scripts/verify_all.sh` (create)
- `scripts/verify_phase8.sh`
- `plans/README.md`

**Out of scope**:

- Runtime source under `backend/`, `collector/`, `telemetry/`, `responder/`, or `scanner/`.
- Enabling live response by default.
- Putting any usable password/token in a tracked file.
- Dependency upgrades, image changes, scoring changes, or refactors.
- Deleting volumes or existing artifacts.

## Git workflow

- Work on `main` only for this one plan because there is no commit from which a safe branch/worktree can be created.
- Use the already configured Git user identity only. Never add AI attribution, co-author trailers, or generated-by lines.
- Suggested commits: `chore: establish reproducible project baseline`, then `test: add cumulative verification evidence` if a second logical commit is useful.
- Do not push.

## Steps

### Step 1: Restore safe bootstrap files

Create `.gitignore` covering `.env`, virtual environments, Python caches/bytecode, pytest/Ruff/coverage caches, build artifacts, SQLite spools, and local experiment outputs. Create `.dockerignore` excluding Git metadata, `.env`, caches, virtual environments, bytecode, coverage, and build metadata.

Create `.env.example` from the variable names referenced by `compose.yaml` and service settings. Secret-bearing keys—including the PostgreSQL password and both Porygon tokens—must contain obvious replacement placeholders, never generated or usable values. Include documented non-secret local defaults for ports, queue limits, intervals, instance IDs, response mode (`disabled`), scanner limits, and Docker socket group/path. Keep internal and operator credentials distinct in the example.

**Verify**:

`test -f .gitignore && test -f .dockerignore && test -f .env.example && rg -n '^\.env$' .gitignore && ! git check-ignore .env.example`

Expected: exit 0; `.env` is ignored and `.env.example` is tracked.

`comm -23 <(rg -o '\$\{[A-Z0-9_]+' compose.yaml | sed 's/^${//' | sort -u) <(sed -n 's/^\([A-Z0-9_]*\)=.*/\1/p' .env.example | sort -u)`

Expected: no output. Review the inverse difference and remove obsolete example-only keys unless a service config directly documents them.

### Step 2: Make phase status evidence-based

Replace the binary README status column with separate columns for `Code`, `Static/unit`, `Live acceptance`, and `Experimental validation`. Preserve the historical 69-test artifact, but label it as packaged evidence rather than a result reproduced on this machine. Until the live scripts pass and artifacts are recorded, use `pending` rather than checkmarks. State plainly that Phase 9 is not implemented and that Phase 5 v1 is provisional pending Plan 004.

Do not weaken the existing claim boundary that a vulnerability finding or anomaly is not proof of exploitation/attack.

**Verify**:

`rg -n 'Static/unit|Live acceptance|Experimental validation|Phase 9' README.md && ! rg -n '\| [1-8] \|.*\| Implemented \|' README.md`

Expected: the multi-axis status vocabulary is present and the misleading binary rows are absent.

### Step 3: Create one honest aggregate verification entry point

Add `scripts/verify_all.sh` with strict shell mode and explicit named gates. It must:

1. reject a missing `.env`, placeholder secrets, equal internal/operator tokens, or unavailable prerequisites;
2. run non-mutating static/schema checks and all five unit suites;
3. invoke the cumulative safe Phase 1–6 live verifier;
4. invoke Phase 8 separately because it requires scanner egress;
5. never invoke Phase 7 response execution unless the operator runs a separately named Make target with live-response mode intentionally configured;
6. write a JSON evidence manifest containing UTC start/end, Git SHA (or `UNBORN` before the first commit), tool versions, each gate’s command/status, and artifact hashes—never environment values;
7. exit nonzero if a required gate fails and label intentionally unrun disruptive gates `skipped`, not `passed`.

Update the Makefile with explicit `verify-static`, `verify-unit`, `verify-live-safe`, `verify-scanner-live`, `verify-response-live`, and aggregate `verify` targets. `verify-response-live` must be visibly disruptive and must not be a dependency of `verify`.

**Verify**:

`bash -n scripts/verify_all.sh && make -n verify-response-live | rg 'verify_phase7.sh' && make -n verify | tee /tmp/porygon-make-verify.txt && ! rg 'verify_phase7.sh' /tmp/porygon-make-verify.txt`

Expected: shell syntax passes; only the explicit response target contains Phase 7.

### Step 4: Reproduce static/unit evidence, then create the initial commit

Create a local `.env` from the example, replace its secret placeholders with separately generated values, set the real Docker GID, and keep the file ignored. Run Compose parsing, shell syntax, and all unit suites. Do not start disruptive response. If Docker/BTF/egress are available, run the safe aggregate and retain its manifest; otherwise the README must continue to label those live gates pending.

Stage all intended repository source plus `plans/`; verify `.env` and runtime databases are not staged. Create the initial commit using the configured identity only.

**Verify**:

`git diff --cached --name-only | rg '^\.env$'` → expected exit 1/no output before committing.

`git log -1 --format='%an <%ae>%n%B'` → configured user identity and commit message only; no AI/co-author/generated-by text.

`git status --short` → empty except ignored local runtime artifacts.

## Test plan

- Exercise missing `.env`, placeholder secret, equal-token, missing-command, static failure, unit failure, safe-live failure, scanner failure, and skipped-response manifest paths. Use a temporary copy or command shims; do not corrupt the working `.env`.
- Confirm the manifest never contains the literal values of any environment variable whose name includes `TOKEN`, `PASSWORD`, `SECRET`, or `KEY`.
- Run all existing service tests; the pre-change baseline is 69 tests.

## Done criteria

- [ ] Bootstrap from `.env.example` works without relying on files outside the repository.
- [ ] `.env` is ignored and no secret value is tracked or printed in evidence.
- [ ] README distinguishes implementation, static/unit verification, live acceptance, and experimental validation.
- [ ] `make verify` is cumulative for required non-disruptive gates and never silently runs Phase 7.
- [ ] All existing tests pass and the verification manifest records exact gate status.
- [ ] An initial commit exists under only the configured Git identity, with no AI attribution.
- [ ] No runtime source file was modified.
- [ ] Plan 001 is marked `DONE` in `plans/README.md`.

## STOP conditions

- Any bootstrap copy contains a real credential or a value that may be a real credential.
- Docker is unavailable and a live gate is about to be labelled passed instead of pending/skipped.
- Safe verification unexpectedly performs a pause/stop operation or requires `PORYGON_RESPONSE_EXECUTION_MODE=live`.
- Existing unit tests fail twice for reasons unrelated to bootstrap/verification changes.
- The staged set contains `.env`, a database/spool, private key, token, or unrelated user file.

## Maintenance notes

Reviewers should scrutinize claim wording and the boundary between safe and disruptive verification. Plan a later dependency-lock/image-digest refresh workflow; do not mix it into this baseline. After this plan, all subsequent work should use `codex/<plan-number>-<slug>` branches from the initial commit.

