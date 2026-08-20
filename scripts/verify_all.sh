#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-all}"
case "$MODE" in
  all|static|unit|live-safe|scanner-live) ;;
  *)
    printf 'Usage: %s [all|static|unit|live-safe|scanner-live]\n' "$0" >&2
    exit 2
    ;;
esac

ARTIFACT_DIR="$ROOT_DIR/artifacts"
MANIFEST_PATH="$ARTIFACT_DIR/verification-manifest.json"
WORK_DIR="$(mktemp -d)"
RESULTS_PATH="$WORK_DIR/results.tsv"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$ARTIFACT_DIR"
: > "$RESULTS_PATH"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log() {
  printf '[verify:%s] %s\n' "$MODE" "$*"
}

record_result() {
  local name="$1"
  local status_value="$2"
  local duration="$3"
  local command_label="$4"
  printf '%s\t%s\t%s\t%s\n' "$name" "$status_value" "$duration" "$command_label" >> "$RESULTS_PATH"
}

run_gate() {
  local name="$1"
  local command_label="$2"
  shift 2
  local started_seconds="$SECONDS"
  log "starting ${name}"
  "$@"
  local result=$?
  if [[ "$result" -eq 0 ]]; then
    record_result "$name" passed "$((SECONDS - started_seconds))" "$command_label"
    log "passed ${name}"
    return 0
  fi
  record_result "$name" failed "$((SECONDS - started_seconds))" "$command_label"
  log "failed ${name} (exit ${result})"
  return "$result"
}

validate_environment() {
  for command_name in docker curl python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
      printf 'Required command is missing: %s\n' "$command_name" >&2
      return 1
    }
  done
  docker info >/dev/null || return $?
  [[ -f .env ]] || {
    printf '.env is missing. Run make init, then replace every placeholder.\n' >&2
    return 1
  }
  python3 - <<'PY'
from pathlib import Path

values: dict[str, str] = {}
for raw_line in Path('.env').read_text(encoding='utf-8').splitlines():
    line = raw_line.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    values[key.strip()] = value.strip()

required = {
    'POSTGRES_DB',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD',
    'PORYGON_INTERNAL_API_TOKEN',
    'PORYGON_OPERATOR_API_TOKEN',
    'DOCKER_GID',
}
missing = sorted(required - values.keys())
if missing:
    raise SystemExit('Missing required .env keys: ' + ', '.join(missing))
if any('replace-with-' in value for value in values.values()):
    raise SystemExit('.env still contains replacement placeholders')
if len(values['POSTGRES_PASSWORD']) < 24:
    raise SystemExit('POSTGRES_PASSWORD must contain at least 24 characters')
internal = values['PORYGON_INTERNAL_API_TOKEN']
operator = values['PORYGON_OPERATOR_API_TOKEN']
if len(internal) < 32 or len(operator) < 32:
    raise SystemExit('Porygon API tokens must contain at least 32 characters')
if internal == operator:
    raise SystemExit('Internal and operator API tokens must be different')
if not values['DOCKER_GID'].isdigit():
    raise SystemExit('DOCKER_GID must be numeric')
if values.get('PORYGON_RESPONSE_EXECUTION_MODE', 'disabled') != 'disabled':
    raise SystemExit('Safe verification requires PORYGON_RESPONSE_EXECUTION_MODE=disabled')
PY
}

static_checks() {
  command -v ruff >/dev/null 2>&1 || {
    printf 'ruff is required for verify-static\n' >&2
    return 1
  }
  docker compose config --quiet || return $?
  ruff check --select E4,E7,E9,F backend collector telemetry responder scanner scripts || return $?
  python3 - <<'PY'
import ast
from pathlib import Path
import tomllib

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f'duplicate YAML key: {key!r}')
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping,
)

python_files = sorted(
    path
    for root in ('backend', 'collector', 'telemetry', 'responder', 'scanner', 'scripts')
    for path in Path(root).rglob('*.py')
)
for path in python_files:
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
for path in sorted(Path('.').glob('*/pyproject.toml')):
    tomllib.loads(path.read_text(encoding='utf-8'))
compose = yaml.load(
    Path('compose.yaml').read_text(encoding='utf-8'),
    Loader=UniqueKeyLoader,
)
rules = yaml.load(
    Path('falco/porygon_rules.yaml').read_text(encoding='utf-8'),
    Loader=UniqueKeyLoader,
)

services = compose['services']
networks = compose['networks']
gateway = services['gateway']
falco_events_init = services['falco-events-init']
assert not services['backend'].get('ports'), 'backend must not publish a host port'
assert gateway['ports'] == ['127.0.0.1:${BACKEND_PORT:-8000}:8080']
assert set(gateway['networks']) == {'porygon_internal', 'porygon_ingress'}
assert '@sha256:' in gateway['image'], 'gateway image must be digest pinned'
assert not gateway.get('env_file') and not gateway.get('environment')
assert falco_events_init['network_mode'] == 'none'
assert '@sha256:' in falco_events_init['image']
assert falco_events_init['cap_add'] == ['CHOWN']
assert services['falco']['depends_on']['falco-events-init']['condition'] == 'service_completed_successfully'
assert services['telemetry']['depends_on']['falco-events-init']['condition'] == 'service_completed_successfully'
assert networks['porygon_internal']['internal'] is True
assert not networks['porygon_ingress'].get('internal', False)
assert '\n' not in rules[0]['output'], 'Falco output template must be one line'
assert '%proc.vpid' in rules[0]['output']
print(f'parsed {len(python_files)} Python files, service TOML, and YAML with unique keys')
PY
  for script_path in scripts/*.sh backend/entrypoint.sh; do
    bash -n "$script_path" || return $?
  done
  docker compose build backend || return $?
  docker compose run --rm --no-deps --entrypoint python backend -c \
    'from porygon_api.main import app; schema=app.openapi(); assert len(schema["paths"]) >= 60; print("openapi_paths=" + str(len(schema["paths"])))' || return $?
  docker compose run --rm --no-deps --entrypoint alembic backend upgrade head --sql >/dev/null || return $?
  docker run --rm \
    --volume "$ROOT_DIR/falco/porygon_rules.yaml:/etc/falco/porygon_rules.yaml:ro" \
    --entrypoint falco \
    falcosecurity/falco:0.44.1 \
    --validate /etc/falco/porygon_rules.yaml || return $?
}

unit_checks() {
  local service_name
  for service_name in backend collector telemetry responder scanner; do
    docker compose run --rm --no-deps --build --entrypoint pytest "$service_name" -q || return $?
  done
}

live_safe_checks() {
  ./scripts/verify_phase2.sh
  ./scripts/verify_phase6.sh
}

scanner_live_checks() {
  ./scripts/verify_phase8.sh
}

write_manifest() {
  local overall_status="$1"
  local finished_at
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RESULTS_PATH="$RESULTS_PATH" \
  MANIFEST_PATH="$MANIFEST_PATH" \
  STARTED_AT="$STARTED_AT" \
  FINISHED_AT="$finished_at" \
  VERIFY_MODE="$MODE" \
  OVERALL_STATUS="$overall_status" \
    python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess


def command_version(command: list[str]) -> str:
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except Exception as exc:
        return f'unavailable:{exc.__class__.__name__}'


results = []
for line in Path(os.environ['RESULTS_PATH']).read_text(encoding='utf-8').splitlines():
    name, status, duration, command = line.split('\t', 3)
    results.append(
        {
            'name': name,
            'status': status,
            'duration_seconds': int(duration),
            'command': command,
        }
    )
results.append(
    {
        'name': 'response-live',
        'status': 'skipped',
        'duration_seconds': 0,
        'command': 'make verify-response-live',
        'reason': 'disruptive gate is explicit opt-in and is never part of aggregate verification',
    }
)

artifact_hashes = {}
for path in sorted(Path('artifacts').glob('*')):
    if not path.is_file() or path.name == Path(os.environ['MANIFEST_PATH']).name:
        continue
    artifact_hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()

git_sha = command_version(['git', 'rev-parse', '--short', 'HEAD'])
if git_sha.startswith('unavailable:'):
    git_sha = 'UNBORN'
dirty = bool(subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True).stdout)

document = {
    'schema_version': 'porygon.verification.v1',
    'mode': os.environ['VERIFY_MODE'],
    'status': os.environ['OVERALL_STATUS'],
    'started_at_utc': os.environ['STARTED_AT'],
    'finished_at_utc': os.environ['FINISHED_AT'],
    'git_sha': git_sha,
    'git_dirty': dirty,
    'tools': {
        'python': command_version(['python3', '--version']),
        'docker': command_version(['docker', 'version', '--format', '{{.Client.Version}}/{{.Server.Version}}']),
        'compose': command_version(['docker', 'compose', 'version', '--short']),
        'ruff': command_version(['ruff', '--version']),
    },
    'gates': results,
    'artifact_sha256': artifact_hashes,
}
target = Path(os.environ['MANIFEST_PATH'])
temporary = target.with_suffix(target.suffix + '.tmp')
temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
temporary.replace(target)
PY
}

main() {
  validate_environment || return $?
  case "$MODE" in
    static)
      run_gate static 'make verify-static' static_checks
      ;;
    unit)
      run_gate unit 'make verify-unit' unit_checks
      ;;
    live-safe)
      run_gate live-safe 'make verify-live-safe' live_safe_checks
      ;;
    scanner-live)
      run_gate scanner-live 'make verify-scanner-live' scanner_live_checks
      ;;
    all)
      local aggregate_status=0
      run_gate static 'make verify-static' static_checks || aggregate_status=$?
      run_gate unit 'make verify-unit' unit_checks || aggregate_status=$?
      run_gate live-safe 'make verify-live-safe' live_safe_checks || aggregate_status=$?
      run_gate scanner-live 'make verify-scanner-live' scanner_live_checks || aggregate_status=$?
      return "$aggregate_status"
      ;;
  esac
}

set +e
main
main_status=$?
set -e
if [[ "$main_status" -eq 0 ]]; then
  write_manifest passed
else
  write_manifest failed
fi
exit "$main_status"
