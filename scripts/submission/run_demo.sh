#!/usr/bin/env bash
# Controlled end-to-end acceptance. The responder acts only on the verifier's disposable target.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
python3 - <<'PY'
from pathlib import Path
values=dict(line.split('=',1) for line in Path('.env').read_text().splitlines() if '=' in line and not line.lstrip().startswith('#'))
if values.get('PORYGON_RESPONSE_EXECUTION_MODE','disabled') != 'disabled':
    raise SystemExit('Start the controlled demonstration with response execution disabled.')
PY
restore_mode() {
  python3 - <<'PY'
from pathlib import Path
p=Path('.env'); lines=p.read_text().splitlines()
p.write_text('\n'.join('PORYGON_RESPONSE_EXECUTION_MODE=disabled' if line.startswith('PORYGON_RESPONSE_EXECUTION_MODE=') else line for line in lines)+'\n')
PY
  docker compose up --detach --no-deps --wait backend responder >/dev/null 2>&1 || true
}
trap restore_mode EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('.env');lines=p.read_text().splitlines()
if not any(line.startswith('PORYGON_RESPONSE_EXECUTION_MODE=') for line in lines):
    lines.append('PORYGON_RESPONSE_EXECUTION_MODE=live')
else:
    lines=['PORYGON_RESPONSE_EXECUTION_MODE=live' if line.startswith('PORYGON_RESPONSE_EXECUTION_MODE=') else line for line in lines]
p.write_text('\n'.join(lines)+'\n')
PY
bash scripts/verify_containment_response.sh
python3 datasets/porygon-pilot-v1.0.0/verify.py
