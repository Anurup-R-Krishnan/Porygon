"""Record real verification output with monotonic timing for the submission video."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]


def record(out: Path, command: list[str]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    header = {'version': 2, 'width': 130, 'height': 28,
              'timestamp': int(time.time()), 'title': 'Porygon working demonstration',
              'command': ' '.join(command)}
    with (out / 'demo.cast').open('w') as cast, (out / 'run.log').open('w') as log:
        cast.write(json.dumps(header) + '\n')
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in process.stdout:
            log.write(line); log.flush()
            cast.write(json.dumps([round(time.monotonic()-start, 3), 'o', line])+'\n');cast.flush()
            if '[PASS]' in line or '[FAIL]' in line:
                print(line, end='', flush=True)
        code = process.wait()
    metadata = {'command': command, 'exit_code': code,
                'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': round(time.monotonic()-start, 3),
                'git_sha': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                'git_dirty': bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT))}
    (out/'run-metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return code


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==['--'] else args.command
    if not command: parser.error('command is required')
    raise SystemExit(record(args.out,command))
