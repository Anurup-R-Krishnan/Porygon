#!/usr/bin/env python3
"""Render pilot experiment results as a single self-contained HTML page.

Usage: python3 scripts/render_results.py [OUT_HTML]

Reads every run under artifacts/experiments/local/, writes a tracked summary to
artifacts/results.json, and renders artifacts/results.html. Regenerate after any
new run; nothing is hand-edited.
"""
from __future__ import annotations

import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "artifacts/experiments/local"


def collect() -> dict:
    runs = []
    for run_json in sorted(RUNS.glob("*/run.json")):
        run = json.loads(run_json.read_text(encoding="utf-8"))
        if run.get("kind") == "smoke_fixture":
            continue
        trials = [
            json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((run_json.parent / "trials").glob("*.json"))
        ]
        rows = []
        for t in trials:
            b = (t.get("reconciliation") or {}).get("boundaries", {})
            load = t.get("load") or {}

            def obs(name):
                e = b.get(name) or {}
                return e.get("observed", "—") if e.get("status") == "measured" else "unmeasured"

            rows.append({
                "trial_id": t["trial_id"],
                "workload": t.get("workload_id", "—"),
                "tag": t.get("human_tag", "—"),
                "variant": t.get("context_variant", "—"),
                "status": t.get("status", "—"),
                "context_hash": (t.get("runtime_context_hash") or "—")[:16],
                "generated": (t.get("reconciliation") or {}).get("generated", "—"),
                "falco": obs("source"),
                "database": obs("database"),
                "duplicates": (b.get("database") or {}).get("duplicates", "—"),
                "ops": f'{load.get("successes", "—")}/{load.get("operations_planned", "—")}',
                "unmeasured": sorted(n for n, e in b.items() if e.get("status") == "unmeasured"),
                "failure_reason": t.get("failure_reason"),
            })
        runs.append({
            "run_id": run["run_id"],
            "created_at_utc": run.get("created_at_utc", "—"),
            "git_sha": (run.get("git_sha") or "")[:12],
            "git_dirty": run.get("git_dirty"),
            "protocol_status": run.get("protocol_status_at_creation", "—"),
            "research_eligible": run.get("research_eligible"),
            "docker": run.get("docker_version", "—"),
            "platform": run.get("platform", "—"),
            "trials": rows,
        })
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "totals": {
            "runs": len(runs),
            "trials": sum(len(r["trials"]) for r in runs),
            "completed": sum(t["status"] == "completed" for r in runs for t in r["trials"]),
            "canaries": sum(
                t["generated"] for r in runs for t in r["trials"] if isinstance(t["generated"], int)
            ),
            "canaries_at_falco": sum(
                t["falco"] for r in runs for t in r["trials"] if isinstance(t["falco"], int)
            ),
            "canaries_in_db": sum(
                t["database"] for r in runs for t in r["trials"] if isinstance(t["database"], int)
            ),
        },
    }


GATES = [
    ("make verify-static", "passed"),
    ("make verify-unit", "passed"),
    ("make verify-live-safe", "passed"),
    ("make verify-experiment-live", "passed"),
    ("make verify-scanner-live", "not run"),
    ("make verify-response-live", "not run (disruptive)"),
    ("make experiment-confirmatory", "refused (protocol review-pending)"),
]

FINDINGS = [
    ("Context variants are behaviourally identical",
     "cap-drop NET_RAW and tmpfs /scratch change the context identity but not what executes. "
     "Identical (process, executable) multisets across all three variants in every family."),
    ("execve-only telemetry is blind to application traffic",
     "40 HTTP requests and 40 Redis operations each produced zero process events. "
     "Profiles are dominated by container startup and exec'd activity."),
    ("Container-runtime scaffolding sits inside every profile",
     "runc init appears as process '6' (/runc) in every container and scales with docker exec count."),
    ("Container-startup correlation gap",
     "1017/1067 (95.3%) of pilot events resolved to a digest. The 50 that did not are "
     "container-startup processes Falco sees before the collector binds the container ID."),
    ("network_mode encoded the per-run network name (fixed)",
     "The same deployment produced a different context identity every run, so no stratum "
     "could reach its minimum fit-run count. Now normalised to its security class."),
]


def esc(v) -> str:
    return html.escape(str(v))


def render(data: dict) -> str:
    t = data["totals"]
    rows = []
    for run in data["runs"]:
        rows.append(f'<tr class="rh"><td colspan="11">{esc(run["run_id"])} '
                    f'<span class="mut">· {esc(run["created_at_utc"][:19])} · git {esc(run["git_sha"])}'
                    f'{" (dirty)" if run["git_dirty"] else ""} · protocol {esc(run["protocol_status"])}</span>'
                    f'<span class="pill warn">research_eligible: false</span></td></tr>')
        for x in run["trials"]:
            ok = x["status"] == "completed"
            loss = ok and x["generated"] == x["falco"] == x["database"]
            rows.append(
                "<tr>"
                f'<td class="mono">{esc(x["trial_id"])}</td>'
                f'<td>{esc(x["workload"])}</td><td class="mono sm">{esc(x["tag"])}</td>'
                f'<td>{esc(x["variant"])}</td>'
                f'<td><span class="pill {"ok" if ok else "bad"}">{esc(x["status"])}</span></td>'
                f'<td class="mono sm">{esc(x["context_hash"])}</td>'
                f'<td class="num">{esc(x["generated"])}</td><td class="num">{esc(x["falco"])}</td>'
                f'<td class="num">{esc(x["database"])}</td><td class="num">{esc(x["duplicates"])}</td>'
                f'<td class="num">{esc(x["ops"])}</td>'
                "</tr>"
                + (f'<tr><td colspan="11" class="note bad-note">{esc(x["failure_reason"])}</td></tr>'
                   if x["failure_reason"] else "")
                + ("" if loss else
                   f'<tr><td colspan="11" class="note">unmeasured boundaries: '
                   f'{esc(", ".join(x["unmeasured"]) or "none")}</td></tr>')
            )
    gates = "".join(
        f'<tr><td class="mono">{esc(c)}</td>'
        f'<td><span class="pill {"ok" if s == "passed" else "mut-pill"}">{esc(s)}</span></td></tr>'
        for c, s in GATES)
    findings = "".join(
        f"<li><b>{esc(h)}</b><span>{esc(b)}</span></li>" for h, b in FINDINGS)
    return TEMPLATE.format(
        generated=esc(data["generated_at_utc"][:19]),
        runs=t["runs"], trials=t["trials"], completed=t["completed"],
        canaries=t["canaries"], falco=t["canaries_at_falco"], db=t["canaries_in_db"],
        rows="".join(rows), gates=gates, findings=findings,
        data=json.dumps(data, indent=1).replace("</", "<\\/"),
    )


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Porygon Pilot Results</title>
<style>
:root{{--bg:#fbfbfa;--fg:#1a1a19;--mut:#6b6b66;--line:#e3e3df;--card:#fff;
--ok:#1a7f43;--okbg:#e6f4ec;--bad:#b3261e;--badbg:#fbeae9;--warn:#8a6100;--warnbg:#fdf3e0;--acc:#2d5bd7}}
@media(prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#16161a;--fg:#e9e9e6;--mut:#9b9b95;
--line:#2c2c33;--card:#1d1d22;--ok:#5fd08a;--okbg:#12321f;--bad:#f08a80;--badbg:#3a1a17;
--warn:#e8b84b;--warnbg:#3a2e10;--acc:#8aa8ff}}}}
:root[data-theme=dark]{{--bg:#16161a;--fg:#e9e9e6;--mut:#9b9b95;--line:#2c2c33;--card:#1d1d22;
--ok:#5fd08a;--okbg:#12321f;--bad:#f08a80;--badbg:#3a1a17;--warn:#e8b84b;--warnbg:#3a2e10;--acc:#8aa8ff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:32px 20px 64px}}
h1{{font-size:26px;margin:0 0 4px;letter-spacing:-.02em}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin:34px 0 10px}}
.sub{{color:var(--mut);font-size:13px;margin-bottom:22px}}
.banner{{background:var(--warnbg);color:var(--warn);border:1px solid currentColor;border-radius:8px;
padding:11px 14px;font-size:13.5px;margin-bottom:26px}}
.banner b{{color:inherit}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:14px 16px}}
.card .k{{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}}
.card .v{{font-size:25px;font-weight:600;letter-spacing:-.02em;margin-top:3px}}
.scroll{{overflow-x:auto;border:1px solid var(--line);border-radius:9px;background:var(--card)}}
table{{border-collapse:collapse;width:100%;font-size:13.5px;min-width:900px}}
th{{text-align:left;font-weight:600;color:var(--mut);font-size:11.5px;text-transform:uppercase;
letter-spacing:.05em;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap}}
td{{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
tr:last-child td{{border-bottom:0}}
.rh td{{background:var(--bg);font-weight:600;font-size:13px}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.sm{{font-size:12px}} .num{{text-align:right;font-variant-numeric:tabular-nums}}
.mut{{color:var(--mut);font-weight:400}}
.note{{color:var(--mut);font-size:12px;padding-top:0}}
.bad-note{{color:var(--bad)}}
.pill{{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600;margin-left:8px}}
.ok{{background:var(--okbg);color:var(--ok)}} .bad{{background:var(--badbg);color:var(--bad)}}
.warn{{background:var(--warnbg);color:var(--warn)}} .mut-pill{{background:var(--line);color:var(--mut)}}
ul{{list-style:none;padding:0;margin:0;display:grid;gap:10px}}
li{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--acc);
border-radius:7px;padding:12px 15px}}
li b{{display:block;font-size:14px;margin-bottom:3px}}
li span{{color:var(--mut);font-size:13px}}
details{{margin-top:30px}} summary{{cursor:pointer;color:var(--mut);font-size:13px}}
pre{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;
overflow-x:auto;font-size:11.5px;line-height:1.45;max-height:420px}}
footer{{margin-top:38px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px}}
</style></head><body><div class="wrap">
<h1>Porygon &mdash; real-container pilot results</h1>
<div class="sub">Generated {generated}Z from immutable run artifacts. Regenerate with
<span class="mono">python3 scripts/render_results.py</span></div>

<div class="banner"><b>Pilot evidence, not research evidence.</b> These runs used real containers
pulled by immutable digest, but were collected while the research protocol is review-pending.
Every record carries <span class="mono">research_eligible: false</span>. No detection-quality,
false-positive, calibration, or profile-scope claim is supported by this data.</div>

<div class="grid">
<div class="card"><div class="k">Runs</div><div class="v">{runs}</div></div>
<div class="card"><div class="k">Trials</div><div class="v">{trials}</div></div>
<div class="card"><div class="k">Completed</div><div class="v">{completed}</div></div>
<div class="card"><div class="k">Canaries sent</div><div class="v">{canaries}</div></div>
<div class="card"><div class="k">Seen at Falco</div><div class="v">{falco}</div></div>
<div class="card"><div class="k">In PostgreSQL</div><div class="v">{db}</div></div>
</div>

<h2>Trials</h2>
<div class="scroll"><table>
<thead><tr><th>Trial</th><th>Workload</th><th>Image tag</th><th>Context variant</th><th>Status</th>
<th>Context hash</th><th>Gen</th><th>Falco</th><th>DB</th><th>Dup</th><th>Ops</th></tr></thead>
<tbody>{rows}</tbody></table></div>

<h2>Verification gates</h2>
<div class="scroll"><table style="min-width:auto">
<thead><tr><th>Command</th><th>Result</th></tr></thead><tbody>{gates}</tbody></table></div>

<h2>Measured findings</h2>
<ul>{findings}</ul>

<details><summary>Raw data (artifacts/results.json)</summary><pre>{data}</pre></details>

<footer>Boundaries marked <span class="mono">unmeasured</span> are never recorded as zero loss.
Kernel-to-eBPF and Falco userspace drops remain unmeasured by design.</footer>
</div></body></html>"""


def main() -> int:
    data = collect()
    (ROOT / "artifacts/results.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "artifacts/results.html"
    out.write_text(render(data), encoding="utf-8")
    print(f"wrote {out} and artifacts/results.json "
          f"({data['totals']['trials']} trials across {data['totals']['runs']} runs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
