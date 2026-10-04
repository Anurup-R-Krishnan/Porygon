#!/usr/bin/env python3
"""Capture the operator console to reproducible screenshots with provenance.

docs/presentation/screenshots/ held six PNGs that the review decks
\\includegraphics as build inputs. They were captured by hand, and nothing
recorded which commit, which stack state, or which data produced them, so
nothing could regenerate them. For a project whose experiments/ module enforces
an immutable artifact contract with hashing and split-leakage checks, the
figures carrying the argument to a reviewer were its least reproducible
evidence.

This drives headless Chrome against a running stack and writes, beside each
image, a manifest recording the commit SHA, the stack state, the viewport, and
a sha256 of every API payload the view was rendered from.

No browser automation dependency is needed. scripts/_cdp.py speaks enough of
the DevTools protocol over the standard library to switch tabs, measure each
one, and capture it at its own full height -- the console's tabs range from
roughly 1,700 to 8,400 CSS pixels, so Chrome's plain --screenshot flag, which
captures exactly the window height it is given, would clip the tall ones and
pad the short ones with dead background.

Usage:
    python3 scripts/capture_console.py
    python3 scripts/capture_console.py --output-dir docs/presentation/screenshots
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _cdp import Chrome  # noqa: E402  - needs the sys.path line above

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = "http://127.0.0.1:8000"
DEFAULT_OUTPUT = ROOT / "artifacts" / "console-captures"

CHROME_CANDIDATES = (
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
)

# Each console tab, keyed by the location.hash that selects it on load. The
# names match the nav labels so a reader can map a figure back to the UI.
TABS: dict[str, str] = {
    "overview": "Overview",
    "pathway": "Process Graph",
    "telemetry": "Telemetry",
    "anomalies": "Math",
    "incidents": "Incidents",
    "pipeline": "Pipeline",
    "vulnerabilities": "Reachability",
    "simulator": "Simulator",
}

# Viewports captured for every tab. The narrow one evidences the responsive
# claim rather than leaving it asserted.
VIEWPORTS: dict[str, tuple[int, int]] = {
    "desktop": (1600, 1000),
    "narrow": (430, 1200),
}

# Read-only endpoints the console renders from. Hashing their responses records
# what the figures actually show, so a capture can be told apart from one taken
# against a different database.
PROVENANCE_ENDPOINTS = (
    "/api/v1/system/info",
    "/api/v1/services",
    "/api/v1/containers?limit=100",
    "/api/v1/process-events?limit=40",
    "/api/v1/anomaly-scores?limit=20",
    "/api/v1/incidents?limit=50",
    "/api/v1/image-scans?limit=20",
)


def find_chrome() -> str:
    for candidate in CHROME_CANDIDATES:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise SystemExit(
        "No Chrome or Chromium binary found. Tried: " + ", ".join(CHROME_CANDIDATES)
    )


def git(*arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def stack_state() -> list[dict[str, str]]:
    """Record which services were up, so a capture is not mistaken for a full run."""
    try:
        completed = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    services: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        services.append(
            {
                "service": row.get("Service", "?"),
                "state": row.get("State", "?"),
                "health": row.get("Health", "") or "none",
            }
        )
    return sorted(services, key=lambda item: item["service"])


def payload_hashes(base_url: str) -> dict[str, dict[str, object]]:
    provenance: dict[str, dict[str, object]] = {}
    for path in PROVENANCE_ENDPOINTS:
        try:
            with urllib.request.urlopen(f"{base_url}{path}", timeout=30) as response:
                body = response.read()
            provenance[path] = {
                "status": 200,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        except urllib.error.HTTPError as error:
            provenance[path] = {"status": error.code, "bytes": 0, "sha256": None}
        except Exception as error:  # noqa: BLE001 - recorded, not raised
            provenance[path] = {"status": None, "error": str(error), "sha256": None}
    return provenance


def capture_tab(
    chrome: Chrome,
    console_url: str,
    tab: str,
    destination: Path,
    width: int,
    settle_seconds: float,
    max_height: int,
) -> tuple[int, int]:
    """Select one tab, size the viewport to its content, and shoot it whole.

    Returns (bytes written, captured height). Tabs are switched through Alpine
    rather than by reloading with a different location.hash: a reload restarts
    every poll and re-renders every chart, so a run would cost one full console
    boot per tab and the views would not be of the same moment.
    """
    chrome.set_viewport(width, 1000)
    chrome.evaluate(
        f"Alpine.$data(document.querySelector('[x-data]')).activeTab = {tab!r}",
        await_promise=False,
    )
    # Alpine renders on a microtask; charts and the reveal observer need a frame
    # or two beyond that, and any fetch the tab triggers needs the network.
    time.sleep(settle_seconds)

    height = int(chrome.evaluate("document.documentElement.scrollHeight") or 1000)
    height = max(600, min(height, max_height))
    chrome.set_viewport(width, height)
    time.sleep(0.4)  # let the layout settle at the new height before shooting
    return chrome.screenshot(destination, full_page=True), height


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--boot-seconds",
        type=float,
        default=7.0,
        help="time allowed for the console's first fetch round and chart render",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=1.4,
        help="time allowed for a tab to render after it is selected",
    )
    parser.add_argument(
        "--max-height",
        type=int,
        default=9000,
        help="cap on captured page height, so a runaway list cannot produce a huge image",
    )
    parser.add_argument("--scale", type=int, default=2, help="device pixel ratio")
    parser.add_argument(
        "--viewport",
        choices=(*VIEWPORTS, "all"),
        default="all",
    )
    parser.add_argument("--tab", choices=(*TABS, "all"), default="all")
    arguments = parser.parse_args()

    chrome = find_chrome()
    console_url = f"{arguments.base_url}/console/"
    try:
        with urllib.request.urlopen(console_url, timeout=15) as response:
            if response.status != 200:
                raise SystemExit(f"{console_url} returned HTTP {response.status}")
    except Exception as error:  # noqa: BLE001
        raise SystemExit(
            f"Console is not reachable at {console_url}: {error}\nBring the stack up with `make up`."
        ) from error

    tabs = TABS if arguments.tab == "all" else {arguments.tab: TABS[arguments.tab]}
    viewports = (
        VIEWPORTS
        if arguments.viewport == "all"
        else {arguments.viewport: VIEWPORTS[arguments.viewport]}
    )

    output_dir = arguments.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"chrome:  {chrome}")
    print(f"console: {console_url}")
    print(f"output:  {output_dir}")

    services = stack_state()
    provenance = payload_hashes(arguments.base_url)

    captures: list[dict[str, object]] = []
    with Chrome(chrome, width=1600, height=1000, scale=arguments.scale) as browser:
        for viewport_name, (width, _) in viewports.items():
            browser.set_viewport(width, 1000)
            browser.navigate(console_url)
            # One boot per viewport, not per tab: the console polls on a timer
            # and re-renders its charts on load, so reloading for every tab
            # would both cost a full boot each time and leave the tabs showing
            # different moments.
            time.sleep(arguments.boot_seconds)
            ready = browser.evaluate("typeof window.Alpine !== 'undefined'")
            if not ready:
                raise SystemExit(
                    "Alpine did not initialise; the console may be failing to load. "
                    "Check the browser console against a running stack."
                )
            external = browser.evaluate(
                "performance.getEntriesByType('resource')"
                ".filter(e => new URL(e.name).origin !== location.origin).length"
            )
            if external:
                raise SystemExit(
                    f"The console issued {external} request(s) to a third-party origin. "
                    "That is the condition plans/010-operator-console-hardening.md exists "
                    "to prevent; refusing to record evidence from it."
                )

            for tab_hash, label in tabs.items():
                name = f"console-{tab_hash}-{viewport_name}.png"
                destination = output_dir / name
                written, height = capture_tab(
                    browser,
                    console_url,
                    tab_hash,
                    destination,
                    width,
                    arguments.settle_seconds,
                    arguments.max_height,
                )
                captures.append(
                    {
                        "file": name,
                        "tab": tab_hash,
                        "label": label,
                        "viewport": f"{width}x{height}",
                        "device_scale_factor": arguments.scale,
                        "url": f"{console_url}#{tab_hash}",
                        "bytes": written,
                        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                    }
                )
                print(f"  {name}: {width}x{height} css px, {written:,} bytes")

    unhealthy = [s for s in services if s["health"] not in ("healthy", "none")]
    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "commit": git("rev-parse", "HEAD"),
        "commit_subject": git("log", "-1", "--format=%s"),
        "tree_dirty": bool(git("status", "--porcelain")),
        "base_url": arguments.base_url,
        "boot_seconds": arguments.boot_seconds,
        "settle_seconds": arguments.settle_seconds,
        "device_scale_factor": arguments.scale,
        "chrome": chrome,
        # docs/EXPERIMENT_ACCEPTANCE.md governs what a given class of evidence
        # may support. Screenshots show the console rendering whatever the
        # database already held; they are illustrative and never confirmatory,
        # and a capture taken with a service down must say so rather than
        # imply a complete pipeline.
        "evidence_class": "illustrative",
        "evidence_note": (
            "Console rendering of existing database state. Not pilot or "
            "confirmatory evidence; see docs/EXPERIMENT_ACCEPTANCE.md."
        ),
        "stack": services,
        "stack_degraded": [s["service"] for s in unhealthy],
        "api_provenance": provenance,
        "captures": captures,
    }
    manifest_path = output_dir / "capture-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\nwrote {manifest_path.relative_to(ROOT)}")
    print(f"  commit {manifest['commit'][:12]}, {len(captures)} captures")
    if unhealthy:
        print(
            "  stack degraded: "
            + ", ".join(f"{s['service']}={s['health']}" for s in unhealthy)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
