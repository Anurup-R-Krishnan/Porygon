#!/usr/bin/env python3
"""Fetch, pin, and hash every third-party asset the operator console needs.

The console holds the operator token that authorises containment. Before this
script existed it loaded nine resources from four third-party origins with no
integrity checking, so any one of those origins could execute code on the
console origin and read the token out of storage. `compose.yaml` pins every
container image by sha256 digest and `verify_all.sh` enforces it; this gives the
console the same property.

Re-run after changing PINS. The written manifest is what
`verify_all.sh static` checks, so a silent byte change in a vendored file fails
the gate.

Usage:
    python3 scripts/vendor_console_assets.py          # fetch and write manifest
    python3 scripts/vendor_console_assets.py --check   # verify, fetch nothing
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "dashboard" / "vendor"
MANIFEST = VENDOR / "integrity-manifest.json"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Exact, immutable upstream URLs. No tag ranges: `unpkg.com/pkg@2.1.1` with no
# path resolves through the package `main` field at request time, which is not a
# fixed artifact. Every entry below names a file.
PINS: dict[str, str] = {
    "alpine.min.js": "https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js",
    "chart.umd.min.js": "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js",
    "phosphor/style.css": "https://unpkg.com/@phosphor-icons/web@2.1.1/src/regular/style.css",
}

# Webfont CSS whose url() references are rewritten to local paths and whose
# font binaries are pulled alongside.
#
# Only Satoshi and JetBrains Mono are fetched. The original console also loaded
# Clash Display (referenced nowhere in the markup) and Space Grotesk plus Plus
# Jakarta Sans, which sat behind Satoshi in the font stack and so could only
# render if Satoshi failed to load. Vendored locally Satoshi cannot fail, which
# makes both fallbacks unreachable and removes the Google Fonts origin outright.
FONT_CSS: dict[str, str] = {
    "satoshi.css": "https://api.fontshare.com/v2/css?f[]=satoshi@300,400,500,700,900&display=swap",
    "jetbrains-mono.css": (
        "https://fonts.googleapis.com/css2"
        "?family=JetBrains+Mono:wght@400;500;700&display=swap"
    ),
}


# Assets built from this repository's own sources rather than fetched. They are
# recorded in the same manifest so the integrity gate also catches a hand-edit
# or a silent drift in generated CSS; regenerating them is expected to change
# the manifest, and that change is reviewable in the diff.
GENERATED: dict[str, str] = {
    "tailwind.css": "built by scripts/build_console_css.sh",
}


def woff2_only(stylesheet: str) -> str:
    """Drop every non-woff2 source from each @font-face src list.

    Upstream webfont CSS offers woff2 alongside woff, ttf, and an SVG font for
    browsers that have not needed them in a decade. A browser picks the first
    format it understands and never requests the rest, so vendoring them adds
    megabytes of bytes that are served to nobody. Satoshi alone ships 5 weights
    in 3 formats. Keeping woff2 only also drops the SVG font, which is an XML
    document rather than an opaque binary.

    A src list with no woff2 entry is left untouched so nothing silently loses
    its only source.
    """

    def filter_src(match: re.Match[str]) -> str:
        sources = [part.strip() for part in match.group(1).split(",")]
        preferred = [part for part in sources if "woff2" in part]
        if not preferred:
            return match.group(0)
        return "src: " + ", ".join(preferred)

    return re.sub(r"src:\s*([^;}]+)", filter_src, stylesheet)


def canonical(url: str) -> str:
    """Strip the query and fragment a CSS url() may carry.

    Phosphor's stylesheet references its SVG font as `Phosphor.svg#Phosphor`;
    taken literally that fragment becomes part of the saved filename.
    """
    return url.split("#", 1)[0].split("?", 1)[0]


def fetch(url: str) -> bytes:
    # Fontshare emits protocol-relative url() references (//cdn.fontshare.com/...).
    if url.startswith("//"):
        url = f"https:{url}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def sri(payload: bytes) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(payload).digest()).decode("ascii")


def write(relative_path: str, payload: bytes) -> None:
    target = VENDOR / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def vendor_font_css(name: str, url: str, manifest: dict[str, dict[str, str]]) -> None:
    """Download webfont CSS, pull each referenced binary, and localise url()."""
    stylesheet = woff2_only(fetch(url).decode("utf-8"))
    stem = name.removesuffix(".css")
    seen: dict[str, str] = {}

    def localise(match: re.Match[str]) -> str:
        remote = match.group(1).strip("'\"")
        if remote.startswith("data:"):
            return match.group(0)
        if remote.startswith("//"):
            remote = f"https:{remote}"
        remote = canonical(remote)
        if remote in seen:
            return f"url('{seen[remote]}')"
        suffix = Path(remote).suffix or ".woff2"
        payload = fetch(remote)
        local_name = f"{stem}-{hashlib.sha256(remote.encode()).hexdigest()[:12]}{suffix}"
        write(f"fonts/{local_name}", payload)
        manifest[f"fonts/{local_name}"] = {"source": remote, "integrity": sri(payload)}
        local_reference = f"fonts/{local_name}"
        seen[remote] = local_reference
        return f"url('{local_reference}')"

    localised = re.sub(r"url\(([^)]+)\)", localise, stylesheet)
    body = localised.encode("utf-8")
    write(name, body)
    manifest[name] = {"source": url, "integrity": sri(body)}
    print(f"  {name}: {len(seen)} font binaries localised")


def vendor_phosphor(manifest: dict[str, dict[str, str]]) -> None:
    """Phosphor's stylesheet references its font file relative to its own path."""
    url = PINS["phosphor/style.css"]
    stylesheet = woff2_only(fetch(url).decode("utf-8"))
    base = url.rsplit("/", 1)[0]
    seen: dict[str, str] = {}

    def localise(match: re.Match[str]) -> str:
        remote = match.group(1).strip("'\"")
        if remote.startswith("data:"):
            return match.group(0)
        absolute = remote if remote.startswith("http") else f"{base}/{remote.lstrip('./')}"
        clean = canonical(absolute)
        if clean in seen:
            return f"url('{seen[clean]}')"
        payload = fetch(clean)
        local_name = Path(clean).name
        write(f"phosphor/{local_name}", payload)
        manifest[f"phosphor/{local_name}"] = {"source": clean, "integrity": sri(payload)}
        seen[clean] = local_name
        return f"url('{local_name}')"

    localised = re.sub(r"url\(([^)]+)\)", localise, stylesheet)
    body = localised.encode("utf-8")
    write("phosphor/style.css", body)
    manifest["phosphor/style.css"] = {"source": url, "integrity": sri(body)}
    print(f"  phosphor/style.css: {len(seen)} font binaries localised")


def record_generated() -> int:
    """Re-hash the generated assets in place, leaving fetched entries alone."""
    if not MANIFEST.is_file():
        print(f"missing integrity manifest: {MANIFEST}", file=sys.stderr)
        print("run without --record-generated first", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["assets"]
    for relative_path, source in GENERATED.items():
        target = VENDOR / relative_path
        if not target.is_file():
            print(f"generated asset is missing: {relative_path}", file=sys.stderr)
            print("run scripts/build_console_css.sh first", file=sys.stderr)
            return 1
        manifest[relative_path] = {"source": source, "integrity": sri(target.read_bytes())}
        print(f"  {relative_path}: recorded")
    MANIFEST.write_text(
        json.dumps({"assets": dict(sorted(manifest.items()))}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {MANIFEST.relative_to(ROOT)} with {len(manifest)} assets")
    return 0


def sync_markup() -> int:
    """Rewrite index.html's integrity attributes from the manifest.

    Rebuilding tailwind.css changes its hash, which leaves the integrity
    attribute in the markup stale. The browser then refuses the stylesheet and
    the console renders unstyled -- so the markup must be updated in the same
    breath as the manifest, not left for a human to remember.
    """
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))["assets"]
    markup_path = VENDOR.parent / "index.html"
    markup = markup_path.read_text(encoding="utf-8")

    changed: list[str] = []

    def rewrite(match: re.Match[str]) -> str:
        asset, declared = match.group("asset"), match.group("declared")
        recorded = manifest.get(asset, {}).get("integrity")
        if recorded is None or recorded == declared:
            return match.group(0)
        changed.append(asset)
        return match.group(0).replace(declared, recorded)

    updated = re.sub(
        r'(?:src|href)="vendor/(?P<asset>[^"]+)"[^>]*?integrity="(?P<declared>[^"]+)"',
        rewrite,
        markup,
        flags=re.DOTALL,
    )
    if changed:
        markup_path.write_text(updated, encoding="utf-8")
        for asset in changed:
            print(f"  {asset}: integrity attribute updated in index.html")
    else:
        print("  index.html integrity attributes already match the manifest")
    return 0


def check() -> int:
    if not MANIFEST.is_file():
        print(f"missing integrity manifest: {MANIFEST}", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures: list[str] = []
    for relative_path, entry in sorted(manifest["assets"].items()):
        target = VENDOR / relative_path
        if not target.is_file():
            failures.append(f"{relative_path}: vendored file is missing")
            continue
        actual = sri(target.read_bytes())
        if actual != entry["integrity"]:
            failures.append(
                f"{relative_path}: recorded {entry['integrity']}, found {actual}"
            )
    for failure in failures:
        print(f"integrity failure: {failure}", file=sys.stderr)
    if failures:
        print(
            "\nVendored console assets do not match their recorded hashes. Either a "
            "file was edited by hand or the pins changed; re-run "
            "scripts/vendor_console_assets.py and review the diff.",
            file=sys.stderr,
        )
        return 1
    print(f"console asset integrity: {len(manifest['assets'])} files match")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify vendored files against the manifest without fetching",
    )
    parser.add_argument(
        "--record-generated",
        action="store_true",
        help="re-hash locally built assets (tailwind.css) without refetching",
    )
    parser.add_argument(
        "--sync-markup",
        action="store_true",
        help="rewrite index.html's integrity attributes from the manifest",
    )
    arguments = parser.parse_args()
    if arguments.check:
        return check()
    if arguments.sync_markup:
        return sync_markup()
    if arguments.record_generated:
        status = record_generated()
        return status or sync_markup()

    VENDOR.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict[str, str]] = {}

    print("fetching pinned libraries")
    for name, url in PINS.items():
        if name == "phosphor/style.css":
            continue
        payload = fetch(url)
        write(name, payload)
        manifest[name] = {"source": url, "integrity": sri(payload)}
        print(f"  {name}: {len(payload):,} bytes")

    print("fetching phosphor icon font")
    vendor_phosphor(manifest)

    print("fetching webfonts")
    for name, url in FONT_CSS.items():
        vendor_font_css(name, url, manifest)

    for relative_path, source in GENERATED.items():
        target = VENDOR / relative_path
        if target.is_file():
            manifest[relative_path] = {
                "source": source,
                "integrity": sri(target.read_bytes()),
            }
        else:
            print(
                f"note: {relative_path} not built yet; run scripts/build_console_css.sh "
                "then re-run with --record-generated"
            )

    MANIFEST.write_text(
        json.dumps({"assets": dict(sorted(manifest.items()))}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote {MANIFEST.relative_to(ROOT)} with {len(manifest)} assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
