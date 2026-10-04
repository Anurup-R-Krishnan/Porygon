#!/usr/bin/env python3
"""Assert the operator console cannot load or execute third-party code.

The console (`dashboard/`) holds `PORYGON_OPERATOR_API_TOKEN`, which authorises
`responder/` to pause, stop, or disconnect live containers. It previously loaded
nine resources from four third-party origins with no integrity attributes, so
any one of those origins could run code on the console origin and read that
token out of browser storage.

`compose.yaml` pins every container image by sha256 digest and
`verify_all.sh static` enforces it. This applies the equivalent standard to the
console. Run by `console_supply_chain_checks` in `scripts/verify_all.sh`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "dashboard"

# Source files authored in this repository. `vendor/` is excluded: its CSS
# legitimately records the upstream URL each file came from, and every one of
# those sources is recorded in the integrity manifest.
SOURCE_FILES = ("index.html", "app.js", "style.css")

# Hosts that may appear in source without being fetched.
ALLOWED_HOSTS = frozenset({"www.w3.org"})  # SVG/XML namespace URIs

# An absolute `scheme://host` reference, or a protocol-relative `//host` one.
#
# The protocol-relative half has to be anchored: base64 SRI digests contain
# literal `//` runs (e.g. `sha384-...whjg//gGwfFBXsw...`), and an unanchored
# pattern reads the following characters as a hostname. So a bare `//` only
# counts when it opens an attribute value or a CSS url(), and the host must
# carry a dot -- a hostname without one cannot be a third party.
EXTERNAL_ORIGIN = re.compile(
    r"""(?:
          https?://(?P<absolute>[A-Za-z0-9.-]+)
        | (?<=[\"'(=\s])//(?P<relative>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)
        )""",
    re.VERBOSE,
)

REQUIRED_HEADERS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def csp_directives(text: str) -> dict[str, str]:
    """Pull the console CSP out of nginx.conf or the dev proxy and normalise it.

    Both files spell the same policy differently -- one as an nginx add_header
    string, the other as a Python tuple of concatenated fragments -- so the
    comparison is on parsed directives, not on the raw text.
    """
    match = re.search(r"default-src 'self';(?P<rest>.*?)form-action 'none'", text, re.DOTALL)
    if match is None:
        return {}
    body = "default-src 'self';" + match.group("rest") + "form-action 'none'"
    body = re.sub(r'["\s]+', " ", body)
    directives: dict[str, str] = {}
    for chunk in body.split(";"):
        parts = chunk.split()
        if parts:
            directives[parts[0]] = " ".join(sorted(parts[1:]))
    return directives


def main() -> int:
    failures: list[str] = []

    # 1. No console source file may reference a third-party origin.
    for name in SOURCE_FILES:
        path = CONSOLE / name
        if not path.is_file():
            failures.append(f"dashboard/{name} is missing")
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in EXTERNAL_ORIGIN.finditer(line):
                host = match.group("absolute") or match.group("relative")
                if host and host not in ALLOWED_HOSTS:
                    failures.append(
                        f"dashboard/{name}:{number} references external origin {host!r}"
                    )

    manifest_path = CONSOLE / "vendor" / "integrity-manifest.json"
    if not manifest_path.is_file():
        print(f"console supply chain: missing {manifest_path}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))["assets"]
    markup = (CONSOLE / "index.html").read_text(encoding="utf-8")

    # 2. Every integrity attribute in the markup must match the manifest, so a
    #    vendored file cannot be swapped without the two disagreeing.
    tags = re.findall(
        r'(?:src|href)="vendor/([^"]+)"[^>]*?integrity="([^"]+)"', markup, re.DOTALL
    )
    if not tags:
        failures.append("dashboard/index.html declares no vendored asset with integrity")
    for asset, declared in tags:
        recorded = manifest.get(asset, {}).get("integrity")
        if recorded is None:
            failures.append(
                f"dashboard/index.html loads vendor/{asset}, which the manifest omits"
            )
        elif recorded != declared:
            failures.append(
                f"vendor/{asset}: markup declares {declared}, manifest records {recorded}"
            )

    # 3. Every vendored asset the markup loads must carry an integrity attribute.
    #    A file added without one would otherwise be unverified yet still pass (2).
    for reference in re.findall(r'(?:src|href)="(vendor/[^"]+)"', markup):
        asset = reference.removeprefix("vendor/")
        if asset not in {name for name, _ in tags}:
            failures.append(f"dashboard/index.html loads {reference} with no integrity attribute")

    # 4. Every local asset the markup loads must exist, so a rename cannot leave
    #    the console silently loading nothing.
    for reference in re.findall(r'(?:src|href)="(vendor/[^"]+|app\.js|style\.css)"', markup):
        if not (CONSOLE / reference).is_file():
            failures.append(f"dashboard/index.html loads {reference}, which does not exist")

    # 5. The gateway and the dev proxy must present the same headers, or the
    #    console is hardened on one path and bare on the other.
    nginx = (ROOT / "gateway" / "nginx.conf").read_text(encoding="utf-8")
    dev_proxy = (ROOT / "scripts" / "serve_dashboard.py").read_text(encoding="utf-8")
    for header in REQUIRED_HEADERS:
        if header not in nginx:
            failures.append(f"gateway/nginx.conf does not set {header}")
        if header not in dev_proxy:
            failures.append(f"scripts/serve_dashboard.py does not set {header}")

    nginx_csp = csp_directives(nginx)
    dev_csp = csp_directives(dev_proxy)
    if not nginx_csp:
        failures.append("gateway/nginx.conf has no parseable console CSP")
    if not dev_csp:
        failures.append("scripts/serve_dashboard.py has no parseable console CSP")
    if nginx_csp and dev_csp and nginx_csp != dev_csp:
        for directive in sorted(set(nginx_csp) | set(dev_csp)):
            if nginx_csp.get(directive) != dev_csp.get(directive):
                failures.append(
                    f"CSP {directive} differs: nginx {nginx_csp.get(directive)!r} "
                    f"vs dev proxy {dev_csp.get(directive)!r}"
                )

    # 6. The CSP must actually constrain script loading. A policy that permits a
    #    wildcard or scheme source, or omits script-src and falls back to a
    #    permissive default-src, would satisfy every check above while allowing
    #    precisely what they exist to prevent.
    for label, directives in (("gateway/nginx.conf", nginx_csp), ("dev proxy", dev_csp)):
        if not directives:
            continue
        script_src = directives.get("script-src")
        if script_src is None:
            failures.append(f"{label} CSP has no script-src directive")
            continue
        if "'self'" not in script_src:
            failures.append(f"{label} CSP script-src omits 'self': {script_src!r}")
        for forbidden in ("*", "http:", "https:", "data:"):
            if forbidden in script_src.split():
                failures.append(
                    f"{label} CSP script-src permits {forbidden!r}, re-admitting third-party code"
                )

    for failure in failures:
        print(f"console supply chain: {failure}", file=sys.stderr)
    if failures:
        print(
            f"\n{len(failures)} console supply-chain violation(s). "
            "See plans/010-operator-console-hardening.md.",
            file=sys.stderr,
        )
        return 1
    print(
        f"console supply chain: {len(tags)} hash-verified assets, "
        "no external origins, gateway and dev proxy headers agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
