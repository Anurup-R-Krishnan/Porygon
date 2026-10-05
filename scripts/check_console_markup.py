#!/usr/bin/env python3
"""Static accessibility and structure checks for the operator console markup.

Each check guards something that was broken in dashboard/index.html and fixed
by plan 040, so it cannot quietly regress:

  - icon-only buttons with no accessible name (six were announced only as
    "button", including every modal's close control);
  - ARIA references (aria-controls, aria-labelledby) pointing at ids that do
    not exist, and duplicate ids, which make those references ambiguous;
  - dialogs without the x-dialog directive that gives them role="dialog",
    aria-modal and a focus trap, or without an accessible name;
  - nav tabs missing the tab-pattern attributes.

Run by `verify_all.sh static`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKUP = ROOT / "dashboard" / "index.html"

NAME_ATTRIBUTE = re.compile(r"(?:^|\s)(?:aria-label|:aria-label|title|:title|aria-labelledby)=")


def line_of(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def main() -> int:
    source = MARKUP.read_text(encoding="utf-8")
    failures: list[str] = []

    for match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", source, re.DOTALL):
        attributes, inner = match.group(1), match.group(2)
        visible_text = re.sub(r"<[^>]+>", "", inner).strip()
        if visible_text or "x-text" in attributes + inner or NAME_ATTRIBUTE.search(attributes):
            continue
        failures.append(
            f"index.html:{line_of(source, match.start())} icon-only <button> has no "
            "accessible name; add aria-label"
        )

    ids = re.findall(r'\bid="([^"]+)"', source)
    for duplicate in sorted({i for i in ids if ids.count(i) > 1}):
        failures.append(f'index.html: id="{duplicate}" is used more than once')
    known = set(ids)
    for attribute in ("aria-controls", "aria-labelledby"):
        for match in re.finditer(rf'\b{attribute}="([^"]+)"', source):
            for target in match.group(1).split():
                if target not in known:
                    failures.append(
                        f"index.html:{line_of(source, match.start())} {attribute} "
                        f'references missing id "{target}"'
                    )

    # Every modal overlay (a fixed full-screen x-show layer) must contain an
    # x-dialog panel with a name.
    for match in re.finditer(r'<div x-show="([^"]+)"[^>]*class="fixed inset-0', source):
        window = source[match.end(): match.end() + 1500]
        panel = re.search(r"<div x-dialog=\"([^\"]+)\"([^>]*)>", window)
        where = f"index.html:{line_of(source, match.start())}"
        if panel is None:
            failures.append(f'{where} modal x-show="{match.group(1)}" has no x-dialog panel')
            continue
        if not NAME_ATTRIBUTE.search(" " + panel.group(2)):
            failures.append(f"{where} x-dialog panel has no accessible name")

    tabs = re.findall(r'<button role="tab"([^>]*)>', source)
    if not tabs:
        failures.append("index.html: no role=\"tab\" elements; the nav lost its tab pattern")
    for attributes in tabs:
        for required in ("aria-controls=", ":aria-selected=", ":tabindex=", "data-tab="):
            if required not in attributes:
                failures.append(f"index.html: a nav tab is missing {required.rstrip('=')}")
    if 'role="tablist"' not in source:
        failures.append('index.html: no role="tablist" container')

    for failure in failures:
        print(f"console markup: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"console markup: {len(tabs)} tabs, {source.count('x-dialog=')} dialogs, "
        f"{len(set(ids))} unique ids, every button named"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
