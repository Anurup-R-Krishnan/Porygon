# 050 — Reproducible console evidence capture

## Problem

`docs/presentation/screenshots/` holds six PNGs that the decks
`\includegraphics` as build inputs:

```
incidents_crop.png        math_dropper_crop.png
multicall_evasion_crop.png  overview_dropper_crop.png
reachability_crop.png     telemetry_crop.png
```

They were captured by hand. Nothing records which commit, which stack state, or
which data produced them, and nothing can regenerate them. For a project whose
`experiments/` module enforces an immutable artifact contract with hashing and
split-leakage checks, the figures that carry the argument to a reviewer are the
least reproducible evidence in the repository.

There is also no capture at all for the `pathway`, `anomalies`, `pipeline`,
`vulnerabilities`, or `simulator` tabs.

## Approach

1. A capture script that drives the console against a running stack and writes
   a full set of tab screenshots plus a sidecar manifest recording the commit
   SHA, stack state, viewport, and the API payload hashes the view was rendered
   from.
2. Capture both light and dark rendering and both desktop and narrow viewports,
   so the responsive and theming claims are evidenced rather than asserted.
3. Wire the output into `docs/presentation/screenshots/` so the decks consume
   generated inputs, and record in the manifest which deck figure each file
   backs.

## Gates

- The capture script runs against the live stack and produces every named file.
- The manifest records a commit SHA and payload hashes for each capture.
- Deck `\includegraphics` targets all resolve (shared with plan 030).

## STOP conditions

- Captures taken against a stack with no real telemetry are smoke evidence, not
  pilot or confirmatory evidence, and must be labelled as such in the manifest.
  `docs/EXPERIMENT_ACCEPTANCE.md` governs the distinction; do not blur it.
