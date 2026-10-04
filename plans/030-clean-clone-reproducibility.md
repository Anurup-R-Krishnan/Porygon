# 030 — Clean-clone reproducibility

## Problem

### 030.1 — `make verify-static` fails on a fresh clone

The `Makefile` runs the static gate as:

```
verify-static:
	PATH="$(CURDIR)/.venv/bin:$$PATH" ./scripts/verify_all.sh static
```

Nothing creates `.venv`, and `.gitignore:14` excludes it. `make init` only
writes `.env`. On a fresh clone `.venv/bin/ruff` does not exist, so the first
gate in `verify-static` fails before any invariant is checked. Confirmed on
this machine: the gate only passed after manually running
`python3 -m venv .venv && .venv/bin/pip install ruff`.

The documented setup sequence in `CLAUDE.md` is `make init && make build &&
make up` — none of which produces a working static gate.

### 030.2 — The presentation decks cannot be rebuilt

All three decks contain:

```
\includegraphics[width=2.8cm]{logo.png}
```

`logo.png` exists nowhere in the repository. The committed PDFs
(`porygon_review.pdf`, `_v2`, `_v3`, totalling 4.2 MB) were built against a
file that is not tracked, so `pdflatex` on a clean clone fails. The
`.gitignore` comment explicitly reasons about keeping
`docs/presentation/screenshots/` tracked because the decks `\includegraphics`
them — the same reasoning was never applied to the logo.

### 030.3 — `CLAUDE.md` documents a directory that did not exist

`CLAUDE.md` names `plans/` as the authority for implementation order, with a
`plans/README.md` status table, and instructs that a plan be read fully before
touching related code. The directory was absent until this plan series created
it. Project instructions that point at nothing train the reader to ignore them.

### 030.4 — Build detritus is committed or ambiguous

`docs/presentation/` holds `.aux`, `.log`, `.nav`, `.snm`, `.toc`, `.out`
LaTeX intermediates. `.gitignore` covers most extensions but
`docs/presentation/*.log` is listed separately from the global rules, and three
`.pdf` build products totalling 4.2 MB are tracked.

## Approach

1. Add a `make dev-setup` target that creates `.venv` and installs the lint
   toolchain from a pinned `requirements-dev.txt`, and make `verify-static`
   fail with an actionable message — not a bare "command not found" — when the
   venv is missing. Add it to the documented setup sequence in `CLAUDE.md` and
   `README.md`.
2. Add the missing `docs/presentation/logo.png`, or remove the
   `\includegraphics` if no logo is intended. Add a static assertion that every
   `\includegraphics` target in `docs/presentation/*.tex` resolves to a tracked
   file, so this cannot regress.
3. Reconcile `CLAUDE.md` with the tree: the `plans/` table now exists and is
   accurate; correct any other stale path references found while doing so.
4. Decide the deck-PDF policy explicitly and record it: either the PDFs are
   release artifacts and stay tracked with a documented build command, or they
   are build output and move out of the tree. Do not leave it implicit.

## Gates

- From a clean checkout with no `.venv`: `make dev-setup && make verify-static`
  is green.
- New static assertion: every `\includegraphics` target resolves.
- No path named in `CLAUDE.md` or `README.md` is missing from the tree.

## STOP conditions

- Do not delete tracked PDFs without asking. They may be submitted artifacts.
