# 030 — Clean-clone reproducibility

**Status:** 030.1 and 030.3 done. 030.2 withdrawn as not a defect. 030.4
reduced to a policy decision awaiting the owner.

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

### 030.2 — ~~The presentation decks cannot be rebuilt~~ (withdrawn: not a defect)

The original finding read `\includegraphics[width=2.8cm]{logo.png}` out of all
three decks and concluded a clean clone could not build them, because
`logo.png` exists nowhere in the repository. That was wrong. The full line is:

```
\IfFileExists{logo.png}{\includegraphics[width=2.8cm]{logo.png}\vspace{0.1cm}}{\vspace{0.4cm}}
```

The logo is optional by construction and the decks substitute vertical space
when it is absent. Verified by building all three from `git archive HEAD` with
no untracked files present: `porygon_review` 21 pages, `_v2` 26 pages, `_v3`
37 pages, each with exit 0, no missing-file warnings, and no undefined
references.

### 030.3 — `CLAUDE.md` documents a directory that did not exist

`CLAUDE.md` names `plans/` as the authority for implementation order, with a
`plans/README.md` status table, and instructs that a plan be read fully before
touching related code. The directory was absent until this plan series created
it. Project instructions that point at nothing train the reader to ignore them.

### 030.4 — Deck build policy is implicit

Checked against `git ls-files docs/presentation`: no LaTeX intermediate is
tracked. The `.aux`/`.log`/`.nav`/`.snm`/`.toc`/`.out` files seen in a working
copy are local build products already covered by `.gitignore`. The original
"build detritus is committed" claim was withdrawn for the same reason as 030.2.

What remains is a policy question, not a defect: three built PDFs totalling
4.2 MB are tracked alongside the `.tex` sources that produce them. Whether
they are submitted release artifacts (keep, and document the build command)
or regenerable output (remove) is the owner's decision. STOP condition below
applies.

## Approach

1. Add a `make dev-setup` target that creates `.venv` and installs the lint
   toolchain from a pinned `requirements-dev.txt`, and make `verify-static`
   fail with an actionable message — not a bare "command not found" — when the
   venv is missing. Add it to the documented setup sequence in `CLAUDE.md` and
   `README.md`.
2. ~~Add the missing logo~~ -- withdrawn, see 030.2.
3. Reconcile `CLAUDE.md` with the tree: the `plans/` table now exists and is
   accurate; correct any other stale path references found while doing so.
4. Decide the deck-PDF policy explicitly and record it: either the PDFs are
   release artifacts and stay tracked with a documented build command, or they
   are build output and move out of the tree. **Awaiting the owner.**

## Gates

- From a clean checkout with no `.venv`: `make dev-setup && make verify-static`
  is green.
- No path named in `CLAUDE.md` or `README.md` is missing from the tree.

## STOP conditions

- Do not delete tracked PDFs without asking. They may be submitted artifacts.
