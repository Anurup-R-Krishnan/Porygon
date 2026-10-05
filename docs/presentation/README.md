# Panel review deck

**Current deck: `porygon_review_v3.tex`.** `porygon_review_v2.tex` is
superseded and kept only for provenance (it carries a superseded notice on
its own first slide); v3 corrects a confirmatory/pilot evidence-class
mislabeling present throughout v2, restores foundational citations (Lin
1991, Forrest 1996) v2's bibliography had dropped, describes the current
broadened `POR-DET-004` rule instead of v2's fixed dual-use-tool name list,
and documents a second, later live XMRig run v2 does not include. Build
whichever `.tex` you need with:

```bash
pdflatex porygon_review_v3.tex && pdflatex porygon_review_v3.tex
```

Two passes are needed so the section navigation resolves. There are no external
image dependencies: every diagram is drawn in TikZ, and the deck compiles
without `logo.png` (add it beside the `.tex` and it is picked up automatically).

## Before presenting, replace

- Team number, register numbers, and the names of students 2-4
- Guide name and designation
- The four enrichment course titles, with the actual enrolled courses
- `logo.png` (institution logo, ~2.8 cm wide)

## References

The deck ships a self-contained bibliography so it builds anywhere. If
`IEEEtran.bst` is installed, delete the manual `thebibliography` frame and use
the `ref.bib` supplied here instead. **Verify every citation against the
publisher record before submission** - page ranges and DOIs were written from
memory and have not been checked against the originals.

## Keeping the numbers honest

Every figure in the deck comes from `docs/execution-status.md` and
`docs/final-verification-report.md`, which are regenerated from the immutable
run records. If you re-run the experiments, refresh those documents and update
the deck to match rather than editing the numbers by hand.
