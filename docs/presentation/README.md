# Panel review deck

`porygon_review.tex` fills the department's Phase 2 review template with this
project's real content and measured numbers. Build it with:

```bash
pdflatex porygon_review.tex && pdflatex porygon_review.tex
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
