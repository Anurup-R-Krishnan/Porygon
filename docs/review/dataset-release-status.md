# Dataset release evidence — 25 October 2026

## Prepared locally

Porygon Pilot Dataset v1 (`1.0.0`) is in
[`datasets/porygon-pilot-v1.0.0`](../../datasets/porygon-pilot-v1.0.0/readme.md).
It contains 216 original completed trial JSON records, a derived CSV index,
image/run/study provenance, metadata, annotation guidelines, a data dictionary,
source hashes and package hashes. The offline verifier checks inventory,
checksums, unique trial IDs, labels and the 18-cell × 12-replica matrix.

Labels: 72 controlled non-attack-like trials and 144 controlled attack-like
simulations. All release records remain pilot and research-ineligible for
confirmatory claims. No real exploit was executed.

## Remaining requirements from Technical Enrichment Activities.pdf

The dataset-release activity expects a public repository, README, metadata,
annotation guidelines, license information, version and organized data. This
package supplies the local data/documentation portion. The following remain:

1. Guide confirms prior approval and accepts the metadata-only dataset scope.
2. CC BY 4.0 was authorized by the owner on 25 October 2026 and is included.
3. Publish the approved package to GitHub, Zenodo or another accepted repository.
4. Record the release URL and version and submit evidence through the guide.

No marks, public release, guide approval or official submission are claimed.
The college deadline is one week before the last working day of semester seven;
the actual calendar date is not present in the supplied PDF.

## Next technical deliverable

Verify and record the end-to-end working demo with a short video, setup commands,
model/config versions, sample outputs and a command/script regenerating the shown
metrics. Only PostgreSQL was running when checked on 25 October; runtime readiness
has not been established by the dataset packaging work.

For a richer dataset edition, export sanitized source process events, per-arm
predictions and exact analysis membership. This draft cannot regenerate the
existing 53-benign/96-scenario analysis from its collection metadata alone.
