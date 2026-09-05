from porygon_scanner.scanner import (
    database_cache_metadata,
    extract_cves,
    merge_intel,
    parse_epss,
    parse_kev,
)


def test_parse_epss_and_kev() -> None:
    epss = parse_epss({"data": [{"cve": "CVE-2025-12345", "epss": "0.42", "percentile": "0.91", "date": "2026-07-21"}]})
    kev = parse_kev({"vulnerabilities": [{"cveID": "CVE-2025-12345", "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Known"}]})
    merged = merge_intel(["CVE-2025-12345"], epss, kev, source_metadata={"partial": False})[0]
    assert merged["epss_score"] == 0.42
    assert merged["kev"] is True
    assert merged["source_metadata"]["epss_record_returned"] is True
    assert merged["source_metadata"]["kev_record_returned"] is True


def test_extract_cves_is_sorted_and_unique() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2025-0002"},
                    {"VulnerabilityID": "CVE-2025-0001"},
                    {"VulnerabilityID": "CVE-2025-0002"},
                ]
            }
        ]
    }
    assert extract_cves(report) == ["CVE-2025-0001", "CVE-2025-0002"]


def test_extract_cves_drops_non_cve_vulnerability_ids() -> None:
    # Some scanners/plugins emit vendor-specific advisory IDs (e.g. GHSA-*) in
    # the same field; only well-formed CVE IDs should be treated as CVEs.
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2025-0003"},
                    {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz"},
                    {"VulnerabilityID": "CVE-2025-1"},  # too few digits, not a valid CVE ID
                ]
            }
        ]
    }
    assert extract_cves(report) == ["CVE-2025-0003"]


def test_database_cache_metadata_hashes_reproducibility_files(tmp_path) -> None:
    db = tmp_path / "db"
    db.mkdir()
    (db / "metadata.json").write_text('{"UpdatedAt":"2026-07-21"}')
    (db / "trivy.db").write_bytes(b"database-content")
    records = database_cache_metadata(str(tmp_path))
    assert [row["path"] for row in records] == ["db/metadata.json", "db/trivy.db"]
    assert all(len(row["sha256"]) == 64 for row in records)
