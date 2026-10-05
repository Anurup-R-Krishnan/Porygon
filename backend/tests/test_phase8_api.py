from porygon_api.main import app, vulnerability_policy


def test_phase8_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]
    required = {
        "/api/v1/vulnerability-policy",
        "/operator/v1/image-scans",
        "/internal/v1/image-scans/claim",
        "/internal/v1/image-scans/{scan_id}/renew",
        "/internal/v1/image-scans/{scan_id}/complete",
        "/internal/v1/image-scans/{scan_id}/fail",
        "/api/v1/image-scans",
        "/api/v1/image-scans/{scan_id}",
        "/api/v1/image-scans/{scan_id}/sbom",
        "/api/v1/image-scans/{scan_id}/report",
        "/api/v1/vulnerabilities",
        "/api/v1/vulnerability-intel/{cve_id}",
    }
    assert required.issubset(paths)


def test_vulnerability_policy_forbids_exploitation_claims() -> None:
    policy = vulnerability_policy()
    assert policy["scanner"]["pinned_version"] == "0.72.0"
    assert "No stage proves exploitation" in policy["claim_boundary"]
