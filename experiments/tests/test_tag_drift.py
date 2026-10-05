from __future__ import annotations

from experiments.tag_drift import build_mutable_alias, load_versions


def test_build_mutable_alias_uses_a_controlled_local_namespace_never_upstream():
    assert build_mutable_alias("nginx") == "porygon-study/nginx:mutable"
    assert build_mutable_alias("library/redis") == "porygon-study/library/redis:mutable"


def test_load_versions_finds_both_v1_and_v2_for_a_pinned_family():
    versions = load_versions("WL-NGX")
    assert "WL-NGX-V1" in versions
    assert "WL-NGX-V2" in versions
    assert versions["WL-NGX-V1"]["human_tag"] == "nginx:1.26.3-alpine"
    assert versions["WL-NGX-V2"]["human_tag"] == "nginx:1.28.0-alpine"
    assert versions["WL-NGX-V1"]["index_digest_ref"] != versions["WL-NGX-V2"]["index_digest_ref"]


def test_load_versions_rejects_a_family_with_only_one_pinned_version(tmp_path):
    doc = tmp_path / "scope.md"
    doc.write_text(
        "| `WL-FAKE-V1` | `fake:1.0` | `fake@sha256:" + "a" * 64 + "` |\n",
        encoding="utf-8",
    )
    import pytest
    from experiments import real

    with pytest.raises(real.PilotError, match="V1 and V2"):
        load_versions("WL-FAKE", doc=doc)
