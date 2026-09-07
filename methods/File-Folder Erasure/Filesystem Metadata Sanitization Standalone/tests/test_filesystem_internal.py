import metadata_sanitizer.filesystem_internal as internal


def test_ntfs_is_not_claimed_supported(monkeypatch, tmp_path):
    monkeypatch.setattr(internal, "detect_filesystem", lambda target: "ntfs")
    result = internal.assess_internal_metadata(tmp_path)
    assert result.internal_metadata_status == "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND"
    assert "MFT" in " ".join(result.unsupported_reasons)


def test_ext4_requires_specific_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(internal, "detect_filesystem", lambda target: "ext4")
    result = internal.assess_internal_metadata(tmp_path)
    assert result.internal_metadata_status == "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND"
    assert "journal" in " ".join(result.unsupported_reasons)


def test_btrfs_requires_specific_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(internal, "detect_filesystem", lambda target: "btrfs")
    result = internal.assess_internal_metadata(tmp_path)
    assert result.internal_metadata_status == "REQUIRES_FILESYSTEM_SPECIFIC_BACKEND"
    assert "copy-on-write" in " ".join(result.unsupported_reasons)


def test_unknown_filesystem_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(internal, "detect_filesystem", lambda target: None)
    result = internal.assess_internal_metadata(tmp_path)
    assert result.internal_metadata_status == "UNSUPPORTED"
    assert result.recommended_route.startswith("Do not guess")
