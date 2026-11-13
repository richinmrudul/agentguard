"""Fail-closed checks for the scratch gateway's build evidence."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from agentguard.evaluation.runtime_images import RuntimeImageError
from scripts.stage1_compiled_gateway_evidence import _extract_rootfs, _findings


def _tar_member(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(data)
    archive.addfile(member, io.BytesIO(data))


def _image_archive(
    root: Path, *, wrong_digest: bool = False, duplicate: bool = False,
    compressed: bool = False, wrong_diff_id: bool = False,
    stored_override: bytes | None = None, layer_count: int = 1,
    include_layer: bool = True, config_diff_ids: list[str] | None = None,
    config_path: str | None = None, extra_member: str | None = None,
) -> bytes:
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w:") as layer:
        _tar_member(layer, "stage1-metering-gateway", b"compiled-binary")
    layer_bytes = layer_buffer.getvalue()
    stored_layer = stored_override if stored_override is not None else (
        gzip.compress(layer_bytes, mtime=0) if compressed else layer_bytes
    )
    digest = hashlib.sha256(stored_layer).hexdigest()
    layer_name = f"blobs/sha256/{'0' * 64 if wrong_digest else digest}"
    diff_id = "0" * 64 if wrong_diff_id else hashlib.sha256(layer_bytes).hexdigest()
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": (
        config_diff_ids if config_diff_ids is not None else [f"sha256:{diff_id}"]
    )}}).encode()
    config_name = config_path or f"blobs/sha256/{hashlib.sha256(config).hexdigest()}"
    manifest = json.dumps([{"Config": config_name, "Layers": [layer_name] * layer_count}]).encode()
    image_buffer = io.BytesIO()
    with tarfile.open(fileobj=image_buffer, mode="w:") as image:
        _tar_member(image, "manifest.json", manifest)
        _tar_member(image, config_name, config)
        if include_layer:
            _tar_member(image, layer_name, stored_layer)
        if duplicate:
            _tar_member(image, layer_name, stored_layer)
        if extra_member:
            _tar_member(image, extra_member, b"unexpected")
    image_bytes = image_buffer.getvalue()
    (root / "gateway-a.image.tar").write_bytes(image_bytes)
    return layer_bytes


@pytest.mark.parametrize("compressed", [False, True])
def test_extracts_only_digest_verified_scratch_layer(tmp_path: Path, compressed: bool) -> None:
    expected = _image_archive(tmp_path, compressed=compressed)
    _extract_rootfs(tmp_path, "a")
    assert (tmp_path / "gateway-a.rootfs.tar").read_bytes() == expected


@pytest.mark.parametrize("wrong_digest,duplicate,wrong_diff_id", [
    (True, False, False), (False, True, False), (False, False, True),
])
def test_rejects_invalid_or_duplicated_image_layer(
    tmp_path: Path, wrong_digest: bool, duplicate: bool, wrong_diff_id: bool,
) -> None:
    _image_archive(tmp_path, wrong_digest=wrong_digest, duplicate=duplicate, wrong_diff_id=wrong_diff_id)
    with pytest.raises(RuntimeImageError):
        _extract_rootfs(tmp_path, "a")
    assert not (tmp_path / "gateway-a.rootfs.tar").exists()


@pytest.mark.parametrize("archive_options", [
    {"wrong_digest": True, "compressed": True},
    {"wrong_diff_id": True, "compressed": True},
    {"include_layer": False},
    {"layer_count": 0},
    {"layer_count": 2},
    {"config_diff_ids": ["sha256:" + "1" * 64, "sha256:" + "2" * 64]},
    {"config_diff_ids": ["SHA256:" + "1" * 64]},
    {"config_path": "blobs/sha256/" + "0" * 64},
    {"extra_member": "../escape"},
    {"extra_member": "manifest.json"},
    {"stored_override": b"not-a-tar-or-supported-compression"},
    {"stored_override": b"\x1f\x8b\x08\x00"},
])
def test_rejects_malformed_or_unsafe_oci_archive(
    tmp_path: Path, archive_options: dict[str, object],
) -> None:
    _image_archive(tmp_path, **archive_options)
    with pytest.raises((RuntimeImageError, tarfile.TarError, OSError, EOFError)):
        _extract_rootfs(tmp_path, "a")
    assert not (tmp_path / "gateway-a.rootfs.tar").exists()


def test_rejects_truncated_image_archive(tmp_path: Path) -> None:
    _image_archive(tmp_path)
    image = tmp_path / "gateway-a.image.tar"
    image.write_bytes(image.read_bytes()[:512])
    with pytest.raises((RuntimeImageError, tarfile.TarError, OSError)):
        _extract_rootfs(tmp_path, "a")
    assert not (tmp_path / "gateway-a.rootfs.tar").exists()


def test_empty_trivy_result_requires_empty_image_sbom() -> None:
    empty = {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": None}
    assert _findings(empty, 0) == []
    with pytest.raises(RuntimeImageError):
        _findings(empty, 1)
    with pytest.raises(RuntimeImageError):
        _findings({"SchemaVersion": 2, "Results": None}, 0)


def test_candidate_executable_has_no_live_or_public_transport_selection() -> None:
    source = Path(__file__).parents[2] / "runtime-images/stage1-metering-rust/src"
    main = (source / "main.rs").read_text(encoding="utf-8")
    session = (source / "session.rs").read_text(encoding="utf-8")
    assert 'if mock == rehearsal || std::env::var_os("CODEX_API_KEY").is_some()' in main
    assert "parse_rehearsal(&raw" in main
    assert "LocalTlsProvider" in main and "LocalTlsProvider" in session
    assert "mock_tls_request(" in session
    assert "live_tls_request(" not in main + session
    assert "STAGE1_RUST_LIVE" not in main
