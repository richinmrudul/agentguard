"""Fail-closed checks for the scratch gateway's build evidence."""

from __future__ import annotations

import hashlib
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


def _image_archive(root: Path, *, wrong_digest: bool = False, duplicate: bool = False) -> bytes:
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w:") as layer:
        _tar_member(layer, "stage1-metering-gateway", b"compiled-binary")
    layer_bytes = layer_buffer.getvalue()
    digest = hashlib.sha256(layer_bytes).hexdigest()
    layer_name = f"blobs/sha256/{'0' * 64 if wrong_digest else digest}"
    manifest = json.dumps([{"Layers": [layer_name]}]).encode()
    image_buffer = io.BytesIO()
    with tarfile.open(fileobj=image_buffer, mode="w:") as image:
        _tar_member(image, "manifest.json", manifest)
        _tar_member(image, layer_name, layer_bytes)
        if duplicate:
            _tar_member(image, layer_name, layer_bytes)
    image_bytes = image_buffer.getvalue()
    (root / "gateway-a.image.tar").write_bytes(image_bytes)
    return layer_bytes


def test_extracts_only_digest_verified_scratch_layer(tmp_path: Path) -> None:
    expected = _image_archive(tmp_path)
    _extract_rootfs(tmp_path, "a")
    assert (tmp_path / "gateway-a.rootfs.tar").read_bytes() == expected


@pytest.mark.parametrize("wrong_digest,duplicate", [(True, False), (False, True)])
def test_rejects_invalid_or_duplicated_image_layer(
    tmp_path: Path, wrong_digest: bool, duplicate: bool,
) -> None:
    _image_archive(tmp_path, wrong_digest=wrong_digest, duplicate=duplicate)
    with pytest.raises(RuntimeImageError):
        _extract_rootfs(tmp_path, "a")
    assert not (tmp_path / "gateway-a.rootfs.tar").exists()


def test_empty_trivy_result_requires_empty_image_sbom() -> None:
    empty = {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": None}
    assert _findings(empty, 0) == []
    with pytest.raises(RuntimeImageError):
        _findings(empty, 1)
    with pytest.raises(RuntimeImageError):
        _findings({"SchemaVersion": 2, "Results": None}, 0)
