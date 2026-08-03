import hashlib
import re
import struct
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
DEMO = DOCS / "assets" / "demo"
VIDEO = DEMO / "agentguard-v0.2.2-demo.mp4"
CAPTIONS = DEMO / "agentguard-v0.2.2-demo.vtt"
NOTES = DEMO / "README.md"
CHECKSUMS = DEMO / "SHA256SUMS"
PAGE = DOCS / "demo-video.md"
TIMESTAMP = re.compile(
    r"^(\d{2}):(\d{2}):(\d{2})\.(\d{3}) --> "
    r"(\d{2}):(\d{2}):(\d{2})\.(\d{3})$"
)


class _MkDocsLoader(yaml.SafeLoader):
    pass


_MkDocsLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:",
    lambda _loader, suffix, _node: f"python/name:{suffix}",
)


def _seconds(groups: tuple[str, ...]) -> float:
    hours, minutes, seconds, milliseconds = (int(value) for value in groups)
    return hours * 3600 + minutes * 60 + seconds + milliseconds / 1000


def _top_level_mp4_atoms(data: bytes) -> list[tuple[bytes, int]]:
    atoms: list[tuple[bytes, int]] = []
    offset = 0
    while offset + 8 <= len(data):
        size = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        header = 8
        if size == 1:
            assert offset + 16 <= len(data)
            size = struct.unpack(">Q", data[offset + 8 : offset + 16])[0]
            header = 16
        elif size == 0:
            size = len(data) - offset
        assert size >= header
        assert offset + size <= len(data)
        atoms.append((kind, offset))
        offset += size
    assert offset == len(data)
    return atoms


def test_demo_video_is_bounded_seekable_mp4_with_matching_checksum() -> None:
    data = VIDEO.read_bytes()
    assert 100_000 < len(data) < 10_000_000
    atoms = _top_level_mp4_atoms(data)
    kinds = [kind for kind, _offset in atoms]
    assert kinds[0] == b"ftyp"
    assert b"moov" in kinds
    assert b"mdat" in kinds
    assert kinds.index(b"moov") < kinds.index(b"mdat")

    digest, name = CHECKSUMS.read_text(encoding="ascii").strip().split("  ")
    assert name == VIDEO.name
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert hashlib.sha256(data).hexdigest() == digest


def test_demo_captions_are_valid_ordered_webvtt_within_duration() -> None:
    captions = CAPTIONS.read_text(encoding="utf-8")
    assert captions.startswith("WEBVTT\n\n")
    ranges: list[tuple[float, float]] = []
    for line in captions.splitlines():
        match = TIMESTAMP.fullmatch(line)
        if match:
            start = _seconds(match.groups()[:4])
            end = _seconds(match.groups()[4:])
            assert start < end
            ranges.append((start, end))
    assert len(ranges) == 8
    assert ranges == sorted(ranges)
    assert all(previous[1] <= current[0] for previous, current in zip(ranges, ranges[1:]))
    assert ranges[-1][1] <= 80.333


def test_demo_page_is_accessible_bounded_and_linked() -> None:
    page = PAGE.read_text(encoding="utf-8")
    assert (
        '<video controls preload="metadata" playsinline '
        'style="width: 100%; height: auto;"' in page
    )
    assert "autoplay" not in page.lower()
    assert 'poster="../assets/screenshots/agentguard-dashboard.png"' in page
    assert 'src="../assets/demo/agentguard-v0.2.2-demo.mp4"' in page
    assert 'type="video/mp4"' in page
    assert 'kind="captions"' in page
    assert 'src="../assets/demo/agentguard-v0.2.2-demo.vtt"' in page
    assert 'srclang="en"' in page
    assert "Open or download the MP4" in page
    assert "## Transcript" in page
    for target in (
        "quickstart.md",
        "demo.md",
        "showcase.md",
        "static-site.md",
        "screenshots.md",
    ):
        assert f"({target})" in page


def test_demo_navigation_readme_and_reproduction_record_are_safe() -> None:
    config = yaml.load(
        (ROOT / "mkdocs.yml").read_text(encoding="utf-8"),
        Loader=_MkDocsLoader,
    )
    getting_started = next(
        item["Getting Started"]
        for item in config["nav"]
        if isinstance(item, dict) and "Getting Started" in item
    )
    assert {"Product Demo Video": "demo-video.md"} in getting_started

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "https://richinmrudul.github.io/agentguard/demo-video/" in readme
    assert "<video" not in readme.lower()

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in (NOTES, CAPTIONS, PAGE)
    )
    assert "2e73384e3e8ebb5862cef68ea7073685fe3ad6cb" in combined
    assert "agentguard-evals==0.2.2" in combined
    assert "Asciinema 3.2.1" in combined
    assert "FFmpeg/ffprobe 8.1.2" in combined
    assert not re.search(r"(/Users/|/private/|[A-Za-z]:\\\\)", combined)


def test_demo_intermediates_are_absent_and_media_stays_outside_package() -> None:
    assert {path.name for path in DEMO.iterdir()} == {
        "README.md",
        "SHA256SUMS",
        "agentguard-v0.2.2-demo.mp4",
        "agentguard-v0.2.2-demo.vtt",
    }
    assert not list(DOCS.rglob("*.cast"))
    assert not list(DOCS.rglob("*.gif"))
    assert not list(DEMO.glob("*frame-*.png"))
    assert VIDEO.is_relative_to(DOCS)
    assert not VIDEO.is_relative_to(ROOT / "agentguard")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["agentguard*"]' in pyproject
