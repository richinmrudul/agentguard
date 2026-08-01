import binascii
import re
import struct
import zlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
ASSETS = DOCS / "assets" / "screenshots"
README = ROOT / "README.md"
MKDOCS = ROOT / "mkdocs.yml"
EXPECTED = {
    "agentguard-docs-home.png": (1440, 900),
    "agentguard-dashboard.png": (1440, 900),
    "agentguard-incident-detail.png": (1440, 1055),
    "agentguard-evaluation-evidence.png": (1440, 900),
}
IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
FORBIDDEN_METADATA_CHUNKS = {b"eXIf", b"tEXt", b"iTXt", b"zTXt"}


class _MkDocsLoader(yaml.SafeLoader):
    pass


_MkDocsLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/name:",
    lambda _loader, suffix, _node: f"python/name:{suffix}",
)


def _png(path: Path) -> tuple[int, int, list[bytes], bytes]:
    data = path.read_bytes()
    assert data.startswith(b"\x89PNG\r\n\x1a\n"), path
    offset = 8
    chunks: list[bytes] = []
    compressed = bytearray()
    width = height = 0
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        crc = struct.unpack(">I", data[offset + 8 + length : offset + 12 + length])[0]
        assert binascii.crc32(kind + payload) & 0xFFFFFFFF == crc, path
        chunks.append(kind)
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )
            assert (depth, color, compression, filtering, interlace) == (
                8,
                2,
                0,
                0,
                0,
            )
        elif kind == b"IDAT":
            compressed.extend(payload)
        offset += 12 + length
        if kind == b"IEND":
            break
    assert chunks[0] == b"IHDR"
    assert chunks[-1] == b"IEND"
    decoded = zlib.decompress(bytes(compressed))
    assert len(decoded) == height * (1 + width * 3)
    return width, height, chunks, data


def _markdown_images(path: Path) -> list[tuple[str, str]]:
    return IMAGE.findall(path.read_text(encoding="utf-8"))


def test_screenshot_pngs_are_valid_bounded_and_metadata_free() -> None:
    assert {path.name for path in ASSETS.glob("*.png")} == set(EXPECTED)
    total_size = 0
    for name, expected_dimensions in EXPECTED.items():
        path = ASSETS / name
        width, height, chunks, raw = _png(path)
        assert (width, height) == expected_dimensions
        assert 1000 <= width <= 2000
        assert 700 <= height <= 1400
        assert path.stat().st_size < 1_000_000
        assert FORBIDDEN_METADATA_CHUNKS.isdisjoint(chunks)
        for forbidden in (b"/Users/", b"/private/", b"Authorization", b"Bearer "):
            assert forbidden not in raw
        total_size += path.stat().st_size
    assert total_size < 3_000_000


def test_screenshot_references_resolve_and_have_meaningful_alt_text() -> None:
    sources = [
        README,
        DOCS / "index.md",
        DOCS / "screenshots.md",
    ]
    seen: set[str] = set()
    for source in sources:
        for alt, target in _markdown_images(source):
            if "assets/screenshots/" not in target:
                continue
            assert len(alt.strip()) >= 30
            assert alt.strip().lower() not in {"image", "screenshot"}
            assert not target.startswith(("data:", "http://", "https://"))
            assert "/raw/" not in target
            assert (source.parent / target).resolve().is_file()
            seen.add(Path(target).name)
    assert seen == set(EXPECTED)
    readme_screenshots = [
        target
        for _alt, target in _markdown_images(README)
        if "assets/screenshots/" in target
    ]
    assert readme_screenshots == [
        "docs/assets/screenshots/agentguard-dashboard.png"
    ]


def test_visual_tour_navigation_and_source_record_are_safe() -> None:
    config = yaml.load(MKDOCS.read_text(encoding="utf-8"), Loader=_MkDocsLoader)
    getting_started = next(
        item["Getting Started"]
        for item in config["nav"]
        if isinstance(item, dict) and "Getting Started" in item
    )
    assert {"Visual Tour": "screenshots.md"} in getting_started
    assert "/assets/screenshots/README.md" in config["not_in_nav"]

    notes = (ASSETS / "README.md").read_text(encoding="utf-8")
    assert "150709b3b790aba5c33d1918f00184d46868dd2e" in notes
    assert "package version\n`0.2.2`" in notes
    assert "No OCR utility was available" in notes
    assert not re.search(r"(/Users/|/private/var/|[A-Za-z]:\\\\)", notes)
    assert "github.com/raw" not in notes
