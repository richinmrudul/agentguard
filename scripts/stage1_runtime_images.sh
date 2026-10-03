#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
out_dir="${1:-dist/stage1-runtime-images}"
mkdir -p "$out_dir"

python scripts/validate_runtime_images.py \
  --source-commit "$commit" \
  --emit-manifest "$out_dir/stage1-runtime-image-manifest.json"

echo "Stage 1 runtime-image policy validated. Manifest: $out_dir/stage1-runtime-image-manifest.json"
