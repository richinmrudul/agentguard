#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
out_dir="${1:-dist/stage1-runtime-images}"
mkdir -p "$out_dir"

gateway_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
agent_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222"
if [[ -f dist-runtime-image-local-digests.txt ]]; then
  gateway_digest="$(sed -n '1p' dist-runtime-image-local-digests.txt)"
  agent_digest="$(sed -n '2p' dist-runtime-image-local-digests.txt)"
fi

python scripts/validate_runtime_images.py \
  --source-commit "$commit" \
  --gateway-digest "$gateway_digest" \
  --agent-digest "$agent_digest" \
  --emit-manifest "$out_dir/stage1-runtime-image-manifest.json"

echo "Stage 1 runtime-image policy validated. Manifest: $out_dir/stage1-runtime-image-manifest.json"
