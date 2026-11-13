#!/usr/bin/env bash
set -euo pipefail

source_commit="${1:?usage: stage1_metering_security_build.sh FULL_SOURCE_COMMIT}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]
root="${2:-dist/stage1-metering-security}"
mkdir -p "$root"
root="$(cd "$root" && pwd -P)"
base='gcr.io/distroless/python3-debian13:nonroot@sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d'
syft='anchore/syft@sha256:cefadcf11bd9cce9e3ec5248bb1538a84e33d519486c1b4523ac155c9b5f5033'
trivy='aquasec/trivy@sha256:adbf5948d99de471725d37d2cfbd982178971d1cf081615284671d1c8ba99fb8'

docker version > "$root/docker-version.txt"
docker buildx version > "$root/buildx-version.txt"
docker image inspect "$base" > "$root/base.inspect.json"
mkdir -p .trivy-cache
docker run --rm -v "$root:/work" -v "$PWD/.trivy-cache:/root/.cache/" \
  "$trivy" --version > "$root/trivy-version.txt"

for build in a b; do
  image="agentguard-metering-security:$build"
  docker build --no-cache --pull=false --network=none --platform linux/amd64 \
    --build-arg "SOURCE_COMMIT=$source_commit" \
    -f runtime-images/stage1-metering/Dockerfile.security-candidate \
    -t "$image" .
  docker image inspect "$image" > "$root/$build.inspect.json"
  cid="$(docker create "$image")"
  docker export "$cid" -o "$root/$build.rootfs.tar"
  docker rm "$cid" >/dev/null
  python scripts/runtime_image_identity.py --image-role gateway --base-image "$base" \
    --inspect-json "$root/$build.inspect.json" --rootfs-tar "$root/$build.rootfs.tar" \
    --output "$root/$build.identity.json"
  docker save "$image" -o "$root/$build.image.tar"
  docker run --rm -v "$root:/work" "$syft" \
    "docker-archive:/work/$build.image.tar" -o "syft-json=/work/$build.sbom.json"
  docker run --rm -v "$root:/work" -v "$PWD/.trivy-cache:/root/.cache/" \
    "$trivy" image --input "/work/$build.image.tar" --format json \
    --output "/work/$build.trivy.json" --severity HIGH,CRITICAL \
    --exit-code 0 --skip-version-check
done

test -s .trivy-cache/trivy/db/metadata.json
cp .trivy-cache/trivy/db/metadata.json "$root/trivy-db-metadata.json"
python scripts/stage1_metering_security_evidence.py \
  --root "$root" --source-commit "$source_commit"
(
  cd "$root"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
