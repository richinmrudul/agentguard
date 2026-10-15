#!/usr/bin/env bash
set -euo pipefail

source_dir="${1:?usage: verify_reviewed_codex_model.sh SOURCE_DIR}"
source_dir="$(cd "$source_dir" && pwd -P)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
patch="$repo_root/runtime-images/codex-agent/model-gpt-5.2-2025-12-11.patch"

expected_commit=ff6aec96948b70d94983af2641a6b67c94faeff5
expected_tag=8b9fa496bbf2c47aebd62e85a080b9a522a455b5
expected_tree=406dfdd5c68f303a3a8d04f32b3965b3b0ca0361
expected_lock=4fab6fe99180e2b8f305bd4b33c1b4bd825e3fa4cdef1045be750843bd3d431e
expected_license=d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc
expected_notice=9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915
expected_patch=f0cfb22492f69e71b6124c45afe5809ba1dcd0f9f63c3ac2bdce990987be44eb

test "$(git -C "$source_dir" rev-parse HEAD)" = "$expected_commit"
test "$(git -C "$source_dir" rev-parse refs/tags/rust-v0.159.2)" = "$expected_tag"
test "$(git -C "$source_dir" rev-parse 'HEAD^{tree}')" = "$expected_tree"
test -z "$(git -C "$source_dir" status --porcelain)"
printf '%s  %s\n' "$expected_lock" "$source_dir/codex-rs/Cargo.lock" | sha256sum --check --status
printf '%s  %s\n' "$expected_license" "$source_dir/LICENSE" | sha256sum --check --status
printf '%s  %s\n' "$expected_notice" "$source_dir/NOTICE" | sha256sum --check --status
printf '%s  %s\n' "$expected_patch" "$patch" | sha256sum --check --status
[[ "$(rustc --version)" == "rustc 1.95.0 "* ]]
git -C "$source_dir" apply --unidiff-zero --check "$patch"
git -C "$source_dir" apply --unidiff-zero "$patch"
git -C "$source_dir" diff --check

(
  cd "$source_dir/codex-rs"
  cargo test --locked -p codex-models-manager dated_gpt_5_2_snapshot_has_exact_bundled_metadata
  cargo build --locked --release --target x86_64-unknown-linux-musl -p codex-cli --bin codex
)

binary="$source_dir/codex-rs/target/x86_64-unknown-linux-musl/release/codex"
test -x "$binary"
"$binary" --version
sha256sum "$binary"
