# Benchmark Pack Index

Benchmark pack indexes are static YAML or JSON files that describe curated
local benchmark packs. They let AgentGuard list, verify, and install packs from
a directory without running a service or executing benchmark code.

## Format

An index uses this schema:

```yaml
schema: agentguard.benchmark-pack-index
schema_version: 1
index_id: agentguard-local
generated_at: "2026-06-21T00:00:00Z"
packs:
  - pack_id: benchmark-pack-example
    pack_version: 1.0.0
    title: Example benchmark pack
    description: Example-only metadata.
    categories: [test_tampering]
    tags: [example]
    benchmark_ids: [auth_bug]
    benchmark_versions:
      auth_bug: 1
    pack_digest: "0000000000000000000000000000000000000000000000000000000000000000"
    size_bytes: 0
    source:
      type: url
      path: https://example.invalid/agentguard/auth-benchmark.zip
    signature:
      key_id: example-key
      signature_path: auth-benchmark.sig.json
    compatibility:
      min_agentguard_version: 0.1.0
    created_at: "1970-01-01T00:00:00Z"
    license: MIT
```

`pack_version` and compatibility versions use strict `MAJOR.MINOR.PATCH`
semver. Duplicate `pack_id` and `pack_version` pairs are rejected. Local file
sources may be absolute or relative to the index file. Relative paths must not
contain `..`. URL sources are metadata only in this phase.

## Workflow

Create an index from one or more local packs:

```bash
agentguard benchmarks pack index create \
  --pack /tmp/auth-benchmark.zip \
  --signature /tmp/auth-benchmark.sig.json \
  --base-dir /tmp \
  --output /tmp/pack-index.yaml \
  --force
```

List entries:

```bash
agentguard benchmarks pack index list /tmp/pack-index.yaml
```

Verify the index and referenced local packs:

```bash
agentguard benchmarks pack index verify /tmp/pack-index.yaml
```

Install the latest semver version for a pack ID:

```bash
agentguard benchmarks pack index install /tmp/pack-index.yaml \
  --pack benchmark-pack-... \
  --dest /tmp/imported-benchmarks \
  --dry-run
```

Use `--version` to select a specific version. Use `show` to inspect detailed
metadata for one selected entry.

## Trust Policy Integration

When an index entry includes a detached signature path, `index verify` can
enforce a local trust policy:

```bash
agentguard benchmarks pack index verify /tmp/pack-index.yaml \
  --trust-policy /tmp/pack-trust.yaml
```

`index install --trust-policy ...` passes the indexed signature to the existing
pack import gate. If the policy requires trusted signatures and verification
fails, installation is refused before extraction. A trusted signature only means
the pack root digest was signed by a trusted local key; it does not mean the
benchmark is safe to execute.

## Security Model

Index verification treats the index and all referenced packs as untrusted:

- validates the index schema and strict semver fields
- rejects duplicate pack ID/version pairs
- rejects path traversal in local source and signature paths
- checks every referenced local pack exists
- recomputes the raw pack archive SHA-256 before import
- runs full benchmark pack verification
- verifies signature metadata and optional local trust policies
- never executes imported benchmark files

URL entries are listed but not downloaded or installed. Automatic remote
downloads are intentionally deferred until a future phase with explicit network
flags, digest enforcement, and tests.

## Local-First Distribution

A curated repository can commit an illustrative or real index file next to
packs and signatures. Consumers can clone or copy that directory, run
`index list`, verify digests and trust policy, then import into a review
directory. No network trust registry is consulted.

The committed `examples/benchmarks/pack-index.yaml` includes illustrative
metadata for `adversarial-core` so local tooling can list the pack alongside
the older auth example. The source uses an `example.invalid` URL and is not
downloaded by AgentGuard in this phase; the runnable in-repo entrypoint is the
suite at `examples/suites/adversarial_core.yaml`.

## Limitations

Indexes do not replace pack verification, signature policy, or human review.
They do not sandbox benchmark execution, certify benchmark quality, or fetch
remote URLs. Local file sources are resolved relative to the index file, so move
packs and signatures together when sharing a directory.
