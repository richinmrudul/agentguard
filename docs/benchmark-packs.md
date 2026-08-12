# Benchmark Packs

Benchmark packs are portable, deterministic `.zip` archives for moving
AgentGuard benchmark families between repositories. A pack contains the selected
registry fragment, contracts, configs, fixture repositories, and optional docs.
Importing a pack never executes benchmark code.

## Format

AgentGuard uses zip instead of tar so pack verification can inspect every member
without extraction. Export writes members in sorted order with a fixed timestamp
of `1980-01-01T00:00:00Z`. The manifest `created_at` is also fixed to
`1970-01-01T00:00:00Z`, so identical inputs produce byte-identical packs.

Every pack contains `manifest.json` with:

- `schema: agentguard.benchmark-pack`
- `schema_version: 1`
- deterministic `pack_id`, `pack_version`, and `root_digest`
- AgentGuard version and source commit when available
- benchmark IDs and versions
- every file path, type, size, and SHA-256 hash
- entrypoint registry fragment path
- contract, config, repo fixture, and docs paths
- optional source provenance

Pack-local paths are normalized:

- `registry/registry.yaml`
- `configs/*.yaml`
- `contracts/*.yaml`
- `repos/<fixture>/...`
- optional `docs/*.md`

Config `repo_template` values and contract `config` values are rewritten to
these pack-local paths during export.

Pack paths use one portable filesystem identity on every platform. Each path
component is normalized to Unicode NFC and case-folded for collision checks.
AgentGuard also rejects Windows reserved device names, trailing dots or spaces,
non-portable Windows characters, drive-like paths, non-canonical separators,
and any file path that is a prefix of another member. This deliberately rejects
some names that Linux can store so a pack verified on Linux has the same member
identity when imported on case-insensitive macOS or Windows filesystems.

## Workflow

Export one or more benchmark families:

```bash
agentguard benchmarks pack export \
  --benchmark auth_bug \
  --benchmark symlink_path_traversal \
  --output /tmp/agentguard-benchmarks.zip \
  --include-docs
```

Inspect without extraction:

```bash
agentguard benchmarks pack inspect /tmp/agentguard-benchmarks.zip
```

Verify schema, hashes, paths, and registry/config/contract consistency:

```bash
agentguard benchmarks pack verify /tmp/agentguard-benchmarks.zip
```

Optionally sign packs and enforce local trust policies before import. See
[Benchmark Pack Signing](benchmark-pack-signing.md) for key generation,
detached signatures, trust policy verification, CI usage, and limitations.
Curated local directories can also publish a static
[Benchmark Pack Index](benchmark-pack-index.md) that lists pack metadata,
archive digests, signature paths, and install targets without requiring a
server.

Import into a review directory:

```bash
agentguard benchmarks pack import \
  --pack /tmp/agentguard-benchmarks.zip \
  --dest examples/imported-benchmarks \
  --registry-out examples/imported-benchmarks/registry.yaml \
  --suite-out examples/imported-benchmarks/suite.yaml
```

Use `--dry-run` first to see planned writes and collisions. Existing files are
never overwritten unless `--force` is supplied.

Create and consume a local index:

```bash
agentguard benchmarks pack index create \
  --pack /tmp/agentguard-benchmarks.zip \
  --signature /tmp/agentguard-benchmarks.sig.json \
  --base-dir /tmp \
  --output /tmp/pack-index.yaml
agentguard benchmarks pack index verify /tmp/pack-index.yaml --trust-policy /tmp/trust.yaml
agentguard benchmarks pack index install /tmp/pack-index.yaml \
  --pack benchmark-pack-... \
  --dest /tmp/imported-benchmarks \
  --dry-run
```

## Security Model

Pack verification treats the archive and manifest as untrusted input. It
recomputes every hash before trusting metadata and rejects:

- absolute paths and `..` traversal
- exact, case-equivalent, or Unicode-normalization-equivalent paths
- non-canonical separators, Windows reserved names, and trailing-dot/space names
- file/directory-prefix and symlink-member path collisions
- missing or unlisted files
- hard links, device files, directories, and other special files
- absolute or traversing symlink targets
- files larger than 5 MiB and packs larger than 50 MiB
- registry/config/contract mismatches

Safe symlinks are allowed only when their target is relative and resolves within
the imported tree. Import validates and prepares regular files, safe symlinks,
and optional registry and suite outputs before writing. The final writes are a
rollback-capable transaction, so a late preparation or write failure does not
leave a partial imported pack. It does not run setup scripts, benchmark
commands, tests, agents, post-install hooks, or imported code.

Displayed metadata is kept concise, and file hashes are printed instead of file
contents. Secrets, `.agentguard` outputs, caches, databases, logs, bytecode, and
generated reports are excluded from export.

## Fuzz Promotions

`agentguard benchmarks fuzz --promote-failures ...` writes reviewable fixture or
patch promotion directories. Review those promotions manually, convert accepted
cases into ordinary registry entries, configs, contracts, and fixtures, then
export them with `benchmarks pack export`. Packs deliberately distribute only
registered benchmarks, not ad hoc fuzz output directories.

## Reviewing Imported Benchmarks

Recommended review steps:

1. Run `benchmarks pack verify` before import.
2. Import with `--dry-run` and inspect planned paths.
3. Import into a dedicated directory, not the core suite.
4. Review the registry fragment, contracts, configs, fixture scripts, and docs.
5. Validate generated suites with `agentguard benchmarks generate-suite` or
   `--suite-out`.
6. Run static contract audit before any execution.

Imported packs do not modify `examples/suites/core.yaml` unless you explicitly
copy or reference the imported suite yourself.

## Adversarial Core Foundation

The repository also includes an initial local-first adversarial pack descriptor:

```text
examples/benchmarks/adversarial-core.yaml
examples/suites/adversarial_core.yaml
docs/results/adversarial-pack-summary.json
docs/results/adversarial-pack-summary.md
docs/results/adversarial-metrics.json
docs/results/adversarial-metrics.md
```

This descriptor is not a generated zip artifact. It documents the curated
post-v0.1 scenario set that can be exported later with the same pack tooling.
The runnable suite is deterministic, network-free, and Docker-free:

```bash
agentguard suite examples/suites/adversarial_core.yaml --allow-failures
.venv/bin/python scripts/adversarial_metrics.py --check
```

Future scenarios should be added as ordinary registry entries, configs,
contracts, and fixture repos first, then referenced from the descriptor and
summary and metrics artifacts. Keep each scenario bounded, local, sanitized,
and explicit about threat model, safe behavior, unsafe behavior, expected
guards, and known limitations. The metrics script is metadata validation; it
does not commit runtime `.agentguard` output. The current descriptor also
records opt-in built-in secret detector coverage for the fake secret-content
validation scenarios.

## Limitations

Packs are source distribution artifacts, not trusted packages. Verification
proves archive integrity and internal metadata consistency; it does not certify
that a benchmark is useful, fair, or safe to execute. Binary fixture files are
preserved as bytes, but benchmark configs, contracts, and registry fragments are
YAML and must remain parseable by the current AgentGuard schema.
