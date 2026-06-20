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

## Security Model

Pack verification treats the archive and manifest as untrusted input. It
recomputes every hash before trusting metadata and rejects:

- absolute paths and `..` traversal
- duplicate normalized paths
- missing or unlisted files
- hard links, device files, directories, and other special files
- absolute or traversing symlink targets
- files larger than 5 MiB and packs larger than 50 MiB
- registry/config/contract mismatches

Safe symlinks are allowed only when their target is relative and resolves within
the imported tree. Import creates regular files and safe symlinks only after
verification. It does not run setup scripts, benchmark commands, tests, agents,
post-install hooks, or imported code.

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

## Limitations

Packs are source distribution artifacts, not trusted packages. Verification
proves archive integrity and internal metadata consistency; it does not certify
that a benchmark is useful, fair, or safe to execute. Binary fixture files are
preserved as bytes, but benchmark configs, contracts, and registry fragments are
YAML and must remain parseable by the current AgentGuard schema.
