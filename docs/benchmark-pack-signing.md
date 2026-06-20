# Benchmark Pack Signing

Benchmark pack signing adds optional detached signatures and local trust
policies for portable benchmark packs. Signing is not required for the existing
export, inspect, verify, or import workflows unless you explicitly provide a
trust policy.

## Threat Model

Pack verification already proves that the archive matches its manifest and that
the registry, configs, and contracts are internally consistent. Signing adds a
local authenticity check: the pack root digest was signed by a key that your
local policy trusts.

It does not make imported benchmark code safe to execute. A trusted signature
only means the signed digest came from a trusted key. Review imported fixtures,
configs, contracts, and docs before running them.

AgentGuard does not use a network trust registry. Trust policies are local YAML
files that you create and review.

## Algorithm

This release uses detached `HMAC-SHA256` signatures because the Python standard
library does not include Ed25519 and AgentGuard avoids adding a new crypto
runtime dependency for this phase.

This is a limited local-CI trust mode:

- the signing key and verification key both contain shared HMAC secret material
- private keys must never be committed
- verification keys are also sensitive unless your organization intentionally
  shares them with trusted CI
- HMAC signatures authenticate a digest to holders of the shared secret, but
  they do not provide public-key non-repudiation

If AgentGuard later adds an Ed25519 dependency, the signature schema can support
that as a new `algorithm` value.

## Key Generation

Generate keys into a secure local directory:

```bash
agentguard benchmarks pack keygen --output-dir /tmp/agentguard-pack-keys --name ci-pack-signer
```

The command writes:

- `<name>.private-key.json`
- `<name>.public-key.json`

The private key is written with restrictive permissions where the platform
supports `chmod`. The command prints warnings because both HMAC key files
contain secret material.

## Sign And Verify

Export and sign a pack:

```bash
agentguard benchmarks pack export --benchmark auth_bug --output /tmp/auth.zip --force
agentguard benchmarks pack sign /tmp/auth.zip \
  --key /tmp/agentguard-pack-keys/ci-pack-signer.private-key.json \
  --output /tmp/auth.sig.json
```

Verify a detached signature:

```bash
agentguard benchmarks pack verify-signature /tmp/auth.zip \
  --signature /tmp/auth.sig.json \
  --key /tmp/agentguard-pack-keys/ci-pack-signer.public-key.json
```

Signing refuses invalid packs. Signature verification verifies pack integrity
first, checks that the signature references the current pack root digest, then
checks the HMAC.

The detached signature JSON uses:

- `schema: agentguard.benchmark-pack-signature`
- `schema_version: 1`
- pack ID, pack version, and pack root digest
- key ID and signer name
- `algorithm: hmac-sha256`
- creation time
- strict base64 signature bytes

## Trust Policy

Initialize a local trust policy:

```bash
agentguard benchmarks pack trust init /tmp/pack-trust.yaml
agentguard benchmarks pack trust add-key /tmp/pack-trust.yaml \
  /tmp/agentguard-pack-keys/ci-pack-signer.public-key.json
agentguard benchmarks pack trust list /tmp/pack-trust.yaml
```

Trust policy schema:

```yaml
schema: agentguard.pack-trust-policy
schema_version: 1
trusted_keys:
  - key_id: abc123
    name: ci-pack-signer
    public_key_path: /secure/path/ci-pack-signer.public-key.json
required_signatures: 1
allow_unsigned: false
```

Verify a pack against policy:

```bash
agentguard benchmarks pack trust verify /tmp/auth.zip \
  --policy /tmp/pack-trust.yaml \
  --signature /tmp/auth.sig.json
```

`allow_unsigned: true` permits unsigned packs when no signatures are supplied.
Otherwise the policy requires at least `required_signatures` valid signatures
from trusted keys.

## Import Integration

Unsigned imports remain supported by default:

```bash
agentguard benchmarks pack import --pack /tmp/auth.zip --dest /tmp/imported
```

To require trust verification before import:

```bash
agentguard benchmarks pack import \
  --pack /tmp/auth.zip \
  --dest /tmp/imported \
  --trust-policy /tmp/pack-trust.yaml \
  --signature /tmp/auth.sig.json
```

Dry-run imports report trust status without extracting files:

```bash
agentguard benchmarks pack import \
  --pack /tmp/auth.zip \
  --dest /tmp/imported \
  --trust-policy /tmp/pack-trust.yaml \
  --signature /tmp/auth.sig.json \
  --dry-run
```

## CI Usage

A small CI flow can:

1. Store the HMAC verification key as a CI secret or otherwise protected file.
2. Check in a trust policy that references that protected path.
3. Download or copy a pack and detached signature.
4. Run `benchmarks pack trust verify`.
5. Run `benchmarks pack import --trust-policy ... --signature ... --dry-run`.
6. Review or audit imported benchmarks before executing them.

## Limitations

- HMAC is shared-secret trust, not public-key signing.
- Anyone with the verification key can also create signatures.
- Signatures authenticate the pack root digest only; they do not sandbox code.
- There is no remote trust discovery, revocation service, timestamp authority,
  or transparency log.
- Trust policy files are local configuration and must be reviewed like any
  other security-sensitive input.
