//! Candidate-only authorization projection and one-shot Unix credential client.

use crate::config::{Scope, valid_digest, valid_id};
use crate::protocol::parse_json;
use crate::{Denial, MODEL, PRICING_DIGEST, PROVIDER, Result, canonical, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SOCKET_PATH: &str = "/stage1-credential.sock";
const MAX_PROJECTION: usize = 8192;
const MAX_FRAME: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema: String,
    pub schema_version: u64,
    pub digest: String,
    pub id: String,
    pub not_before_epoch: u64,
    pub expires_at_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedDigest {
    pub id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    pub publication_state: String,
    pub subject: String,
    pub canonical_identity: String,
    pub binary_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub publication_state: String,
    pub subject: String,
    pub canonical_identity: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub model: String,
    pub destination: String,
    pub operations: Vec<Operation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub schema: String,
    pub schema_version: u64,
    pub scope_digest: String,
    pub study_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_turns: u64,
    pub max_generation_requests: u64,
    pub max_count_requests: u64,
    pub max_trial_seconds: u64,
    pub max_trial_input_tokens: u64,
    pub max_trial_output_tokens: u64,
    pub max_trial_total_tokens: u64,
    pub max_trial_cost_usd: String,
    pub max_study_cost_usd: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub schema_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub schema: String,
    pub schema_version: u64,
    pub mode: String,
    pub authorization: Authorization,
    pub study_id: String,
    pub trial_id: String,
    pub replay_id: String,
    pub plan_digest: String,
    pub profile: NamedDigest,
    pub fixture: NamedDigest,
    pub gateway: Gateway,
    pub agent: Agent,
    pub provider: Provider,
    pub credential_env_name: String,
    pub pricing_digest: String,
    pub ledger: Ledger,
    pub limits: Limits,
    pub evidence: Evidence,
    pub redaction_digest: String,
    pub run_nonce: String,
    pub broker_protocol_version: u64,
}

pub fn parse_rehearsal(raw: &[u8], scope: &Scope, trial_id: &str, now: u64) -> Result<(Projection, String)> {
    let value = parse_json(raw, MAX_PROJECTION).map_err(|_| Denial::InvalidConfig)?;
    if canonical(&value)? != raw {
        return Err(Denial::InvalidConfig);
    }
    let parsed: Projection = serde_json::from_value(value.clone()).map_err(|_| Denial::InvalidConfig)?;
    let projection_digest = digest(&value)?;
    parsed.validate(scope, trial_id, now)?;
    Ok((parsed, projection_digest))
}

impl Projection {
    fn validate(&self, scope: &Scope, trial_id: &str, now: u64) -> Result<()> {
        let candidate = "candidate-rehearsal";
        let auth_digest = self.authorization.digest.strip_prefix("sha256:").ok_or(Denial::InvalidConfig)?;
        if self.schema != "agentguard.stage1-live-capability-projection"
            || self.schema_version != 1
            || self.mode != candidate
            || self.authorization.schema != "agentguard.live-study-authorization"
            || self.authorization.schema_version != 1
            || !valid_id(&self.study_id)
            || self.study_id != format!("study-{}", &self.plan_digest.get(7..31).ok_or(Denial::InvalidConfig)?)
            || !valid_id(&self.trial_id)
            || self.trial_id != trial_id
            || !valid_id(&self.profile.id)
            || !valid_id(&self.fixture.id)
            || self.gateway.publication_state != candidate
            || self.agent.publication_state != candidate
            || self.provider.id != PROVIDER
            || self.provider.model != MODEL
            || self.provider.destination != "api.openai.com:443"
            || self.provider.operations != [
                Operation { method: "POST".into(), path: "/v1/responses/input_tokens".into() },
                Operation { method: "POST".into(), path: "/v1/responses".into() },
            ]
            || self.credential_env_name != "CODEX_API_KEY"
            || self.pricing_digest != PRICING_DIGEST
            || self.ledger.schema != "agentguard.stage1-study-ledger"
            || self.ledger.schema_version != 1
            || self.ledger.study_id != self.study_id
            || self.evidence.schema != "agentguard.stage1-metering-evidence"
            || self.evidence.schema_version != 2
            || self.broker_protocol_version != 1
            || self.run_nonce.len() != 64
            || !self.run_nonce.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.authorization.not_before_epoch > now
            || now >= self.authorization.expires_at_epoch
            || self.authorization.expires_at_epoch - now > 7 * 24 * 60 * 60
            || self.authorization.id.is_empty()
            || !valid_digest(&self.replay_id)
        {
            return Err(Denial::InvalidConfig);
        }
        for field in [
            &self.authorization.digest, &self.plan_digest, &self.profile.digest,
            &self.fixture.digest, &self.gateway.subject, &self.gateway.canonical_identity,
            &self.gateway.binary_digest, &self.agent.subject,
            &self.agent.canonical_identity, &self.pricing_digest,
            &self.ledger.scope_digest, &self.redaction_digest,
        ] {
            if !valid_digest(field) {
                return Err(Denial::InvalidConfig);
            }
        }
        let expected_replay = digest(&json!({
            "authorization_digest": auth_digest,
            "trial_id": self.trial_id,
            "nonce": self.run_nonce,
        }))?;
        if self.replay_id != expected_replay
            || self.authorization.digest != scope.authorization_digest
            || self.plan_digest != scope.plan_digest
            || self.profile.digest != scope.profile_digest
            || self.pricing_digest != scope.pricing_digest
            || self.redaction_digest != scope.redaction_digest
            || self.ledger.scope_digest != scope.canonical_digest()?
            || !scope.trial_ids.iter().any(|id| id == trial_id)
            || self.limits.max_generation_requests != scope.max_trial_generations
            || self.limits.max_count_requests != scope.max_trial_counts
            || self.limits.max_trial_seconds != scope.max_trial_seconds
            || self.limits.max_trial_input_tokens != scope.max_trial_input_tokens
            || self.limits.max_trial_output_tokens != scope.max_trial_output_tokens
            || self.limits.max_trial_total_tokens != scope.max_trial_total_tokens
            || self.limits.max_trial_cost_usd != scope.max_trial_cost_usd
            || self.limits.max_study_cost_usd != scope.max_study_cost_usd
            || self.limits.max_turns < scope.max_trial_generations
        {
            return Err(Denial::InvalidConfig);
        }
        Ok(())
    }

    pub fn broker_request(&self, projection_digest: &str) -> Result<Vec<u8>> {
        if !valid_digest(projection_digest) {
            return Err(Denial::InvalidConfig);
        }
        let value = json!({
            "schema": "agentguard.stage1-credential-handoff",
            "schema_version": 1,
            "binding": {
                "authorization_digest": self.authorization.digest,
                "projection_digest": projection_digest,
                "nonce": self.run_nonce,
                "study_id": self.study_id,
                "trial_id": self.trial_id,
                "gateway_subject": self.gateway.subject,
                "gateway_canonical_identity": self.gateway.canonical_identity,
                "gateway_binary_digest": self.gateway.binary_digest,
                "agent_subject": self.agent.subject,
                "agent_canonical_identity": self.agent.canonical_identity,
                "model": self.provider.model,
                "destination": self.provider.destination,
                "pricing_digest": self.pricing_digest,
                "credential_env_name": self.credential_env_name,
                "expires_at_epoch": self.authorization.expires_at_epoch,
            }
        });
        let mut bytes = canonical(&value)?;
        bytes.pop(); // Broker v1 frames canonical JSON without a trailing newline.
        if bytes.len() > MAX_FRAME {
            return Err(Denial::InvalidConfig);
        }
        Ok(bytes)
    }
}

pub struct Credential(Vec<u8>);

impl Credential {
    pub fn bytes(&self) -> &[u8] { &self.0 }
    pub fn into_bytes(mut self) -> Vec<u8> { std::mem::take(&mut self.0) }
}

impl Drop for Credential {
    fn drop(&mut self) { self.0.fill(0); }
}

pub fn request_fake_credential(projection: &Projection, projection_digest: &str) -> Result<Credential> {
    let metadata = fs::symlink_metadata(SOCKET_PATH).map_err(|_| Denial::InvalidConfig)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 65532
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Denial::InvalidConfig);
    }
    let mut stream = UnixStream::connect(Path::new(SOCKET_PATH)).map_err(|_| Denial::Io)?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).map_err(|_| Denial::Io)?;
    stream.set_write_timeout(Some(Duration::from_secs(3))).map_err(|_| Denial::Io)?;
    let request = projection.broker_request(projection_digest)?;
    stream.write_all(&(request.len() as u32).to_be_bytes()).map_err(|_| Denial::Io)?;
    stream.write_all(&request).map_err(|_| Denial::Io)?;
    stream.shutdown(std::net::Shutdown::Write).map_err(|_| Denial::Io)?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(|_| Denial::Io)?;
    let length = u32::from_be_bytes(header) as usize;
    if !(16..=512).contains(&length) { return Err(Denial::InvalidConfig); }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).map_err(|_| Denial::Io)?;
    let mut trailing = [0u8; 1];
    if stream.read(&mut trailing).map_err(|_| Denial::Io)? != 0
        || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        bytes.fill(0);
        return Err(Denial::InvalidConfig);
    }
    Ok(Credential(bytes))
}

pub fn running_binary_digest() -> Result<String> {
    let bytes = fs::read("/proc/self/exe").map_err(|_| Denial::InvalidConfig)?;
    if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
        return Err(Denial::InvalidConfig);
    }
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

pub fn now_epoch() -> Result<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|value| value.as_secs())
        .map_err(|_| Denial::InvalidConfig)
}
