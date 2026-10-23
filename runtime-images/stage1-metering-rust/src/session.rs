use crate::config::valid_id;
use crate::http::UpstreamResponse;
use crate::ledger::StudyLedger;
use crate::pricing::Usage;
use crate::protocol::{count_payload, input_count, normalize_generation, terminal_stream};
use crate::{Denial, MAX_REQUEST_BYTES, Result, canonical};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub trait Provider {
    fn post(&self, path: &str, body: &[u8]) -> Result<UpstreamResponse>;
}

pub struct Session<P: Provider> {
    ledger: StudyLedger,
    trial_id: String,
    synthetic_token: Vec<u8>,
    provider: P,
    output_cap: u64,
    evidence: PathBuf,
    events: Vec<Value>,
    closed: bool,
}

impl<P: Provider> Session<P> {
    pub fn new(
        ledger: StudyLedger,
        trial_id: &str,
        synthetic_token: &[u8],
        provider: P,
        output_cap: u64,
        evidence: PathBuf,
    ) -> Result<Self> {
        if !ledger.scope.trial_ids.iter().any(|id| id == trial_id)
            || !valid_id(trial_id)
            || synthetic_token.len() < 16
            || synthetic_token.len() > 128
            || !synthetic_token.iter().all(u8::is_ascii_graphic)
            || !(1..=4096).contains(&output_cap)
            || evidence.exists()
        {
            return Err(Denial::InvalidConfig);
        }
        let parent = evidence.parent().ok_or(Denial::InvalidConfig)?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| Denial::InvalidConfig)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Denial::InvalidConfig);
        }
        Ok(Self {
            ledger,
            trial_id: trial_id.into(),
            synthetic_token: synthetic_token.to_vec(),
            provider,
            output_cap,
            evidence,
            events: Vec::new(),
            closed: false,
        })
    }

    pub fn process(&mut self, body: &[u8], supplied_token: &[u8]) -> Result<Vec<u8>> {
        if self.closed {
            return Err(Denial::Uncertain);
        }
        let outcome = self.generate(body, supplied_token);
        if let Err(ref failure) = outcome {
            self.closed = true;
            let _ = self.ledger.fail(&self.trial_id);
            self.events.push(json!({
                "schema": "agentguard.stage1-metering-event",
                "schema_version": 2,
                "trial_id": self.trial_id,
                "status": "rejected",
                "error_class": error_class(*failure),
            }));
        }
        if self.write_evidence().is_err() {
            self.closed = true;
            let _ = self.ledger.fail(&self.trial_id);
            return Err(Denial::Uncertain);
        }
        outcome
    }

    pub fn reject(&mut self) {
        let _ = self.process(&[], &[]);
    }

    fn deadline(&self) -> Result<()> {
        let snapshot = self.ledger.snapshot()?;
        let started = snapshot
            .trials
            .get(&self.trial_id)
            .ok_or(Denial::Uncertain)?
            .started_at;
        if let Some(started) = started {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Denial::Uncertain)?
                .as_secs();
            if now < started || now - started >= self.ledger.scope.max_trial_seconds {
                return Err(Denial::Budget);
            }
        }
        Ok(())
    }

    fn generate(&mut self, body: &[u8], supplied_token: &[u8]) -> Result<Vec<u8>> {
        if body.is_empty()
            || body.len() > MAX_REQUEST_BYTES
            || supplied_token.len() != self.synthetic_token.len()
            || supplied_token.ct_eq(&self.synthetic_token).unwrap_u8() != 1
        {
            return Err(Denial::InvalidRequest);
        }
        self.deadline()?;
        let request = normalize_generation(body, self.output_cap)?;
        let request_bytes = canonical(&request)?;
        let fingerprint = format!("{:x}", Sha256::digest(&request_bytes));
        let count_id = format!("count-{}", &fingerprint[..48]);
        let generation_id = format!("generation-{}", &fingerprint[..48]);
        self.ledger.count(&self.trial_id, &count_id)?;
        let count_bytes = count_payload(&request)?;
        let count_reply = self
            .provider
            .post("/v1/responses/input_tokens", &count_bytes)?;
        if count_reply.status != 200 || count_reply.content_type != "application/json" {
            return Err(Denial::InvalidProvider);
        }
        let counted = input_count(&count_reply.body)?;
        self.deadline()?;
        self.ledger
            .reserve(&self.trial_id, &generation_id, counted, self.output_cap)?;
        let generation_reply = self.provider.post("/v1/responses", &request_bytes)?;
        if generation_reply.status != 200 || generation_reply.content_type != "text/event-stream" {
            return Err(Denial::InvalidProvider);
        }
        let terminal = terminal_stream(&generation_reply.body)?;
        let usage = Usage::from_terminal(&terminal, counted)?;
        self.deadline()?;
        self.ledger.settle(&self.trial_id, &generation_id, usage)?;
        self.record_success(usage)?;
        Ok(generation_reply.body)
    }

    fn record_success(&mut self, usage: Usage) -> Result<()> {
        let state = self.ledger.snapshot()?;
        let trial = state.trials.get(&self.trial_id).ok_or(Denial::Uncertain)?;
        if self.events.len() >= 64 {
            return Err(Denial::Budget);
        }
        self.events.push(json!({
            "schema": "agentguard.stage1-metering-event",
            "schema_version": 2,
            "status": "settled",
            "trial_id": self.trial_id,
            "plan_digest": self.ledger.scope.plan_digest,
            "authorization_digest": self.ledger.scope.authorization_digest,
            "model": crate::MODEL,
            "pricing_digest": self.ledger.scope.pricing_digest,
            "request_sequence": trial.generations,
            "count_requests": trial.counts,
            "input_tokens": usage.input,
            "cached_input_tokens": usage.cached,
            "output_tokens": usage.output,
            "reasoning_tokens": usage.reasoning,
            "charged_usd": trial.charged_usd,
        }));
        Ok(())
    }

    fn write_evidence(&self) -> Result<()> {
        let parent = self.evidence.parent().ok_or(Denial::Uncertain)?;
        let bytes = canonical(&json!({
            "schema": "agentguard.stage1-metering-evidence",
            "schema_version": 2,
            "trial_closed": self.closed,
            "events": self.events,
        }))?;
        if bytes.len() > 64 * 1024 {
            return Err(Denial::Uncertain);
        }
        let temporary = parent.join(format!(".evidence-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Denial::Uncertain)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Denial::Uncertain)?;
        fs::rename(temporary, &self.evidence).map_err(|_| Denial::Uncertain)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Denial::Uncertain)
    }
}

fn error_class(failure: Denial) -> &'static str {
    match failure {
        Denial::InvalidConfig => "configuration",
        Denial::InvalidRequest => "request",
        Denial::InvalidProvider => "provider",
        Denial::Budget => "budget",
        Denial::Uncertain => "accounting",
        Denial::Io => "io",
    }
}

pub struct LocalTlsProvider {
    pub ca_file: PathBuf,
    pub fake_upstream_token: String,
}

impl Provider for LocalTlsProvider {
    fn post(&self, path: &str, body: &[u8]) -> Result<UpstreamResponse> {
        crate::transport::mock_tls_request(
            path,
            body,
            &self.fake_upstream_token,
            Path::new(&self.ca_file),
        )
    }
}
