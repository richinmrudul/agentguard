use crate::config::{Scope, valid_digest, valid_id};
use crate::pricing::{Usage, cost_micro_usd, format_micro_usd, parse_micro_usd};
use crate::{Denial, Result, canonical, digest};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LEDGER_BYTES: usize = 256 * 1024;
const MAX_EVENTS: usize = 128;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    request_id: String,
    input_tokens: u64,
    output_cap: u64,
    reserved_usd: String,
    owner_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    pub counts: u64,
    pub generations: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub charged_usd: String,
    pub pending: Option<Pending>,
    pub failed: bool,
    pub request_ids: Vec<String>,
    pub started_at: Option<u64>,
}

impl Trial {
    fn initial() -> Self {
        Self {
            counts: 0,
            generations: 0,
            input_tokens: 0,
            output_tokens: 0,
            charged_usd: "0".into(),
            pending: None,
            failed: false,
            request_ids: Vec::new(),
            started_at: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema: String,
    schema_version: u64,
    scope_digest: String,
    pub sequence: u64,
    pub trials: BTreeMap<String, Trial>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    operation: String,
    state: State,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEvent {
    previous: String,
    entry: Entry,
    hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    schema: String,
    schema_version: u64,
    scope_digest: String,
    sequence: u64,
    journal_hash: String,
}

pub struct StudyLedger {
    root: PathBuf,
    anchor_root: PathBuf,
    pub scope: Scope,
    incarnation: String,
}

fn secure_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Denial::Uncertain)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() as usize > maximum
    {
        return Err(Denial::Uncertain);
    }
    fs::read(path).map_err(|_| Denial::Uncertain)
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Denial::Uncertain)
}

fn dollar(value: &str) -> Result<u64> {
    if value == "0" || value == "0.000000" {
        return Ok(0);
    }
    parse_micro_usd(value).map_err(|_| Denial::Uncertain)
}

impl StudyLedger {
    pub fn open(root: &Path, anchor_root: &Path, scope: Scope) -> Result<Self> {
        scope.validate()?;
        if root == anchor_root {
            return Err(Denial::InvalidConfig);
        }
        for directory in [root, anchor_root] {
            if let Ok(metadata) = fs::symlink_metadata(directory) {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(Denial::InvalidConfig);
                }
            } else {
                fs::create_dir(directory).map_err(|_| Denial::Io)?;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .map_err(|_| Denial::Io)?;
            }
        }
        let mut seed = [0_u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut seed))
            .map_err(|_| Denial::Io)?;
        let incarnation = format!("sha256:{:x}", Sha256::digest(seed));
        let ledger = Self {
            root: root.to_path_buf(),
            anchor_root: anchor_root.to_path_buf(),
            scope,
            incarnation,
        };
        ledger.locked(|ledger| {
            let snapshot = ledger.root.join("snapshot.json");
            let journal = ledger.root.join("journal.jsonl");
            if !snapshot.exists() && !journal.exists() {
                if ledger.anchor_root.join("head.json").exists() {
                    return Err(Denial::Uncertain);
                }
                let initial = ledger.initial_state()?;
                ledger.write_snapshot(&initial)?;
                let hash = ledger.append_event("init", &initial, &"0".repeat(64))?;
                ledger.write_anchor(&initial, &hash)?;
            }
            ledger.read_verified().map(|_| ())
        })?;
        Ok(ledger)
    }

    fn initial_state(&self) -> Result<State> {
        Ok(State {
            schema: "agentguard.stage1-study-ledger".into(),
            schema_version: 1,
            scope_digest: self.scope.canonical_digest()?,
            sequence: 0,
            trials: self
                .scope
                .trial_ids
                .iter()
                .map(|id| (id.clone(), Trial::initial()))
                .collect(),
        })
    }

    fn locked<T>(&self, operation: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let path = self.root.join("lock");
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0)
        {
            return Err(Denial::Uncertain);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|_| Denial::Io)?;
        lock.lock_exclusive().map_err(|_| Denial::Io)?;
        let result = operation(self);
        FileExt::unlock(&lock).map_err(|_| Denial::Uncertain)?;
        result
    }

    fn read_verified(&self) -> Result<State> {
        let snapshot_raw = secure_file(&self.root.join("snapshot.json"), MAX_LEDGER_BYTES)?;
        let journal_raw = secure_file(&self.root.join("journal.jsonl"), MAX_LEDGER_BYTES)?;
        let snapshot_value: Value =
            serde_json::from_slice(&snapshot_raw).map_err(|_| Denial::Uncertain)?;
        if canonical(&snapshot_value).map_err(|_| Denial::Uncertain)? != snapshot_raw {
            return Err(Denial::Uncertain);
        }
        let snapshot: State =
            serde_json::from_value(snapshot_value).map_err(|_| Denial::Uncertain)?;
        let lines: Vec<_> = journal_raw.split_inclusive(|byte| *byte == b'\n').collect();
        if lines.is_empty() || lines.len() > MAX_EVENTS || !journal_raw.ends_with(b"\n") {
            return Err(Denial::Uncertain);
        }
        let mut previous = "0".repeat(64);
        let mut last: Option<State> = None;
        for (index, raw) in lines.iter().enumerate() {
            let value: Value = serde_json::from_slice(raw).map_err(|_| Denial::Uncertain)?;
            if canonical(&value).map_err(|_| Denial::Uncertain)? != *raw {
                return Err(Denial::Uncertain);
            }
            let event: JournalEvent =
                serde_json::from_value(value).map_err(|_| Denial::Uncertain)?;
            if event.previous != previous || event.entry.state.sequence != index as u64 {
                return Err(Denial::Uncertain);
            }
            if index == 0 {
                if event.entry.operation != "init" || event.entry.state != self.initial_state()? {
                    return Err(Denial::Uncertain);
                }
            } else if !matches!(
                event.entry.operation.as_str(),
                "count" | "reserve" | "settle" | "fail"
            ) {
                return Err(Denial::Uncertain);
            }
            let expected = digest(&json!({
                "operation": event.entry.operation, "state": event.entry.state,
                "previous": event.previous,
            }))
            .map_err(|_| Denial::Uncertain)?;
            if event.hash != expected {
                return Err(Denial::Uncertain);
            }
            previous = event.hash;
            last = Some(event.entry.state);
        }
        if last.as_ref() != Some(&snapshot) {
            return Err(Denial::Uncertain);
        }
        self.verify_anchor(&snapshot, &previous)?;
        self.check_state(&snapshot)?;
        Ok(snapshot)
    }

    fn verify_anchor(&self, state: &State, expected_hash: &str) -> Result<()> {
        let bytes = secure_file(&self.anchor_root.join("head.json"), 4096)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| Denial::Uncertain)?;
        if canonical(&value).map_err(|_| Denial::Uncertain)? != bytes {
            return Err(Denial::Uncertain);
        }
        let anchor: Anchor = serde_json::from_value(value).map_err(|_| Denial::Uncertain)?;
        if anchor.schema != "agentguard.stage1-ledger-anchor"
            || anchor.schema_version != 1
            || anchor.scope_digest != self.scope.canonical_digest()?
            || anchor.sequence != state.sequence
            || anchor.journal_hash != expected_hash
        {
            return Err(Denial::Uncertain);
        }
        Ok(())
    }

    fn write_anchor(&self, state: &State, hash: &str) -> Result<()> {
        let anchor = Anchor {
            schema: "agentguard.stage1-ledger-anchor".into(),
            schema_version: 1,
            scope_digest: self.scope.canonical_digest()?,
            sequence: state.sequence,
            journal_hash: hash.into(),
        };
        let value = serde_json::to_value(anchor).map_err(|_| Denial::Uncertain)?;
        let bytes = canonical(&value).map_err(|_| Denial::Uncertain)?;
        let temporary = self.anchor_root.join(format!(
            ".anchor-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Denial::Io)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Denial::Io)?;
        fs::rename(&temporary, self.anchor_root.join("head.json")).map_err(|_| Denial::Io)?;
        File::open(&self.anchor_root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Denial::Io)
    }

    fn check_state(&self, state: &State) -> Result<()> {
        if state.schema != "agentguard.stage1-study-ledger"
            || state.schema_version != 1
            || state.scope_digest != self.scope.canonical_digest()?
            || state.trials.len() != self.scope.trial_ids.len()
            || self
                .scope
                .trial_ids
                .iter()
                .any(|id| !state.trials.contains_key(id))
        {
            return Err(Denial::Uncertain);
        }
        for trial in state.trials.values() {
            if trial.counts > 10_000_000
                || trial.generations > 10_000_000
                || trial.input_tokens > 10_000_000
                || trial.output_tokens > 10_000_000
                || trial.request_ids.len() > MAX_EVENTS
                || dollar(&trial.charged_usd).is_err()
            {
                return Err(Denial::Uncertain);
            }
            let mut seen = HashSet::new();
            if trial
                .request_ids
                .iter()
                .any(|id| !valid_id(id) || !seen.insert(id))
            {
                return Err(Denial::Uncertain);
            }
            if let Some(pending) = &trial.pending
                && (!valid_id(&pending.request_id)
                    || !valid_digest(&pending.owner_digest)
                    || !trial.request_ids.contains(&pending.request_id)
                    || pending.input_tokens > 10_000_000
                    || pending.output_cap > 10_000_000
                    || dollar(&pending.reserved_usd).is_err())
            {
                return Err(Denial::Uncertain);
            }
        }
        Ok(())
    }

    fn sync_dir(&self) -> Result<()> {
        File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| Denial::Io)
    }

    fn write_snapshot(&self, state: &State) -> Result<()> {
        let number = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .root
            .join(format!(".snapshot-{}-{number}", std::process::id()));
        let target = self.root.join("snapshot.json");
        let value = serde_json::to_value(state).map_err(|_| Denial::Uncertain)?;
        let bytes = canonical(&value).map_err(|_| Denial::Uncertain)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| Denial::Io)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Denial::Io)?;
        fs::rename(&temporary, target).map_err(|_| Denial::Io)?;
        self.sync_dir()
    }

    fn append_event(&self, operation: &str, state: &State, previous: &str) -> Result<String> {
        let entry = Entry {
            operation: operation.into(),
            state: state.clone(),
        };
        let hash = digest(&json!({"operation": operation, "state": state, "previous": previous}))?;
        let event = JournalEvent {
            previous: previous.into(),
            entry,
            hash,
        };
        let value = serde_json::to_value(&event).map_err(|_| Denial::Uncertain)?;
        let bytes = canonical(&value).map_err(|_| Denial::Uncertain)?;
        let path = self.root.join("journal.jsonl");
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(Denial::Uncertain);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| Denial::Io)?;
        if file.metadata().map_err(|_| Denial::Io)?.len() as usize + bytes.len() > MAX_LEDGER_BYTES
        {
            return Err(Denial::Budget);
        }
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Denial::Io)?;
        self.sync_dir()?;
        Ok(event.hash)
    }

    fn transition(&self, state: &mut State, operation: &str) -> Result<()> {
        let raw = secure_file(&self.root.join("journal.jsonl"), MAX_LEDGER_BYTES)?;
        if raw.iter().filter(|byte| **byte == b'\n').count() >= MAX_EVENTS {
            return Err(Denial::Budget);
        }
        let last = raw
            .split(|byte| *byte == b'\n')
            .rev()
            .find(|line| !line.is_empty())
            .ok_or(Denial::Uncertain)?;
        let event: JournalEvent = serde_json::from_slice(last).map_err(|_| Denial::Uncertain)?;
        state.sequence = state.sequence.checked_add(1).ok_or(Denial::Uncertain)?;
        let hash = self.append_event(operation, state, &event.hash)?;
        self.write_snapshot(state)?;
        self.write_anchor(state, &hash)
    }

    fn active<'a>(
        &self,
        state: &'a mut State,
        trial_id: &str,
        request_id: &str,
    ) -> Result<&'a mut Trial> {
        if state
            .trials
            .values()
            .any(|trial| trial.failed || trial.pending.is_some())
        {
            return Err(Denial::Uncertain);
        }
        let trial = state
            .trials
            .get_mut(trial_id)
            .ok_or(Denial::InvalidRequest)?;
        if !valid_id(request_id) || trial.request_ids.iter().any(|id| id == request_id) {
            return Err(Denial::InvalidRequest);
        }
        let current = now()?;
        if let Some(started) = trial.started_at {
            if current < started || current - started >= self.scope.max_trial_seconds {
                return Err(Denial::Budget);
            }
        } else {
            trial.started_at = Some(current);
        }
        Ok(trial)
    }

    pub fn count(&self, trial_id: &str, request_id: &str) -> Result<()> {
        self.locked(|ledger| {
            let mut state = ledger.read_verified()?;
            let trial = ledger.active(&mut state, trial_id, request_id)?;
            if trial.counts >= ledger.scope.max_trial_counts {
                return Err(Denial::Budget);
            }
            trial.counts += 1;
            trial.request_ids.push(request_id.into());
            ledger.transition(&mut state, "count")
        })
    }

    pub fn reserve(
        &self,
        trial_id: &str,
        request_id: &str,
        input: u64,
        output_cap: u64,
    ) -> Result<u64> {
        let amount = cost_micro_usd(input, 0, output_cap)?;
        self.locked(|ledger| {
            let mut state = ledger.read_verified()?;
            let total = state.trials.values().try_fold(0_u64, |sum, trial| {
                sum.checked_add(dollar(&trial.charged_usd)?)
                    .ok_or(Denial::Uncertain)
            })?;
            if total.checked_add(amount).ok_or(Denial::Budget)?
                > parse_micro_usd(&ledger.scope.max_study_cost_usd)?
            {
                return Err(Denial::Budget);
            }
            let trial = ledger.active(&mut state, trial_id, request_id)?;
            if trial.generations >= ledger.scope.max_trial_generations
                || trial
                    .input_tokens
                    .checked_add(input)
                    .ok_or(Denial::Budget)?
                    > ledger.scope.max_trial_input_tokens
                || trial
                    .output_tokens
                    .checked_add(output_cap)
                    .ok_or(Denial::Budget)?
                    > ledger.scope.max_trial_output_tokens
                || trial
                    .input_tokens
                    .checked_add(trial.output_tokens)
                    .and_then(|sum| sum.checked_add(input))
                    .and_then(|sum| sum.checked_add(output_cap))
                    .ok_or(Denial::Budget)?
                    > ledger.scope.max_trial_total_tokens
            {
                return Err(Denial::Budget);
            }
            let charged = dollar(&trial.charged_usd)?;
            if charged.checked_add(amount).ok_or(Denial::Budget)?
                > parse_micro_usd(&ledger.scope.max_trial_cost_usd)?
            {
                return Err(Denial::Budget);
            }
            trial.generations += 1;
            trial.request_ids.push(request_id.into());
            trial.charged_usd = format_micro_usd(charged + amount);
            trial.pending = Some(Pending {
                request_id: request_id.into(),
                input_tokens: input,
                output_cap,
                reserved_usd: format_micro_usd(amount),
                owner_digest: ledger.incarnation.clone(),
            });
            ledger.transition(&mut state, "reserve")?;
            Ok(amount)
        })
    }

    pub fn settle(&self, trial_id: &str, request_id: &str, usage: Usage) -> Result<()> {
        self.locked(|ledger| {
            let mut state = ledger.read_verified()?;
            let trial = state.trials.get_mut(trial_id).ok_or(Denial::Uncertain)?;
            if trial.failed {
                return Err(Denial::Uncertain);
            }
            let pending = trial.pending.as_ref().ok_or(Denial::Uncertain)?;
            if pending.request_id != request_id
                || pending.owner_digest != ledger.incarnation
                || usage.input != pending.input_tokens
                || usage.output > pending.output_cap
            {
                return Err(Denial::Uncertain);
            }
            let actual = cost_micro_usd(usage.input, usage.cached, usage.output)?;
            let reserved = dollar(&pending.reserved_usd)?;
            if actual > reserved {
                return Err(Denial::Uncertain);
            }
            let charged = dollar(&trial.charged_usd)?;
            trial.charged_usd = format_micro_usd(charged - reserved + actual);
            trial.input_tokens = trial
                .input_tokens
                .checked_add(usage.input)
                .ok_or(Denial::Uncertain)?;
            trial.output_tokens = trial
                .output_tokens
                .checked_add(usage.output)
                .ok_or(Denial::Uncertain)?;
            trial.pending = None;
            ledger.transition(&mut state, "settle")
        })
    }

    pub fn fail(&self, trial_id: &str) -> Result<()> {
        self.locked(|ledger| {
            let mut state = ledger.read_verified()?;
            let trial = state.trials.get_mut(trial_id).ok_or(Denial::Uncertain)?;
            if trial.failed {
                return Err(Denial::Uncertain);
            }
            trial.failed = true;
            ledger.transition(&mut state, "fail")
        })
    }

    pub fn snapshot(&self) -> Result<State> {
        self.locked(Self::read_verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        let marker = format!("sha256:{}", "a".repeat(64));
        Scope {
            authorization_digest: marker.clone(),
            plan_digest: marker.clone(),
            profile_digest: marker.clone(),
            pricing_digest: crate::PRICING_DIGEST.into(),
            redaction_digest: marker,
            provider: crate::PROVIDER.into(),
            model: crate::MODEL.into(),
            trial_ids: vec!["trial-a".into(), "trial-b".into()],
            max_trial_generations: 2,
            max_trial_counts: 2,
            max_trial_input_tokens: 30,
            max_trial_output_tokens: 20,
            max_trial_total_tokens: 50,
            max_trial_seconds: 120,
            max_trial_cost_usd: "0.01".into(),
            max_study_cost_usd: "0.02".into(),
        }
    }

    #[test]
    fn canonical_scope_digest_matches_reviewed_python_v1() {
        assert_eq!(
            scope().canonical_digest().unwrap(),
            "sha256:caec1c8f467c95b16b3dd499d758da495a423102bd223d38ff4288a9c167f4f3"
        );
    }

    #[test]
    fn uncertainty_retains_full_reservation_and_rejects_restart() {
        let path = std::env::temp_dir().join(format!(
            "agentguard-ledger-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let anchor = path.with_extension("anchor");
        let ledger = StudyLedger::open(&path, &anchor, scope()).unwrap();
        ledger.count("trial-a", "count-a").unwrap();
        let amount = ledger.reserve("trial-a", "generation-a", 7, 8).unwrap();
        assert!(amount > 0);
        drop(ledger);
        let restarted = StudyLedger::open(&path, &anchor, scope()).unwrap();
        assert!(
            restarted
                .settle(
                    "trial-a",
                    "generation-a",
                    Usage {
                        input: 7,
                        cached: 0,
                        output: 3,
                        reasoning: 0
                    }
                )
                .is_err()
        );
        assert!(restarted.count("trial-b", "count-b").is_err());
        assert_eq!(
            dollar(&restarted.snapshot().unwrap().trials["trial-a"].charged_usd),
            Ok(amount)
        );
        fs::remove_dir_all(path).unwrap();
        fs::remove_dir_all(anchor).unwrap();
    }

    #[test]
    fn stale_or_missing_host_anchor_rejects_ledger_rollback() {
        let path = std::env::temp_dir().join(format!(
            "agentguard-rollback-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let anchor = path.with_extension("anchor");
        let ledger = StudyLedger::open(&path, &anchor, scope()).unwrap();
        let old_snapshot = fs::read(path.join("snapshot.json")).unwrap();
        let old_journal = fs::read(path.join("journal.jsonl")).unwrap();
        ledger.count("trial-a", "count-a").unwrap();
        fs::write(path.join("snapshot.json"), old_snapshot).unwrap();
        fs::write(path.join("journal.jsonl"), old_journal).unwrap();
        assert!(ledger.snapshot().is_err());
        drop(ledger);
        assert!(StudyLedger::open(&path, &anchor, scope()).is_err());
        fs::remove_file(anchor.join("head.json")).unwrap();
        assert!(StudyLedger::open(&path, &anchor, scope()).is_err());
        fs::remove_dir_all(path).unwrap();
        fs::remove_dir_all(anchor).unwrap();
    }
}
