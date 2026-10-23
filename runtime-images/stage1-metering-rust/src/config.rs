use crate::{Denial, MODEL, PRICING_DIGEST, PROVIDER, Result, digest, protocol::parse_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_CONFIG_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub authorization_digest: String,
    pub plan_digest: String,
    pub profile_digest: String,
    pub pricing_digest: String,
    pub redaction_digest: String,
    pub provider: String,
    pub model: String,
    pub trial_ids: Vec<String>,
    pub max_trial_generations: u64,
    pub max_trial_counts: u64,
    pub max_trial_input_tokens: u64,
    pub max_trial_output_tokens: u64,
    pub max_trial_total_tokens: u64,
    pub max_trial_seconds: u64,
    pub max_trial_cost_usd: String,
    pub max_study_cost_usd: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockConfig {
    pub scope: Scope,
    pub output_cap: u64,
}

pub fn valid_digest(text: &str) -> bool {
    text.len() == 71
        && text.starts_with("sha256:")
        && text[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn valid_id(text: &str) -> bool {
    (1..=80).contains(&text.len())
        && (text.as_bytes()[0].is_ascii_lowercase() || text.as_bytes()[0].is_ascii_digit())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl Scope {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.authorization_digest,
            &self.plan_digest,
            &self.profile_digest,
            &self.pricing_digest,
            &self.redaction_digest,
        ] {
            if !valid_digest(value) {
                return Err(Denial::InvalidConfig);
            }
        }
        if self.pricing_digest != PRICING_DIGEST || self.provider != PROVIDER || self.model != MODEL
        {
            return Err(Denial::InvalidConfig);
        }
        if self.trial_ids.is_empty()
            || self.trial_ids.len() > 16
            || self.trial_ids.iter().any(|id| !valid_id(id))
        {
            return Err(Denial::InvalidConfig);
        }
        let mut unique = self.trial_ids.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != self.trial_ids.len() {
            return Err(Denial::InvalidConfig);
        }
        for limit in [
            self.max_trial_generations,
            self.max_trial_counts,
            self.max_trial_input_tokens,
            self.max_trial_output_tokens,
            self.max_trial_total_tokens,
            self.max_trial_seconds,
        ] {
            if !(1..=10_000_000).contains(&limit) {
                return Err(Denial::InvalidConfig);
            }
        }
        crate::pricing::parse_micro_usd(&self.max_trial_cost_usd)?;
        crate::pricing::parse_micro_usd(&self.max_study_cost_usd)?;
        Ok(())
    }

    pub fn canonical_digest(&self) -> Result<String> {
        let value = serde_json::to_value(self).map_err(|_| Denial::InvalidConfig)?;
        digest(&value)
    }
}

pub fn parse_mock_config(raw: &[u8]) -> Result<MockConfig> {
    if raw.is_empty() || raw.len() > MAX_CONFIG_BYTES {
        return Err(Denial::InvalidConfig);
    }
    let value = parse_json(raw, MAX_CONFIG_BYTES).map_err(|_| Denial::InvalidConfig)?;
    let config: MockConfig = serde_json::from_value(value).map_err(|_| Denial::InvalidConfig)?;
    config.scope.validate()?;
    if !(1..=4096).contains(&config.output_cap) {
        return Err(Denial::InvalidConfig);
    }
    Ok(config)
}

pub fn expected_pricing() -> Result<Value> {
    let raw = include_bytes!("../../../agentguard/evaluation/stage1_pricing_v2.json");
    let value = parse_json(raw, 4096).map_err(|_| Denial::InvalidConfig)?;
    if digest(&value)? != PRICING_DIGEST {
        return Err(Denial::InvalidConfig);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_pricing_is_exact_reviewed_policy() {
        let policy = super::expected_pricing().unwrap();
        assert_eq!(policy["uncached_input_usd"], "1.75");
        assert_eq!(policy["cached_input_usd"], "0.175");
        assert_eq!(policy["output_usd"], "14.00");
    }
}
