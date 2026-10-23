use crate::{Denial, Result};
use serde_json::Value;

pub const MAX_TOKENS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub input: u64,
    pub cached: u64,
    pub output: u64,
    pub reasoning: u64,
}

fn token(value: &Value) -> Result<u64> {
    let count = value.as_u64().ok_or(Denial::InvalidProvider)?;
    if count > MAX_TOKENS {
        return Err(Denial::InvalidProvider);
    }
    Ok(count)
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or(Denial::InvalidProvider)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(Denial::InvalidProvider);
    }
    Ok(())
}

impl Usage {
    pub fn from_terminal(response: &Value, counted_input: u64) -> Result<Self> {
        if response.get("model").and_then(Value::as_str) != Some(crate::MODEL)
            || !matches!(
                response.get("service_tier").and_then(Value::as_str),
                None | Some("default")
            )
        {
            return Err(Denial::InvalidProvider);
        }
        let usage = response.get("usage").ok_or(Denial::InvalidProvider)?;
        exact_keys(
            usage,
            &[
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "input_tokens_details",
                "output_tokens_details",
            ],
        )?;
        let input_details = &usage["input_tokens_details"];
        exact_keys(input_details, &["cached_tokens", "cache_write_tokens"])?;
        let output_details = &usage["output_tokens_details"];
        exact_keys(output_details, &["reasoning_tokens"])?;
        let result = Self {
            input: token(&usage["input_tokens"])?,
            cached: token(&input_details["cached_tokens"])?,
            output: token(&usage["output_tokens"])?,
            reasoning: token(&output_details["reasoning_tokens"])?,
        };
        if result.input != counted_input
            || result.cached > result.input
            || result.reasoning > result.output
            || token(&input_details["cache_write_tokens"])? != 0
            || token(&usage["total_tokens"])?
                != result
                    .input
                    .checked_add(result.output)
                    .ok_or(Denial::InvalidProvider)?
        {
            return Err(Denial::InvalidProvider);
        }
        Ok(result)
    }
}

pub fn cost_micro_usd(input: u64, cached: u64, output: u64) -> Result<u64> {
    if input > MAX_TOKENS || cached > input || output > MAX_TOKENS {
        return Err(Denial::Budget);
    }
    let numerator =
        u128::from(input - cached) * 1750 + u128::from(cached) * 175 + u128::from(output) * 14_000;
    u64::try_from(numerator.div_ceil(1000)).map_err(|_| Denial::Budget)
}

pub fn parse_micro_usd(text: &str) -> Result<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || whole.len() > 7
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || text.ends_with('.')
    {
        return Err(Denial::InvalidConfig);
    }
    let whole = whole.parse::<u64>().map_err(|_| Denial::InvalidConfig)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().map_err(|_| Denial::InvalidConfig)?
            * 10_u64.pow(6 - fraction.len() as u32)
    };
    let amount = whole
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(fraction))
        .ok_or(Denial::InvalidConfig)?;
    if amount == 0 || amount > 1_000_000_000_000 {
        return Err(Denial::InvalidConfig);
    }
    Ok(amount)
}

pub fn format_micro_usd(amount: u64) -> String {
    if amount.is_multiple_of(1_000_000) {
        return (amount / 1_000_000).to_string();
    }
    let mut formatted = format!("{}.{:06}", amount / 1_000_000, amount % 1_000_000);
    while formatted.ends_with('0') {
        formatted.pop();
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_rates_and_rounding() {
        assert_eq!(cost_micro_usd(7, 0, 3), Ok(55));
        assert_eq!(cost_micro_usd(7, 2, 3), Ok(52));
        assert_eq!(cost_micro_usd(1, 0, 0), Ok(2));
        assert_eq!(format_micro_usd(52), "0.000052");
        assert_eq!(parse_micro_usd("0.000052"), Ok(52));
    }

    #[test]
    fn invalid_monetary_values_fail() {
        for value in ["", "-1", "1e4", "0.0000001", "01.2", "0.", "1000001", "NaN"] {
            assert_eq!(parse_micro_usd(value), Err(Denial::InvalidConfig));
        }
        assert_eq!(cost_micro_usd(MAX_TOKENS + 1, 0, 0), Err(Denial::Budget));
    }
}
