#![forbid(unsafe_code)]

pub mod config;
pub mod http;
pub mod ledger;
pub mod pricing;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod trust;

use sha2::{Digest, Sha256};

pub const MODEL: &str = "gpt-5.2-2025-12-11";
pub const PROVIDER: &str = "openai-api";
pub const PRICING_DIGEST: &str =
    "sha256:11da095d2856b07a2ce0a6da30e8d3229b9d4a2138122549d129580f0378eb35";
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    InvalidConfig,
    InvalidRequest,
    InvalidProvider,
    Budget,
    Uncertain,
    Io,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid configuration",
            Self::InvalidRequest => "request rejected",
            Self::InvalidProvider => "provider response rejected",
            Self::Budget => "budget exhausted",
            Self::Uncertain => "provider accounting uncertain",
            Self::Io => "bounded I/O failure",
        })
    }
}

impl std::error::Error for Denial {}

pub type Result<T> = std::result::Result<T, Denial>;

pub fn canonical(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn string(text: &str, output: &mut Vec<u8>) -> Result<()> {
        output.push(b'"');
        for character in text.chars() {
            if character.is_ascii() {
                let encoded = serde_json::to_string(&character.to_string())
                    .map_err(|_| Denial::InvalidRequest)?;
                output.extend_from_slice(&encoded.as_bytes()[1..encoded.len() - 1]);
            } else {
                let scalar = character as u32;
                if scalar <= 0xffff {
                    output.extend_from_slice(format!("\\u{scalar:04x}").as_bytes());
                } else {
                    let value = scalar - 0x10000;
                    output.extend_from_slice(
                        format!(
                            "\\u{:04x}\\u{:04x}",
                            0xd800 + (value >> 10),
                            0xdc00 + (value & 0x3ff)
                        )
                        .as_bytes(),
                    );
                }
            }
        }
        output.push(b'"');
        Ok(())
    }
    fn append(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                output.push(b'{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    string(key, output)?;
                    output.push(b':');
                    append(&map[key], output)?;
                }
                output.push(b'}');
            }
            Value::Array(items) => {
                output.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    append(item, output)?;
                }
                output.push(b']');
            }
            Value::String(text) => string(text, output)?,
            Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
            Value::Bool(value) => {
                output.extend_from_slice(if *value { &b"true"[..] } else { &b"false"[..] })
            }
            Value::Null => output.extend_from_slice(b"null"),
        }
        Ok(())
    }
    let mut bytes = Vec::new();
    append(value, &mut bytes)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn digest(value: &serde_json::Value) -> Result<String> {
    Ok(format!("sha256:{:x}", Sha256::digest(canonical(value)?)))
}
