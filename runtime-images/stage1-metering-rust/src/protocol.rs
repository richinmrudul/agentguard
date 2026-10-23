use crate::{Denial, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MODEL, Result, canonical};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const MAX_DEPTH: usize = 24;
const MAX_ELEMENTS: usize = 128;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_TOOL_BYTES: usize = 64 * 1024;
const MAX_EVENTS: usize = 256;
const MAX_FRAME_BYTES: usize = 64 * 1024;

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded JSON without duplicate keys or floating-point values")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, _value: f64) -> std::result::Result<Self::Value, E> {
                Err(E::custom("fractional or overflowing number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                if value.len() > MAX_STRING_BYTES {
                    return Err(E::custom("string bound"));
                }
                Ok(StrictValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                if value.len() > MAX_STRING_BYTES {
                    return Err(E::custom("string bound"));
                }
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = sequence.next_element::<StrictValue>()? {
                    if items.len() >= MAX_ELEMENTS {
                        return Err(de::Error::custom("array bound"));
                    }
                    items.push(item.0);
                }
                Ok(StrictValue(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut source: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut map = Map::new();
                while let Some((key, value)) = source.next_entry::<String, StrictValue>()? {
                    if key.len() > MAX_STRING_BYTES
                        || map.len() >= MAX_ELEMENTS
                        || map.contains_key(&key)
                    {
                        return Err(de::Error::custom("object bound or duplicate key"));
                    }
                    map.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(map)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn depth(value: &Value, level: usize) -> Result<()> {
    if level > MAX_DEPTH {
        return Err(Denial::InvalidRequest);
    }
    match value {
        Value::Array(items) => {
            if items.len() > MAX_ELEMENTS {
                return Err(Denial::InvalidRequest);
            }
            for item in items {
                depth(item, level + 1)?;
            }
        }
        Value::Object(items) => {
            if items.len() > MAX_ELEMENTS {
                return Err(Denial::InvalidRequest);
            }
            for item in items.values() {
                depth(item, level + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn parse_json(raw: &[u8], maximum: usize) -> Result<Value> {
    if raw.is_empty() || raw.len() > maximum {
        return Err(Denial::InvalidRequest);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| Denial::InvalidRequest)?
        .0;
    deserializer.end().map_err(|_| Denial::InvalidRequest)?;
    if !value.is_object() {
        return Err(Denial::InvalidRequest);
    }
    depth(&value, 0)?;
    Ok(value)
}

const REVIEWED_TOOLS: [(&str, &str, &str); 3] = [
    (
        "function",
        "exec_command",
        "7ecb0f4f51b3982e36be43a9d08daa05348d7dd5f70646231b1f0f9823f40ec3",
    ),
    (
        "function",
        "write_stdin",
        "9c3adbaa65e36ce23c7f1a8778e094a14b2086c993fc783727156276831c99dd",
    ),
    (
        "custom",
        "apply_patch",
        "5947b870d79e16bddc34946a4afb6200ff14a97f8419a2d23f8e5040af9a7154",
    ),
];

fn reviewed_tools(value: &Value) -> Result<()> {
    let tools = value.as_array().ok_or(Denial::InvalidRequest)?;
    if tools.len() != REVIEWED_TOOLS.len() || canonical(value)?.len() > MAX_TOOL_BYTES {
        return Err(Denial::InvalidRequest);
    }
    for (tool, (kind, name, expected)) in tools.iter().zip(REVIEWED_TOOLS) {
        if tool.get("type").and_then(Value::as_str) != Some(kind)
            || tool.get("name").and_then(Value::as_str) != Some(name)
        {
            return Err(Denial::InvalidRequest);
        }
        let mut bytes = canonical(tool)?;
        bytes.pop();
        if format!("{:x}", Sha256::digest(bytes)) != expected {
            return Err(Denial::InvalidRequest);
        }
    }
    Ok(())
}

fn text_only(value: &Value) -> Result<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                text_only(item)?;
            }
        }
        Value::Object(items) => {
            if let Some(kind) = items.get("type") {
                let kind = kind.as_str().ok_or(Denial::InvalidRequest)?;
                if !matches!(
                    kind,
                    "message"
                        | "input_text"
                        | "output_text"
                        | "function_call"
                        | "function_call_output"
                        | "custom_tool_call"
                        | "custom_tool_call_output"
                ) {
                    return Err(Denial::InvalidRequest);
                }
            }
            for (key, item) in items {
                if matches!(
                    key.as_str(),
                    "url" | "file_id" | "image_url" | "audio_url" | "data"
                ) {
                    return Err(Denial::InvalidRequest);
                }
                text_only(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_) => {}
    }
    Ok(())
}

pub fn normalize_generation(raw: &[u8], output_cap: u64) -> Result<Value> {
    if !(1..=4096).contains(&output_cap) {
        return Err(Denial::InvalidConfig);
    }
    let mut request = parse_json(raw, MAX_REQUEST_BYTES)?;
    let fields = [
        "client_metadata",
        "include",
        "input",
        "instructions",
        "max_output_tokens",
        "model",
        "parallel_tool_calls",
        "prompt_cache_key",
        "reasoning",
        "store",
        "stream",
        "tool_choice",
        "tools",
    ];
    let object = request.as_object_mut().ok_or(Denial::InvalidRequest)?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(Denial::InvalidRequest);
    }
    if let Some(metadata) = object.remove("client_metadata")
        && (!metadata.is_object() || canonical(&metadata)?.len() > 4096)
    {
        return Err(Denial::InvalidRequest);
    }
    if object.get("model").and_then(Value::as_str) != Some(MODEL)
        || object.get("store") != Some(&Value::Bool(false))
        || object.get("stream") != Some(&Value::Bool(true))
        || object.get("parallel_tool_calls") != Some(&Value::Bool(true))
        || object.get("tool_choice").and_then(Value::as_str) != Some("auto")
        || object.get("reasoning") != Some(&serde_json::json!({"effort":"none"}))
    {
        return Err(Denial::InvalidRequest);
    }
    reviewed_tools(object.get("tools").ok_or(Denial::InvalidRequest)?)?;
    let include = object
        .get("include")
        .and_then(Value::as_array)
        .ok_or(Denial::InvalidRequest)?;
    if !(include.is_empty() || include == &[Value::String("reasoning.encrypted_content".into())]) {
        return Err(Denial::InvalidRequest);
    }
    let cache_key = object
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .ok_or(Denial::InvalidRequest)?;
    if cache_key.len() > 256 {
        return Err(Denial::InvalidRequest);
    }
    if let Some(cap) = object.get("max_output_tokens")
        && cap.as_u64() != Some(output_cap)
    {
        return Err(Denial::InvalidRequest);
    }
    if let Some(instructions) = object.get("instructions")
        && instructions
            .as_str()
            .is_none_or(|text| text.len() > MAX_STRING_BYTES)
    {
        return Err(Denial::InvalidRequest);
    }
    let input = object
        .get("input")
        .and_then(Value::as_array)
        .ok_or(Denial::InvalidRequest)?;
    if input.is_empty() || input.len() > MAX_ELEMENTS {
        return Err(Denial::InvalidRequest);
    }
    text_only(&Value::Array(input.clone()))?;
    object.insert("max_output_tokens".into(), Value::Number(output_cap.into()));
    object.insert(
        "prompt_cache_retention".into(),
        Value::String("in_memory".into()),
    );
    if canonical(&request)?.len() > MAX_REQUEST_BYTES {
        return Err(Denial::InvalidRequest);
    }
    Ok(request)
}

pub fn count_payload(request: &Value) -> Result<Vec<u8>> {
    let fields = [
        "model",
        "instructions",
        "input",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
    ];
    let object = request.as_object().ok_or(Denial::InvalidRequest)?;
    if object.get("model").and_then(Value::as_str) != Some(MODEL)
        || object.get("prompt_cache_retention").and_then(Value::as_str) != Some("in_memory")
    {
        return Err(Denial::InvalidRequest);
    }
    let mut selected = Map::new();
    for field in fields {
        if let Some(value) = object.get(field) {
            selected.insert(field.into(), value.clone());
        }
    }
    canonical(&Value::Object(selected))
}

pub fn input_count(raw: &[u8]) -> Result<u64> {
    let payload = parse_json(raw, MAX_RESPONSE_BYTES).map_err(|_| Denial::InvalidProvider)?;
    let object = payload.as_object().ok_or(Denial::InvalidProvider)?;
    if object.len() != 2
        || payload.get("object").and_then(Value::as_str) != Some("response.input_tokens")
    {
        return Err(Denial::InvalidProvider);
    }
    let count = payload
        .get("input_tokens")
        .and_then(Value::as_u64)
        .ok_or(Denial::InvalidProvider)?;
    if count > crate::pricing::MAX_TOKENS {
        return Err(Denial::InvalidProvider);
    }
    Ok(count)
}

pub fn terminal_stream(raw: &[u8]) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX_RESPONSE_BYTES || !raw.ends_with(b"\n\n") {
        return Err(Denial::InvalidProvider);
    }
    let mut terminal: Option<Value> = None;
    let mut previous: i64 = -1;
    let frames: Vec<&[u8]> = raw.split(|byte| *byte == b'\n').collect();
    if frames.len() > MAX_EVENTS * 3 {
        return Err(Denial::InvalidProvider);
    }
    let mut events = 0_usize;
    let mut offset = 0_usize;
    while offset < raw.len() {
        let remainder = &raw[offset..];
        let end = remainder
            .windows(2)
            .position(|part| part == b"\n\n")
            .ok_or(Denial::InvalidProvider)?;
        let frame = &remainder[..end];
        offset += end + 2;
        if frame.is_empty() {
            continue;
        }
        events += 1;
        if events > MAX_EVENTS
            || frame.len() > MAX_FRAME_BYTES
            || frame.contains(&b'\r')
            || frame.contains(&b'\n')
            || !frame.starts_with(b"data: ")
        {
            return Err(Denial::InvalidProvider);
        }
        if frame == b"data: [DONE]" {
            if terminal.is_none() || offset != raw.len() {
                return Err(Denial::InvalidProvider);
            }
            continue;
        }
        let event =
            parse_json(&frame[6..], MAX_FRAME_BYTES).map_err(|_| Denial::InvalidProvider)?;
        let sequence = event
            .get("sequence_number")
            .and_then(Value::as_i64)
            .ok_or(Denial::InvalidProvider)?;
        if sequence <= previous || terminal.is_some() {
            return Err(Denial::InvalidProvider);
        }
        previous = sequence;
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or(Denial::InvalidProvider)?;
        if matches!(kind, "response.failed" | "response.incomplete") {
            return Err(Denial::InvalidProvider);
        }
        if kind == "response.completed" {
            terminal = Some(
                event
                    .get("response")
                    .cloned()
                    .ok_or(Denial::InvalidProvider)?,
            );
        }
    }
    let response = terminal.ok_or(Denial::InvalidProvider)?;
    if response.get("status").and_then(Value::as_str) != Some("completed")
        || response.get("model").and_then(Value::as_str) != Some(MODEL)
        || response.get("service_tier").and_then(Value::as_str) != Some("default")
    {
        return Err(Denial::InvalidProvider);
    }
    let id = response
        .get("id")
        .and_then(Value::as_str)
        .ok_or(Denial::InvalidProvider)?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(Denial::InvalidProvider);
    }
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or(Denial::InvalidProvider)?;
    if output.len() > 128
        || output.iter().any(|item| {
            !matches!(
                item.get("type").and_then(Value::as_str),
                Some("message" | "function_call" | "custom_tool_call")
            )
        })
    {
        return Err(Denial::InvalidProvider);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_and_fractional_json() {
        assert_eq!(
            parse_json(br#"{"a":1,"a":2}"#, 100),
            Err(Denial::InvalidRequest)
        );
        assert_eq!(
            parse_json(br#"{"a":1.2}"#, 100),
            Err(Denial::InvalidRequest)
        );
        assert_eq!(
            parse_json(br#"{"a":-1}"#, 100),
            Ok(serde_json::json!({"a":-1}))
        );
    }

    #[test]
    fn rejects_truncated_or_duplicated_terminal_event() {
        let completed = br#"data: {"sequence_number":1,"type":"response.completed","response":{"id":"abc","model":"gpt-5.2-2025-12-11","status":"completed","service_tier":"default","output":[]}}\n\n"#;
        assert!(terminal_stream(completed).is_err());
        assert!(terminal_stream(b"data: {}\n").is_err());
    }
}
