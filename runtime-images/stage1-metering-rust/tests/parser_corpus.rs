use agentguard_stage1_metering_gateway::http::read_request;
use agentguard_stage1_metering_gateway::protocol::{parse_json, terminal_stream};
use serde_json::Value;
use std::io::Cursor;

#[test]
fn fixed_adversarial_seed_corpus_rejects() {
    let corpus: Value = serde_json::from_str(include_str!("../fuzz-corpus.json")).unwrap();
    for raw in corpus["http"].as_array().unwrap() {
        assert!(read_request(&mut Cursor::new(raw.as_str().unwrap().as_bytes()), 256).is_err());
    }
    for raw in corpus["json"].as_array().unwrap() {
        let text = raw.as_str().unwrap();
        let parsed = parse_json(text.as_bytes(), 512);
        if text.contains("input_image") {
            assert!(parsed.is_ok());
        } else {
            assert!(parsed.is_err());
        }
    }
    for raw in corpus["sse"].as_array().unwrap() {
        assert!(terminal_stream(raw.as_str().unwrap().as_bytes()).is_err());
    }
}

#[test]
fn deterministic_mutation_corpus_never_escapes_bounds() {
    let mut state = 0x32_29_0a_8e_57_b0_4d_79_u64;
    for length in 1..=512 {
        let mut raw = vec![0_u8; length];
        for byte in &mut raw {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        if let Ok(value) = parse_json(&raw, 512) {
            assert!(value.is_object());
        }
        if let Ok(message) = read_request(&mut Cursor::new(&raw), 512) {
            assert_eq!(message.path, "/v1/responses");
            assert!(message.body.len() <= 512);
        }
        if let Ok(response) = terminal_stream(&raw) {
            assert_eq!(response["model"], "gpt-5.2-2025-12-11");
        }
    }
}
