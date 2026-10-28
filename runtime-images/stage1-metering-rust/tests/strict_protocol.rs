use agentguard_stage1_metering_gateway::http::{read_request, read_upstream};
use agentguard_stage1_metering_gateway::protocol::terminal_stream;
use serde_json::{Value, json};
use std::io::Cursor;

fn frame(event: &Value) -> Vec<u8> {
    let mut result = b"data: ".to_vec();
    result.extend(serde_json::to_vec(event).unwrap());
    result.extend(b"\n\n");
    result
}

fn valid_stream() -> Vec<u8> {
    let model = "gpt-5.2-2025-12-11";
    let item = json!({
        "id": "msg_1", "type": "message", "status": "completed",
        "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]
    });
    let events = [
        json!({"type":"response.created","sequence_number":0,
            "response":{"id":"resp_1","model":model,"status":"in_progress"}}),
        json!({"type":"response.output_item.added","sequence_number":1,
            "output_index":0,"item":{"id":"msg_1","type":"message","content":[]}}),
        json!({"type":"response.output_text.delta","sequence_number":2,
            "output_index":0,"content_index":0,"item_id":"msg_1","delta":"ok"}),
        json!({"type":"response.output_item.done","sequence_number":3,
            "output_index":0,"item":item}),
        json!({"type":"response.completed","sequence_number":4,
            "response":{"id":"resp_1","model":model,"status":"completed",
                "service_tier":"default","output":[item],
                "usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10,
                    "input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0},
                    "output_tokens_details":{"reasoning_tokens":0}}}}),
    ];
    events.iter().flat_map(frame).collect()
}

fn events(raw: &[u8]) -> Vec<Value> {
    raw.split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"data: "))
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn stream(values: &[Value]) -> Vec<u8> {
    values.iter().flat_map(frame).collect()
}

#[test]
fn sse_exact_lifecycle_and_completed_only_rejection() {
    let good = valid_stream();
    assert_eq!(terminal_stream(&good).unwrap()["id"], "resp_1");
    let values = events(&good);
    assert!(terminal_stream(&stream(&values[4..])).is_err());
    assert!(terminal_stream(b"").is_err());
    assert!(terminal_stream(b": heartbeat\n\n").is_err());
    let mut with_done = good.clone();
    with_done.extend(b"data: [DONE]\n\n");
    assert!(terminal_stream(&with_done).is_ok());
    with_done.extend(b"data: [DONE]\n\n");
    assert!(terminal_stream(&with_done).is_err());
}

#[test]
fn sse_identity_order_replay_and_terminal_usage_fail_closed() {
    let good = valid_stream();
    let original = events(&good);
    let mut cases = Vec::new();
    let mut case = original.clone();
    case[2]["item_id"] = json!("other");
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["id"] = json!("other");
    cases.push(case);
    let mut case = original.clone();
    case[3]["output_index"] = json!(1);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["output"][0]["content"][0]["text"] = json!("changed");
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["input_tokens"] = json!(8);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["input_tokens_details"]["cached_tokens"] = json!(8);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["output_tokens"] = json!(u64::MAX);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"].as_object_mut().unwrap().remove("usage");
    cases.push(case);
    let mut case = original.clone();
    case[4]["sequence_number"] = json!(3);
    cases.push(case);
    let mut case = original.clone();
    let replay = case[2].clone();
    case.insert(3, replay);
    cases.push(case);
    let mut case = original.clone();
    case.push(case[4].clone());
    cases.push(case);
    let mut case = original.clone();
    case.swap(1, 2);
    cases.push(case);
    let mut case = original.clone();
    case[2]["extra"] = json!("unreviewed");
    cases.push(case);
    for (index, case) in cases.iter().enumerate() {
        assert!(terminal_stream(&stream(case)).is_err(), "case {index}");
    }
    assert!(terminal_stream(&good[..good.len() - 1]).is_err());
    assert!(
        terminal_stream(
            b"data: {\"type\":\"response.created\",\"type\":\"response.completed\"}\n\n"
        )
        .is_err()
    );
    assert!(terminal_stream(b"data: not-json\n\n").is_err());
}

#[test]
fn http_framing_and_routing_reject_ambiguity() {
    let valid = b"POST /v1/responses HTTP/1.1\r\nHost: stage1-metering-gateway:8080\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    assert_eq!(
        read_request(&mut Cursor::new(valid), 2).unwrap().body,
        b"{}"
    );
    let invalid: &[&[u8]] = &[
        b"GET /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST https://x/v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.0\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nHost: y\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}GET / HTTP/1.1\r\n\r\n",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 184467440737095516160000\r\n\r\n{}",
    ];
    for (index, raw) in invalid.iter().enumerate() {
        assert!(
            read_request(&mut Cursor::new(raw), 2).is_err(),
            "case {index}"
        );
    }
    let upstream: &[&[u8]] = &[
        b"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=x\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
    ];
    for (index, raw) in upstream.iter().enumerate() {
        assert!(
            read_upstream(&mut Cursor::new(raw), "text/event-stream").is_err(),
            "upstream {index}"
        );
    }
}
