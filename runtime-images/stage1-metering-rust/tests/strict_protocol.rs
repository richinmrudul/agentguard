use agentguard_stage1_metering_gateway::http::{MAX_BODY, MAX_HEADER, read_request, read_upstream};
use agentguard_stage1_metering_gateway::protocol::{count_payload, parse_json, terminal_stream};
use serde_json::{Value, json};
use std::io::{self, Cursor, Read};

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

fn resequence(values: &mut [Value]) {
    for (index, value) in values.iter_mut().enumerate() {
        value["sequence_number"] = json!(index);
    }
}

#[test]
fn json_depth_element_string_and_number_boundaries() {
    assert!(parse_json(b"{}", 0).is_err());
    assert!(parse_json(b"{}", 1).is_err());
    assert!(parse_json(b"{}", 2).is_ok());
    let array_at_limit = serde_json::to_vec(&json!({"input": vec![0; 128]})).unwrap();
    assert!(parse_json(&array_at_limit, 2 * 1024 * 1024).is_ok());
    let array_over_limit = serde_json::to_vec(&json!({"input": vec![0; 129]})).unwrap();
    assert!(parse_json(&array_over_limit, 2 * 1024 * 1024).is_err());
    let string_at_limit = serde_json::to_vec(&json!({"input": "x".repeat(64 * 1024)})).unwrap();
    assert!(parse_json(&string_at_limit, 2 * 1024 * 1024).is_ok());
    let string_over_limit =
        serde_json::to_vec(&json!({"input": "x".repeat(64 * 1024 + 1)})).unwrap();
    assert!(parse_json(&string_over_limit, 2 * 1024 * 1024).is_err());
    let depth_at_limit = format!("{{\"x\":{}0{}}}", "[".repeat(23), "]".repeat(23));
    assert!(parse_json(depth_at_limit.as_bytes(), 2 * 1024 * 1024).is_ok());
    let depth_over_limit = format!("{{\"x\":{}0{}}}", "[".repeat(24), "]".repeat(24));
    assert!(parse_json(depth_over_limit.as_bytes(), 2 * 1024 * 1024).is_err());
    for raw in [
        b"{\"model\":1,\"model\":2}".as_slice(),
        b"{\"value\":18446744073709551616}",
        b"{\"value\":-1.5}",
        b"{\"value\":NaN}",
        b"{\"value\":\"\xff\"}",
        b"{\"value\":\"a\x00b\"}",
    ] {
        assert!(parse_json(raw, 2 * 1024 * 1024).is_err());
    }
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
fn sse_documented_content_and_local_tool_lifecycles() {
    let mut full = events(&valid_stream());
    full.insert(
        1,
        json!({"type":"response.in_progress","sequence_number":1,
        "response":{"id":"resp_1","model":"gpt-5.2-2025-12-11","status":"in_progress"}}),
    );
    full.insert(
        3,
        json!({"type":"response.content_part.added","sequence_number":3,
        "item_id":"msg_1","output_index":0,"content_index":0,
        "part":{"type":"output_text","text":"","annotations":[],"logprobs":[]}}),
    );
    full.insert(
        5,
        json!({"type":"response.output_text.done","sequence_number":5,
        "item_id":"msg_1","output_index":0,"content_index":0,"text":"ok","logprobs":[]}),
    );
    full.insert(
        6,
        json!({"type":"response.content_part.done","sequence_number":6,
        "item_id":"msg_1","output_index":0,"content_index":0,
        "part":{"type":"output_text","text":"ok","annotations":[],"logprobs":[]}}),
    );
    resequence(&mut full);
    assert!(terminal_stream(&stream(&full)).is_ok());
    let mut invalid = full.clone();
    invalid.remove(6);
    resequence(&mut invalid);
    assert!(terminal_stream(&stream(&invalid)).is_err());
    let mut invalid = full.clone();
    invalid[5]["text"] = json!("other");
    assert!(terminal_stream(&stream(&invalid)).is_err());
    let mut invalid = full.clone();
    invalid[5]["logprobs"] = json!([{"unreviewed":true}]);
    assert!(terminal_stream(&stream(&invalid)).is_err());
    let mut invalid = full.clone();
    invalid[7]["item"]["content"] = json!([]);
    invalid[8]["response"]["output"][0]["content"] = json!([]);
    assert!(terminal_stream(&stream(&invalid)).is_err());
    let mut invalid = full.clone();
    invalid[7]["item"]["content"][0]["unreviewed"] = json!(true);
    invalid[8]["response"]["output"][0] = invalid[7]["item"].clone();
    assert!(terminal_stream(&stream(&invalid)).is_err());

    for (kind, name, delta_kind, done_kind, field) in [
        (
            "function_call",
            "exec_command",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "arguments",
        ),
        (
            "custom_tool_call",
            "apply_patch",
            "response.custom_tool_call_input.delta",
            "response.custom_tool_call_input.done",
            "input",
        ),
    ] {
        let mut tool = events(&valid_stream());
        tool[1]["item"] = json!({"id":"call_1","type":kind,"name":name});
        tool[2] = json!({"type":delta_kind,"sequence_number":2,
            "item_id":"call_1","output_index":0,"delta":"{}"});
        let mut complete = json!({"id":"call_1","type":kind,"name":name});
        complete[field] = json!("{}");
        let mut done = json!({"type":done_kind,"sequence_number":3,
            "item_id":"call_1","output_index":0});
        done[field] = json!("{}");
        tool.insert(3, done);
        tool[4]["item"] = complete.clone();
        tool[5]["response"]["output"] = json!([complete]);
        resequence(&mut tool);
        assert!(terminal_stream(&stream(&tool)).is_ok(), "{kind}");
        let mut invalid = tool.clone();
        invalid[3][field] = json!("changed");
        assert!(terminal_stream(&stream(&invalid)).is_err(), "{kind}");
        let mut invalid = tool.clone();
        let swapped = if kind == "function_call" {
            "custom_tool_call"
        } else {
            "function_call"
        };
        invalid[4]["item"]["type"] = json!(swapped);
        invalid[4]["item"]["name"] = json!(if swapped == "function_call" {
            "exec_command"
        } else {
            "apply_patch"
        });
        let swapped_item = invalid[4]["item"].clone();
        invalid[5]["response"]["output"][0] = swapped_item;
        assert!(terminal_stream(&stream(&invalid)).is_err(), "{kind}");
    }
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
    case[2]["sequence_number"] = json!(99);
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
    let mut case = original.clone();
    case[4]["type"] = json!("response.failed");
    cases.push(case);
    let mut case = original.clone();
    case[4]["type"] = json!("response.incomplete");
    cases.push(case);
    let mut case = original.clone();
    case[1]["type"] = json!("response.web_search_call.in_progress");
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["input_tokens_details"]["cached_tokens"] = json!(-1);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["total_tokens"] = json!(11);
    cases.push(case);
    let mut case = original.clone();
    case[0]["response"]["output"] = json!([{"id":"msg_1"}]);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["output_tokens"] = json!(3.5);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["output_tokens"] = json!(-1);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["usage"]["input_tokens_details"]["cached_tokens"] = json!(99);
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["status"] = json!("incomplete");
    cases.push(case);
    let mut case = original.clone();
    case[4]["response"]["error"] = json!({"message":"contradictory"});
    cases.push(case);
    for (index, case) in cases.iter().enumerate() {
        assert!(terminal_stream(&stream(case)).is_err(), "case {index}");
    }
    assert!(terminal_stream(&good[..good.len() - 1]).is_err());
    let mut invalid_utf8 = good.clone();
    invalid_utf8[8] = 0xff;
    assert!(terminal_stream(&invalid_utf8).is_err());
    let mut unsupported_sse_field = good.clone();
    unsupported_sse_field.splice(0..0, b"event: response.created\n".iter().copied());
    assert!(terminal_stream(&unsupported_sse_field).is_err());
    let mut oversized = b"data: ".to_vec();
    oversized.extend(vec![b'x'; 64 * 1024]);
    oversized.extend(b"\n\n");
    assert!(terminal_stream(&oversized).is_err());
    assert!(
        terminal_stream(
            b"data: {\"type\":\"response.created\",\"type\":\"response.completed\"}\n\n"
        )
        .is_err()
    );
    assert!(terminal_stream(b"data: not-json\n\n").is_err());
    assert!(terminal_stream(b"data: {\"type\":\"response.created\"}\n").is_err());
    let mut over_stream = good.clone();
    over_stream.extend(vec![b' '; 2 * 1024 * 1024]);
    assert!(terminal_stream(&over_stream).is_err());
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
        b"POST /v1/responses HTTP/2.0\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST x:443 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses?x=1 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nCookie: x\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nProxy-Authorization: x\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX-Unreviewed: x\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX: \xff\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX: x\x00y\r\n\r\n{}",
        b"POST /v1/responses HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n Folded: x\r\n\r\n{}",
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
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; unreviewed=x\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: gzip\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX: y\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 3\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 2\r\n\r\n{}X",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\nX",
    ];
    for (index, raw) in upstream.iter().enumerate() {
        assert!(
            read_upstream(&mut Cursor::new(raw), "text/event-stream").is_err(),
            "upstream {index}"
        );
    }
}

#[test]
fn http_body_and_header_exact_boundaries() {
    let prefix = b"POST /v1/responses HTTP/1.1\r\nHost: stage1-metering-gateway:8080\r\nContent-Type: application/json\r\nContent-Length: ";
    for size in [MAX_BODY - 1, MAX_BODY, MAX_BODY + 1] {
        let mut raw = prefix.to_vec();
        raw.extend_from_slice(size.to_string().as_bytes());
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend(vec![b'x'; size]);
        assert_eq!(
            read_request(&mut Cursor::new(raw), MAX_BODY).is_ok(),
            size <= MAX_BODY,
            "body size {size}"
        );
    }
    fn header_of_size(target: usize) -> Vec<u8> {
        let names = ["User-Agent", "Originator", "Session-Id", "Thread-Id"];
        let mut raw = b"POST /v1/responses HTTP/1.1\r\nHost: stage1-metering-gateway:8080\r\nContent-Type: application/json\r\nContent-Length: 2\r\n".to_vec();
        let overhead = names.iter().map(|name| name.len() + 4).sum::<usize>() + 2;
        let mut remaining = target - raw.len() - overhead;
        for name in names {
            let length = remaining.min(4096);
            remaining -= length;
            raw.extend_from_slice(name.as_bytes());
            raw.extend_from_slice(b": ");
            raw.extend(vec![b'x'; length]);
            raw.extend_from_slice(b"\r\n");
        }
        assert_eq!(remaining, 0);
        raw.extend_from_slice(b"\r\n{}");
        raw
    }
    assert!(read_request(&mut Cursor::new(header_of_size(MAX_HEADER)), 2).is_ok());
    assert!(read_request(&mut Cursor::new(header_of_size(MAX_HEADER + 1)), 2).is_err());
}

#[test]
fn http_every_truncated_prefix_and_late_body_byte_fail() {
    let request = b"POST /v1/responses HTTP/1.1\r\nHost: stage1-metering-gateway:8080\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    for end in 0..request.len() {
        assert!(read_request(&mut Cursor::new(&request[..end]), 2).is_err(), "request prefix {end}");
    }
    let mut extra = request.to_vec();
    extra.push(b'X');
    assert!(read_request(&mut Cursor::new(extra), 2).is_err());
    let upstream = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    for end in 0..upstream.len() {
        assert!(read_upstream(&mut Cursor::new(&upstream[..end]), "application/json").is_err(), "upstream prefix {end}");
    }
    let mut extra = upstream.to_vec();
    extra.push(b'X');
    assert!(read_upstream(&mut Cursor::new(extra), "application/json").is_err());
}

#[test]
fn sse_exact_frame_bound_and_each_transport_boundary_fail_closed() {
    let good = valid_stream();
    let first_end = good.windows(2).position(|part| part == b"\n\n").unwrap();
    let mut at_limit = good[..first_end].to_vec();
    at_limit.extend(vec![b' '; 64 * 1024 - first_end]);
    at_limit.extend_from_slice(&good[first_end..]);
    assert!(terminal_stream(&at_limit).is_ok());
    let mut above_limit = good[..first_end].to_vec();
    above_limit.extend(vec![b' '; 64 * 1024 + 1 - first_end]);
    above_limit.extend_from_slice(&good[first_end..]);
    assert!(terminal_stream(&above_limit).is_err());

    struct TimeoutAfter(Cursor<Vec<u8>>);
    impl Read for TimeoutAfter {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buffer)? {
                0 => Err(io::Error::from(io::ErrorKind::TimedOut)),
                count => Ok(count),
            }
        }
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
        good.len()
    );
    let mut cuts = vec![0, good.len() - 1];
    cuts.extend(good.windows(2).enumerate().filter_map(|(index, part)| {
        (part == b"\n\n" && index + 2 < good.len()).then_some(index + 2)
    }));
    for cut in cuts {
        let mut partial = header.as_bytes().to_vec();
        partial.extend_from_slice(&good[..cut]);
        assert!(read_upstream(&mut Cursor::new(partial.clone()), "text/event-stream").is_err(), "disconnect at {cut}");
        assert!(read_upstream(&mut TimeoutAfter(Cursor::new(partial)), "text/event-stream").is_err(), "timeout at {cut}");
    }
}

#[test]
fn count_generation_identity_binding_changes_with_input_and_model() {
    let mut generation = json!({
        "model": "gpt-5.2-2025-12-11",
        "prompt_cache_retention": "in_memory",
        "input": [{"role": "user", "content": "first"}],
        "instructions": "bounded",
        "tools": [],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "reasoning": {"effort": "none"},
        "max_output_tokens": 8
    });
    let original = count_payload(&generation).unwrap();
    let counted: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(counted["input"], generation["input"]);
    assert_eq!(counted["instructions"], generation["instructions"]);
    assert_eq!(counted["tools"], generation["tools"]);
    generation["input"][0]["content"] = json!("changed");
    assert_ne!(count_payload(&generation).unwrap(), original);
    generation["model"] = json!("gpt-5.2");
    assert!(count_payload(&generation).is_err());
}

#[test]
fn sse_every_response_and_item_identity_mismatch_rejected() {
    let mut original = events(&valid_stream());
    original.insert(
        1,
        json!({"type":"response.in_progress","sequence_number":1,
            "response":{"id":"resp_1","model":"gpt-5.2-2025-12-11",
                "status":"in_progress"}}),
    );
    resequence(&mut original);
    assert!(terminal_stream(&stream(&original)).is_ok());
    for index in [0, 1, 5] {
        let mut changed = original.clone();
        changed[index]["response"]["id"] = json!("resp_other");
        assert!(terminal_stream(&stream(&changed)).is_err(), "response {index}");
    }
    for index in [2, 4] {
        let mut changed = original.clone();
        changed[index]["item"]["id"] = json!("msg_other");
        assert!(terminal_stream(&stream(&changed)).is_err(), "item {index}");
    }
    let mut changed = original.clone();
    changed[3]["item_id"] = json!("msg_other");
    assert!(terminal_stream(&stream(&changed)).is_err());
    let mut changed = original.clone();
    changed[5]["response"]["output"][0]["id"] = json!("msg_other");
    assert!(terminal_stream(&stream(&changed)).is_err());
}
