#![forbid(unsafe_code)]

use agentguard_stage1_metering_gateway::config::{expected_pricing, parse_mock_config};
use agentguard_stage1_metering_gateway::http::{DeadlineReader, read_request, write_response};
use agentguard_stage1_metering_gateway::ledger::StudyLedger;
use agentguard_stage1_metering_gateway::session::{LocalTlsProvider, Session};
use agentguard_stage1_metering_gateway::{Denial, MAX_REQUEST_BYTES, Result};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn run() -> Result<()> {
    if std::env::var("STAGE1_RUST_MOCK_ONLY").ok().as_deref() != Some("true")
        || std::env::var_os("CODEX_API_KEY").is_some()
    {
        return Err(Denial::InvalidConfig);
    }
    agentguard_stage1_metering_gateway::transport::check_proxy_environment()?;
    expected_pricing()?;
    let config = parse_mock_config(
        &fs::read("/stage1-config/config.json").map_err(|_| Denial::InvalidConfig)?,
    )?;
    let synthetic =
        std::env::var("STAGE1_B1_SYNTHETIC_TOKEN").map_err(|_| Denial::InvalidConfig)?;
    let fake_upstream =
        std::env::var("STAGE1_B1_FAKE_UPSTREAM_TOKEN").map_err(|_| Denial::InvalidConfig)?;
    if synthetic == fake_upstream
        || fake_upstream.len() < 16
        || fake_upstream.len() > 128
        || !fake_upstream.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(Denial::InvalidConfig);
    }
    let ledger = StudyLedger::open(
        &PathBuf::from("/stage1-ledger"),
        &PathBuf::from("/stage1-ledger-anchor"),
        config.scope,
    )?;
    let provider = LocalTlsProvider {
        ca_file: "/stage1-config/ca.der".into(),
        fake_upstream_token: fake_upstream,
    };
    let mut session = Session::new(
        ledger,
        &config.trial_id,
        synthetic.as_bytes(),
        provider,
        config.output_cap,
        PathBuf::from("/stage1-metering/evidence.json"),
    )?;
    let listener = TcpListener::bind("0.0.0.0:8080").map_err(|_| Denial::Io)?;
    eprintln!("STAGE1_RUST_GATEWAY_READY");
    for connection in listener.incoming() {
        let mut stream = connection.map_err(|_| Denial::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Denial::Io)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| Denial::Io)?;
        handle(&mut stream, &mut session);
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, session: &mut Session<LocalTlsProvider>) {
    let request = match read_request(
        &mut DeadlineReader::new(&mut *stream, Duration::from_secs(30)),
        MAX_REQUEST_BYTES,
    ) {
        Ok(request) => request,
        Err(_) => {
            eprintln!("STAGE1_RUST_DENIAL_REQUEST_FRAMING");
            session.reject();
            let _ = write_response(stream, 400, "text/plain", b"request denied\n");
            return;
        }
    };
    let host = request.header("host");
    let token = request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer "));
    if !matches!(host, Some("stage1-metering-gateway:8080")) || token.is_none_or(str::is_empty) {
        eprintln!("STAGE1_RUST_DENIAL_BINDING");
        session.reject();
        let _ = write_response(stream, 403, "text/plain", b"request denied\n");
        return;
    }
    let result = session.process(&request.body, token.unwrap_or("").as_bytes());
    match result {
        Ok(body) => {
            if write_response(stream, 200, "text/event-stream", &body).is_err() {
                session.reject();
            }
        }
        Err(failure) => {
            let stage = match failure {
                Denial::InvalidConfig => "CONFIGURATION",
                Denial::InvalidRequest => "REQUEST",
                Denial::InvalidProvider => "PROVIDER",
                Denial::Budget => "BUDGET",
                Denial::Uncertain => "ACCOUNTING",
                Denial::Io => "IO",
            };
            eprintln!("STAGE1_RUST_DENIAL_{stage}");
            let _ = write_response(stream, 403, "text/plain", b"request denied\n");
        }
    }
}

fn main() {
    if run().is_err() {
        eprintln!("STAGE1_RUST_GATEWAY_STOPPED");
        std::process::exit(2);
    }
}
