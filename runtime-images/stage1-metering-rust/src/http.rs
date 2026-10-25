use crate::{Denial, Result};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub const MAX_HEADER: usize = 16 * 1024;
pub const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADERS: usize = 32;

pub struct DeadlineReader<R> {
    inner: R,
    deadline: Instant,
}

impl<R: Read> DeadlineReader<R> {
    pub fn new(inner: R, maximum: Duration) -> Self {
        Self {
            inner,
            deadline: Instant::now() + maximum,
        }
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline"));
        }
        let count = self.inner.read(buffer)?;
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline"));
        }
        Ok(count)
    }
}

#[derive(Debug)]
pub struct Message {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct UpstreamResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

struct PrefixReader<'a, R: Read> {
    prefix: Vec<u8>,
    position: usize,
    inner: &'a mut R,
}

impl<R: Read> Read for PrefixReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position < self.prefix.len() {
            let count = buffer.len().min(self.prefix.len() - self.position);
            buffer[..count].copy_from_slice(&self.prefix[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        } else {
            self.inner.read(buffer)
        }
    }
}

fn read_chunked<R: Read>(reader: &mut R, prefix: Vec<u8>) -> Result<Vec<u8>> {
    let mut source = PrefixReader {
        prefix,
        position: 0,
        inner: reader,
    };
    let mut decoded = Vec::new();
    loop {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            source
                .read_exact(&mut byte)
                .map_err(|_| Denial::InvalidProvider)?;
            line.push(byte[0]);
            if line.len() > 18 {
                return Err(Denial::InvalidProvider);
            }
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let digits = &line[..line.len() - 2];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(Denial::InvalidProvider);
        }
        let text = std::str::from_utf8(digits).map_err(|_| Denial::InvalidProvider)?;
        let size = usize::from_str_radix(text, 16).map_err(|_| Denial::InvalidProvider)?;
        if size == 0 {
            let mut ending = [0_u8; 2];
            source
                .read_exact(&mut ending)
                .map_err(|_| Denial::InvalidProvider)?;
            if ending != *b"\r\n" || source.position != source.prefix.len() {
                return Err(Denial::InvalidProvider);
            }
            break;
        }
        if size > MAX_BODY - decoded.len() {
            return Err(Denial::InvalidProvider);
        }
        let offset = decoded.len();
        decoded.resize(offset + size, 0);
        source
            .read_exact(&mut decoded[offset..])
            .map_err(|_| Denial::InvalidProvider)?;
        let mut separator = [0_u8; 2];
        source
            .read_exact(&mut separator)
            .map_err(|_| Denial::InvalidProvider)?;
        if separator != *b"\r\n" {
            return Err(Denial::InvalidProvider);
        }
    }
    if decoded.is_empty() {
        return Err(Denial::InvalidProvider);
    }
    Ok(decoded)
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn read_head<R: Read>(reader: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let count = reader.read(&mut chunk).map_err(|_| Denial::Io)?;
        if count == 0 || bytes.len() + count > MAX_HEADER + MAX_BODY {
            return Err(Denial::InvalidRequest);
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 > MAX_HEADER {
                return Err(Denial::InvalidRequest);
            }
            return Ok((bytes[..end + 4].to_vec(), bytes[end + 4..].to_vec()));
        }
        if bytes.len() > MAX_HEADER {
            return Err(Denial::InvalidRequest);
        }
    }
}

fn parse_headers(head: &[u8]) -> Result<Vec<(String, String)>> {
    if head.contains(&0) {
        return Err(Denial::InvalidRequest);
    }
    let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut raw);
    if !matches!(request.parse(head), Ok(httparse::Status::Complete(_))) {
        return Err(Denial::InvalidRequest);
    }
    if request.version != Some(1) {
        return Err(Denial::InvalidRequest);
    }
    let mut result = Vec::new();
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Denial::InvalidRequest)?
            .trim();
        if name.is_empty()
            || value.len() > 4096
            || value.bytes().any(|byte| byte < 32 || byte == 127)
            || result
                .iter()
                .any(|(key, _): &(String, String)| key == &name)
        {
            return Err(Denial::InvalidRequest);
        }
        result.push((name, value.to_owned()));
    }
    Ok(result)
}

pub fn read_request<R: Read>(reader: &mut R, maximum_body: usize) -> Result<Message> {
    let (head, mut body) = read_head(reader)?;
    let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut raw);
    request.parse(&head).map_err(|_| Denial::InvalidRequest)?;
    let method = request.method.ok_or(Denial::InvalidRequest)?.to_owned();
    let path = request.path.ok_or(Denial::InvalidRequest)?.to_owned();
    let headers = parse_headers(&head)?;
    if method != "POST" || path != "/v1/responses" {
        return Err(Denial::InvalidRequest);
    }
    for (name, _) in &headers {
        if !matches!(
            name.as_str(),
            "host"
                | "content-type"
                | "content-length"
                | "authorization"
                | "connection"
                | "accept"
                | "user-agent"
                | "x-agentguard-trial"
                | "x-agentguard-request"
                | "originator"
                | "session-id"
                | "thread-id"
                | "x-client-request-id"
                | "x-codex-beta-features"
                | "x-codex-window-id"
                | "x-codex-turn-metadata"
        ) {
            return Err(Denial::InvalidRequest);
        }
    }
    if headers.iter().any(|(name, _)| {
        matches!(
            name.as_str(),
            "transfer-encoding" | "cookie" | "proxy-authorization"
        )
    }) {
        return Err(Denial::InvalidRequest);
    }
    let message = Message {
        method,
        path,
        headers,
        body: Vec::new(),
    };
    if message.header("content-type") != Some("application/json") {
        return Err(Denial::InvalidRequest);
    }
    let size = message
        .header("content-length")
        .ok_or(Denial::InvalidRequest)?;
    if (size.starts_with('0') && size != "0") || !size.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Denial::InvalidRequest);
    }
    let size = size.parse::<usize>().map_err(|_| Denial::InvalidRequest)?;
    if size == 0 || size > maximum_body || body.len() > size {
        return Err(Denial::InvalidRequest);
    }
    while body.len() < size {
        let mut buffer = [0_u8; 8192];
        let limit = buffer.len().min(size - body.len());
        let count = reader.read(&mut buffer[..limit]).map_err(|_| Denial::Io)?;
        if count == 0 {
            return Err(Denial::InvalidRequest);
        }
        body.extend_from_slice(&buffer[..count]);
    }
    Ok(Message { body, ..message })
}

pub fn read_upstream<R: Read>(reader: &mut R, expected_type: &str) -> Result<UpstreamResponse> {
    let (head, mut body) = read_head(reader).map_err(|_| Denial::InvalidProvider)?;
    let mut raw = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut raw);
    if !matches!(response.parse(&head), Ok(httparse::Status::Complete(_))) {
        return Err(Denial::InvalidProvider);
    }
    let status = response.code.ok_or(Denial::InvalidProvider)?;
    if response.version != Some(1) || status != 200 {
        return Err(Denial::InvalidProvider);
    }
    let mut headers = Vec::<(String, String)>::new();
    for header in response.headers {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Denial::InvalidProvider)?
            .trim();
        if name.is_empty()
            || value.len() > 4096
            || value.bytes().any(|byte| byte < 32 || byte == 127)
            || headers.iter().any(|(key, _)| key == &name)
        {
            return Err(Denial::InvalidProvider);
        }
        headers.push((name, value.to_owned()));
    }
    if headers.iter().any(|(name, _)| {
        matches!(
            name.as_str(),
            "location" | "content-encoding" | "set-cookie" | "trailer"
        )
    }) {
        return Err(Denial::InvalidProvider);
    }
    let field = |key: &str| {
        headers
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    };
    if field("content-type")
        .is_none_or(|value| value.split(';').next().unwrap_or("").trim() != expected_type)
    {
        return Err(Denial::InvalidProvider);
    }
    if let Some(encoding) = field("transfer-encoding") {
        if encoding != "chunked" || field("content-length").is_some() {
            return Err(Denial::InvalidProvider);
        }
        let decoded = read_chunked(reader, body)?;
        return Ok(UpstreamResponse {
            status,
            content_type: expected_type.into(),
            body: decoded,
        });
    }
    let size = field("content-length").ok_or(Denial::InvalidProvider)?;
    if size.is_empty()
        || (size.starts_with('0') && size != "0")
        || !size.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Denial::InvalidProvider);
    }
    let size = size.parse::<usize>().map_err(|_| Denial::InvalidProvider)?;
    if size == 0 || size > MAX_BODY || body.len() > size {
        return Err(Denial::InvalidProvider);
    }
    while body.len() < size {
        let mut chunk = [0_u8; 8192];
        let limit = chunk.len().min(size - body.len());
        let count = reader
            .read(&mut chunk[..limit])
            .map_err(|_| Denial::InvalidProvider)?;
        if count == 0 {
            return Err(Denial::InvalidProvider);
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(UpstreamResponse {
        status,
        content_type: expected_type.into(),
        body,
    })
}

pub fn write_response<W: Write>(
    writer: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    if body.len() > MAX_BODY || !matches!(status, 200 | 400 | 401 | 403 | 409 | 429 | 502) {
        return Err(Denial::InvalidConfig);
    }
    let reason = if status == 200 { "OK" } else { "Rejected" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    writer
        .write_all(header.as_bytes())
        .and_then(|_| writer.write_all(body))
        .map_err(|_| Denial::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn exact_request_and_smuggling_denial() {
        let valid = b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            read_request(&mut Cursor::new(valid), 16).unwrap().body,
            b"{}"
        );
        let frozen_codex_headers = b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nOriginator: codex_cli_rs\r\nSession-Id: 00000000-0000-0000-0000-000000000001\r\nThread-Id: 00000000-0000-0000-0000-000000000001\r\nX-Client-Request-Id: 00000000-0000-0000-0000-000000000001\r\nX-Codex-Window-Id: 00000000-0000-0000-0000-000000000002\r\nX-Codex-Turn-Metadata: {}\r\n\r\n{}";
        assert_eq!(
            read_request(&mut Cursor::new(frozen_codex_headers), 16)
                .unwrap()
                .body,
            b"{}"
        );
        for invalid in [
            b"POST /v1/responses?x=1 HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.0\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX-Unknown: value\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nCookie: value\r\n\r\n{}",
        ] {
            assert!(read_request(&mut Cursor::new(invalid), 16).is_err());
        }
    }

    #[test]
    fn upstream_framing_and_redirects_fail_closed() {
        let valid =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(
            read_upstream(&mut Cursor::new(valid), "application/json")
                .unwrap()
                .body,
            b"{}"
        );
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(
            read_upstream(&mut Cursor::new(chunked), "application/json")
                .unwrap()
                .body,
            b"{}"
        );
        for invalid in [
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=x\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX: y\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{",
            b"NOT_HTTP\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(read_upstream(&mut Cursor::new(invalid), "application/json").is_err());
        }
    }

    #[test]
    fn total_read_deadline_rejects_trickle() {
        struct Trickle;
        impl Read for Trickle {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_millis(3));
                buffer[0] = b'P';
                Ok(1)
            }
        }
        let mut reader = DeadlineReader::new(Trickle, Duration::from_millis(1));
        assert!(read_request(&mut reader, 16).is_err());
    }
}
