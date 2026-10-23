use crate::{Denial, Result};
use std::io::{Read, Write};

pub const MAX_HEADER: usize = 16 * 1024;
pub const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADERS: usize = 32;

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
            "location" | "content-encoding" | "transfer-encoding" | "set-cookie"
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
        for invalid in [
            b"POST /v1/responses?x=1 HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.1\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"POST /v1/responses HTTP/1.0\r\nHost: gateway\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(read_request(&mut Cursor::new(invalid), 16).is_err());
        }
    }
}
