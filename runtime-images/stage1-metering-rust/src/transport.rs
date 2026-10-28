use crate::http::{DeadlineReader, UpstreamResponse, read_upstream};
use crate::{Denial, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const DESTINATION: &str = "api.openai.com";
pub const PORT: u16 = 443;

pub fn allowed_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || a == 169 && b == 254
                || a == 172 && (16..=31).contains(&b)
                || a == 192 && b == 168
                || a == 100 && (64..=127).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 0 && c == 2
                || a == 192 && b == 88 && c == 99
                || a == 198 && (b == 18 || b == 19 || b == 51 && c == 100)
                || a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(!(0x2000..=0x3fff).contains(&segments[0])
                || (segments[0] & 0xfffe) == 0x2000
                || segments[0] == 0x2001 && segments[1] == 0x0db8
                || segments[0] == 0x2002
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

pub fn check_proxy_environment() -> Result<()> {
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ] {
        if std::env::var_os(key).is_some() {
            return Err(Denial::InvalidConfig);
        }
    }
    Ok(())
}

pub fn connect_exact(
    host: &str,
    port: u16,
    test_addresses: Option<&[SocketAddr]>,
) -> Result<TcpStream> {
    if host != DESTINATION || port != PORT {
        return Err(Denial::InvalidConfig);
    }
    check_proxy_environment()?;
    let addresses: Vec<SocketAddr> = match test_addresses {
        Some(addresses) => addresses.to_vec(),
        None => (host, port)
            .to_socket_addrs()
            .map_err(|_| Denial::Io)?
            .collect(),
    };
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses
            .iter()
            .any(|address| address.port() != PORT || !allowed_address(address.ip()))
    {
        return Err(Denial::InvalidConfig);
    }
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .map_err(|_| Denial::Io)?;
            stream
                .set_write_timeout(Some(Duration::from_secs(15)))
                .map_err(|_| Denial::Io)?;
            return Ok(stream);
        }
    }
    Err(Denial::Io)
}

pub fn validate_upstream_path(method: &str, path: &str) -> Result<()> {
    if method != "POST" || !matches!(path, "/v1/responses/input_tokens" | "/v1/responses") {
        return Err(Denial::InvalidRequest);
    }
    Ok(())
}

fn tls_post(
    socket: TcpStream,
    server_name: &'static str,
    host_header: &'static str,
    roots: RootCertStore,
    path: &str,
    body: &[u8],
    token: &[u8],
) -> Result<UpstreamResponse> {
    validate_upstream_path("POST", path)?;
    if body.is_empty()
        || body.len() > crate::MAX_REQUEST_BYTES
        || !(16..=512).contains(&token.len())
        || !token.iter().all(u8::is_ascii_graphic)
        || roots.is_empty()
    {
        return Err(Denial::InvalidConfig);
    }
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(server_name).map_err(|_| Denial::InvalidConfig)?;
    let connection =
        ClientConnection::new(Arc::new(tls_config), name).map_err(|_| Denial::InvalidConfig)?;
    let mut stream = StreamOwned::new(connection, socket);
    let mut header = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAuthorization: Bearer "
    )
    .into_bytes();
    header.extend_from_slice(token);
    header.extend_from_slice(
        format!(
            "\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    let write_result = stream
        .write_all(&header)
        .and_then(|_| stream.write_all(body));
    header.fill(0);
    write_result.map_err(|_| Denial::Io)?;
    let expected_type = if path == "/v1/responses/input_tokens" {
        "application/json"
    } else {
        "text/event-stream"
    };
    read_upstream(
        &mut DeadlineReader::new(&mut stream, Duration::from_secs(60)),
        expected_type,
    )
}

pub fn live_tls_request(path: &str, body: &[u8], credential: &[u8]) -> Result<UpstreamResponse> {
    validate_upstream_path("POST", path)?;
    if body.is_empty() || body.len() > crate::MAX_REQUEST_BYTES {
        return Err(Denial::InvalidRequest);
    }
    if !(16..=512).contains(&credential.len()) || !credential.iter().all(u8::is_ascii_graphic) {
        return Err(Denial::InvalidConfig);
    }
    let socket = connect_exact(DESTINATION, PORT, None)?;
    tls_post(
        socket,
        DESTINATION,
        DESTINATION,
        crate::trust::production_roots(),
        path,
        body,
        credential,
    )
}

pub fn mock_tls_request(
    path: &str,
    body: &[u8],
    fake_token: &[u8],
    ca_file: &Path,
) -> Result<UpstreamResponse> {
    validate_upstream_path("POST", path)?;
    if body.len() > crate::MAX_REQUEST_BYTES
        || fake_token.is_empty()
        || fake_token.len() > 256
        || !fake_token.iter().all(u8::is_ascii_graphic)
    {
        return Err(Denial::InvalidConfig);
    }
    check_proxy_environment()?;
    let addresses: Vec<SocketAddr> = ("stage1-mock-provider", 8443)
        .to_socket_addrs()
        .map_err(|_| {
            eprintln!("STAGE1_RUST_STAGE_MOCK_DNS_FAILED");
            Denial::Io
        })?
        .collect();
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses
            .iter()
            .any(|address| address.port() != 8443 || allowed_address(address.ip()))
    {
        return Err(Denial::InvalidConfig);
    }
    let socket = addresses
        .into_iter()
        .find_map(|address| TcpStream::connect_timeout(&address, Duration::from_secs(5)).ok())
        .ok_or_else(|| {
            eprintln!("STAGE1_RUST_STAGE_MOCK_CONNECT_FAILED");
            Denial::Io
        })?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Denial::Io)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Denial::Io)?;
    let metadata = fs::metadata(ca_file).map_err(|_| Denial::InvalidConfig)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 16 * 1024 {
        return Err(Denial::InvalidConfig);
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            fs::read(ca_file).map_err(|_| Denial::InvalidConfig)?,
        ))
        .map_err(|_| Denial::InvalidConfig)?;
    if roots.is_empty() {
        return Err(Denial::InvalidConfig);
    }
    tls_post(
        socket,
        "stage1-mock-provider",
        "stage1-mock-provider:8443",
        roots,
        path,
        body,
        fake_token,
    )
    .inspect_err(|_| eprintln!("STAGE1_RUST_STAGE_MOCK_TLS_EXCHANGE_FAILED"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_unreviewed_paths_and_private_destinations() {
        for path in [
            "/v1/models",
            "/v1/responses/abc",
            "/v1/responses?x=1",
            "/v1/files",
        ] {
            assert!(validate_upstream_path("POST", path).is_err());
        }
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "10.1.2.3",
            "192.168.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!allowed_address(address.parse().unwrap()));
        }
        let token = b"FAKE_TEST_ONLY_UPSTREAM_TOKEN";
        assert!(live_tls_request("/v1/models", b"{}", token).is_err());
        assert!(live_tls_request("/v1/responses?x=1", b"{}", token).is_err());
        assert!(connect_exact("example.com", PORT, None).is_err());
        let private = ["127.0.0.1:443".parse().unwrap()];
        assert!(connect_exact(DESTINATION, PORT, Some(&private)).is_err());
    }
}
