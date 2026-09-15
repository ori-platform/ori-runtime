// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//! The HTTP/1.1 client both telemetry routes post through.
//!
//! What a response means decides whether readings were stored and whether
//! export is suspended for good, and the Python producer reads responses through
//! h11. A general-purpose client recovers from malformed responses in its own
//! way -- one tried here dropped header lines it could not parse, took the first
//! of two lengths, treated an interim `103` as the final answer and panicked on a
//! line without a colon -- and each recovery was a verdict the other producer
//! did not reach. So this reads a response exactly as h11 does, and anything h11
//! refuses is no answer.
//!
//! It holds one exchange per connection, bounds the whole exchange by one
//! deadline, and reads no more than the caller's ceiling of body bytes.

use rustls::pki_types::ServerName;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// The most bytes buffered while waiting for a header section, a trailer or a
/// chunk-size line to end.
///
/// A memory bound, not the contract's size rule. h11 refuses only while its
/// buffer is incomplete and past 102,400 bytes, and httpcore fills that buffer
/// in pieces of up to 64 KiB, so the Python producer can accept a section up to
/// this length. The contract's limit on a header section is applied to the
/// parsed fields instead (`delivery::readable_header_section`), which both
/// producers measure alike.
pub const MAX_HEAD_BYTES: usize = 102_400 + 64 * 1024;

/// h11 refuses a `Content-Length` of more digits than this.
const CONTENT_LENGTH_MAX_DIGITS: usize = 20;

/// Header fields as parsed: names as received, values as bytes.
pub type Fields = Vec<(String, Vec<u8>)>;

/// A response, as far as it was read.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Every field after h11's normalisation: names as received, values as
    /// bytes, identical repeated lengths merged into one.
    pub fields: Fields,
    pub body: Body,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    Complete(Vec<u8>),
    /// More than the ceiling arrived; reading stopped there.
    PastCeiling,
    /// The caller declined the body, or the status carries none that h11 reads.
    NotRead,
}

/// A byte stream whose remaining wait can be bounded.
pub trait Transport: Read + Write {
    fn wait_until(&mut self, deadline: Instant) -> io::Result<()>;
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "exchange deadline passed",
        ))
    } else {
        Ok(left)
    }
}

impl Transport for TcpStream {
    fn wait_until(&mut self, deadline: Instant) -> io::Result<()> {
        let left = remaining(deadline)?;
        self.set_read_timeout(Some(left))?;
        self.set_write_timeout(Some(left))
    }
}

struct TlsStream(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Transport for TlsStream {
    fn wait_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.0.sock.wait_until(deadline)
    }
}

/// The parts of an endpoint URL this client needs.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    /// For connecting and for TLS server name, without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// The `Host` header value.
    pub authority: String,
    /// Path and query.
    pub request_target: String,
}

pub fn parse_url(url: &str) -> Result<Target, String> {
    if url.bytes().any(|b| b <= b' ' || b == 0x7F) {
        return Err("endpoint URL contains whitespace or a control character".into());
    }
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("endpoint URL must be http:// or https://".into());
    };
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    let tail = tail.split('#').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("endpoint URL must name a host and no user information".into());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (inner, after) = bracketed
            .split_once(']')
            .ok_or("endpoint URL has an unclosed IPv6 bracket")?;
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or("endpoint URL has bytes after its IPv6 host")?,
            ),
        };
        (inner.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("endpoint URL has an empty host".into());
    }
    let port = match port {
        None => {
            if tls {
                443
            } else {
                80
            }
        }
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("endpoint URL has an invalid port")?,
    };
    let request_target = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    Ok(Target {
        tls,
        host,
        port,
        authority: authority.to_string(),
        request_target,
    })
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .expect("the ring provider supports TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Post `body` to `url` and read the answer.
///
/// `Err` means no answer: the endpoint could not be reached, or what came back
/// is not a response h11 would read. `wants_body` sees the final status and
/// fields and says whether to read the body at all.
pub fn post(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
    ceiling: usize,
    wants_body: impl FnOnce(u16, &[(String, Vec<u8>)]) -> bool,
) -> Result<Response, String> {
    let deadline = Instant::now() + timeout;
    let target = parse_url(url)?;
    let request = build_request(&target, headers, body)?;

    let addresses = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve the endpoint: {error}"))?;
    let mut last_error = String::from("the endpoint resolved to no addresses");
    let mut connected = None;
    for address in addresses {
        let left = remaining(deadline).map_err(|error| error.to_string())?;
        match TcpStream::connect_timeout(&address, left) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(error) => last_error = format!("cannot connect to the endpoint: {error}"),
        }
    }
    let tcp = connected.ok_or(last_error)?;

    if target.tls {
        let name = ServerName::try_from(target.host.clone())
            .map_err(|error| format!("invalid TLS server name: {error}"))?;
        let connection = rustls::ClientConnection::new(tls_config(), name)
            .map_err(|error| format!("cannot start TLS: {error}"))?;
        let mut stream = TlsStream(rustls::StreamOwned::new(connection, tcp));
        exchange(&mut stream, &request, deadline, ceiling, wants_body)
    } else {
        let mut stream = tcp;
        exchange(&mut stream, &request, deadline, ceiling, wants_body)
    }
}

fn build_request(
    target: &Target,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n",
        target.request_target, target.authority
    );
    for (name, value) in headers {
        let clean = |text: &str| !text.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0));
        if name.is_empty() || !name.bytes().all(is_token_byte) || !clean(value) {
            return Err(format!("request header {name} cannot be sent as given"));
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// Send `request` and read one response from `stream`.
pub fn exchange<S: Transport>(
    stream: &mut S,
    request: &[u8],
    deadline: Instant,
    ceiling: usize,
    wants_body: impl FnOnce(u16, &[(String, Vec<u8>)]) -> bool,
) -> Result<Response, String> {
    // A server may answer and close before it has read the whole request, as a
    // gateway refusing a credential does. httpcore reads that answer despite
    // the failed write, so a failed write is reported only if no response
    // follows it.
    let sent = stream
        .wait_until(deadline)
        .and_then(|()| stream.write_all(request))
        .and_then(|()| stream.flush());

    let mut reader = Buffered {
        stream,
        buf: Vec::new(),
        eof: false,
        deadline,
        send_failed: sent.is_err(),
    };

    let head = read_final_head(&mut reader);
    let (status, fields) = match (head, sent) {
        (Ok(head), _) => head,
        (Err(_), Err(error)) => return Err(format!("cannot send the request: {error}")),
        (Err(error), Ok(())) => return Err(error),
    };

    let framing = framing(status, &fields)?;
    if !wants_body(status, &fields) {
        return Ok(Response {
            status,
            fields,
            body: Body::NotRead,
        });
    }
    let body = match framing {
        Framing::Length(length) => reader.length_body(length, ceiling)?,
        Framing::Chunked => reader.chunked_body(ceiling)?,
        Framing::UntilClose => reader.close_body(ceiling)?,
    };
    Ok(Response {
        status,
        fields,
        body,
    })
}

/// The final response's head. Interim responses are read past, as httpcore
/// reads past them. A 101 is refused, as h11 refuses a protocol switch the
/// client did not ask for.
fn read_final_head<S: Transport>(reader: &mut Buffered<'_, S>) -> Result<(u16, Fields), String> {
    loop {
        let lines = reader.head_lines()?;
        let (status, fields) = parse_head(&lines)?;
        if status == 101 {
            return Err("the endpoint switched protocols, which was not requested".into());
        }
        if (100..200).contains(&status) {
            continue;
        }
        return Ok((status, fields));
    }
}

enum Framing {
    Length(u128),
    Chunked,
    UntilClose,
}

/// h11's body framing for a response to a POST.
fn framing(status: u16, fields: &[(String, Vec<u8>)]) -> Result<Framing, String> {
    if status == 204 || status == 304 {
        return Ok(Framing::Length(0));
    }
    let find = |wanted: &str| {
        fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value)
    };
    if find("transfer-encoding").is_some() {
        return Ok(Framing::Chunked);
    }
    if let Some(length) = find("content-length") {
        let text = std::str::from_utf8(length).map_err(|_| "bad Content-Length")?;
        return text
            .parse::<u128>()
            .map(Framing::Length)
            .map_err(|_| "bad Content-Length".to_string());
    }
    Ok(Framing::UntilClose)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Python's `\s` in a bytes pattern: space, tab, LF, VT, FF, CR.
fn is_regex_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// h11's `field_vchar`: anything but NUL and whitespace.
fn is_field_vchar(b: u8) -> bool {
    b != 0 && !is_regex_space(b)
}

/// Strip what Python's `bytes.strip()` strips.
fn strip_ascii_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !is_regex_space(*b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_regex_space(*b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Parse a status line and header lines as h11 does, then normalise the
/// fields as h11's `normalize_and_validate` does.
pub fn parse_head(lines: &[Vec<u8>]) -> Result<(u16, Fields), String> {
    let Some((status_line, header_lines)) = lines.split_first() else {
        return Err("no response line received".into());
    };
    let status = parse_status_line(status_line)?;

    // Obsolete line folding: a line starting with space or tab continues the
    // previous one, joined by a single space.
    let mut unfolded: Vec<Vec<u8>> = Vec::new();
    for line in header_lines {
        let fold = line
            .iter()
            .take_while(|b| matches!(b, b' ' | b'\t'))
            .count();
        if fold > 0 {
            let Some(previous) = unfolded.last_mut() else {
                return Err("continuation line at start of headers".into());
            };
            previous.push(b' ');
            previous.extend_from_slice(&line[fold..]);
        } else {
            unfolded.push(line.clone());
        }
    }

    let mut fields: Fields = Vec::new();
    let mut seen_length: Option<Vec<u8>> = None;
    let mut seen_transfer = false;
    for line in &unfolded {
        let (name, value) = parse_field_line(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            let mut lengths: Vec<&[u8]> =
                value.split(|b| *b == b',').map(strip_ascii_space).collect();
            lengths.sort();
            lengths.dedup();
            if lengths.len() != 1 {
                return Err("conflicting Content-Length headers".into());
            }
            let length = lengths[0].to_vec();
            if length.is_empty()
                || !length.iter().all(u8::is_ascii_digit)
                || length.len() > CONTENT_LENGTH_MAX_DIGITS
            {
                return Err("bad Content-Length".into());
            }
            match &seen_length {
                None => {
                    seen_length = Some(length.clone());
                    fields.push((name, length));
                }
                Some(previous) if *previous == length => {}
                Some(_) => return Err("conflicting Content-Length headers".into()),
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if seen_transfer {
                return Err("multiple Transfer-Encoding headers".into());
            }
            let lowered = value.to_ascii_lowercase();
            if lowered != b"chunked" {
                return Err("only Transfer-Encoding: chunked is supported".into());
            }
            seen_transfer = true;
            fields.push((name, lowered));
        } else {
            fields.push((name, value));
        }
    }
    Ok((status, fields))
}

fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    let invalid = || "illegal status line".to_string();
    let rest = line.strip_prefix(b"HTTP/").ok_or_else(invalid)?;
    if rest.len() < 7
        || !rest[0].is_ascii_digit()
        || rest[1] != b'.'
        || !rest[2].is_ascii_digit()
        || rest[3] != b' '
        || !rest[4..7].iter().all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let reason = &rest[7..];
    if !reason.is_empty() {
        let text = reason.strip_prefix(b" ").ok_or_else(invalid)?;
        if !text
            .iter()
            .all(|b| matches!(b, b' ' | b'\t') || is_field_vchar(*b))
        {
            return Err(invalid());
        }
    }
    let status: u16 = std::str::from_utf8(&rest[4..7])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(invalid)?;
    // h11 builds an informational response for 100-199 and a response for
    // 200-999, and refuses anything below 100.
    if status < 100 {
        return Err("status code below 100".into());
    }
    Ok(status)
}

/// h11's `header_field`: a token, a colon, optional whitespace, a value of
/// field-vchars separated by runs of space or tab, optional whitespace.
fn parse_field_line(line: &[u8]) -> Result<(String, Vec<u8>), String> {
    let illegal = || "illegal header line".to_string();
    let colon = line.iter().position(|b| *b == b':').ok_or_else(illegal)?;
    let (name, rest) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || !name.iter().all(|b| is_token_byte(*b)) {
        return Err(illegal());
    }
    let start = rest
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(rest.len());
    let end = rest
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    let value = &rest[start..end];
    if !value
        .iter()
        .all(|b| matches!(b, b' ' | b'\t') || is_field_vchar(*b))
    {
        return Err(illegal());
    }
    let name = String::from_utf8(name.to_vec()).map_err(|_| illegal())?;
    Ok((name, value.to_vec()))
}

struct Buffered<'a, S: Transport> {
    stream: &'a mut S,
    buf: Vec<u8>,
    eof: bool,
    deadline: Instant,
    /// After the peer has reset the connection, some platforms refuse to set a
    /// timeout on the socket while the answer it sent still waits to be read.
    /// The last timeout set still bounds the read, so the refusal is ignored.
    send_failed: bool,
}

impl<S: Transport> Buffered<'_, S> {
    /// Read more bytes into the buffer. False at end of stream.
    fn more(&mut self) -> Result<bool, String> {
        if self.eof {
            return Ok(false);
        }
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            if let Err(error) = self.stream.wait_until(self.deadline) {
                if !self.send_failed || error.kind() == io::ErrorKind::TimedOut {
                    return Err(format!("response did not arrive in time: {error}"));
                }
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(read) => {
                    self.buf.extend_from_slice(&chunk[..read]);
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A TLS peer closing without close_notify is how many servers
                // end a close-delimited body; it is the end of the stream.
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.eof = true;
                    return Ok(false);
                }
                Err(error) => return Err(format!("response could not be read: {error}")),
            }
        }
    }

    /// Everything up to the first blank line, split into lines, as h11's
    /// `maybe_extract_lines` does.
    fn head_lines(&mut self) -> Result<Vec<Vec<u8>>, String> {
        // Where the blank-line search resumes, so bytes arriving one at a time
        // are scanned once rather than from the start on every read.
        let mut searched = 0;
        loop {
            if self.buf.first() == Some(&b'\n') {
                self.buf.drain(..1);
                return Ok(Vec::new());
            }
            if self.buf.starts_with(b"\r\n") {
                self.buf.drain(..2);
                return Ok(Vec::new());
            }
            if let Some(end) = blank_line_end(&self.buf, searched) {
                if end > MAX_HEAD_BYTES {
                    return Err("response header section is too long".into());
                }
                let head: Vec<u8> = self.buf.drain(..end).collect();
                let mut lines: Vec<Vec<u8>> = head
                    .split(|b| *b == b'\n')
                    .map(|line| line.strip_suffix(b"\r").unwrap_or(line).to_vec())
                    .collect();
                lines.truncate(lines.len().saturating_sub(2));
                return Ok(lines);
            }
            searched = self.buf.len().saturating_sub(2);
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err("response header section is too long".into());
            }
            if !self.more()? {
                return Err("connection closed before a complete response".into());
            }
        }
    }

    fn length_body(&mut self, length: u128, ceiling: usize) -> Result<Body, String> {
        let limit = (ceiling as u128).saturating_add(1);
        while (self.buf.len() as u128) < length.min(limit) {
            if !self.more()? {
                return Err("connection closed before the declared body length".into());
            }
        }
        if length > ceiling as u128 {
            return Ok(Body::PastCeiling);
        }
        Ok(Body::Complete(self.buf[..length as usize].to_vec()))
    }

    fn close_body(&mut self, ceiling: usize) -> Result<Body, String> {
        while self.buf.len() <= ceiling {
            if !self.more()? {
                return Ok(Body::Complete(std::mem::take(&mut self.buf)));
            }
        }
        Ok(Body::PastCeiling)
    }

    fn chunked_body(&mut self, ceiling: usize) -> Result<Body, String> {
        let mut body = Vec::new();
        loop {
            let line = self.line_through_crlf()?;
            let size = parse_chunk_header(&line)?;
            if size == 0 {
                // The trailer section, read and validated as header lines.
                let trailer = self.head_lines()?;
                let mut lines = vec![b"HTTP/1.1 200 trailer".to_vec()];
                lines.extend(trailer);
                parse_head(&lines).map_err(|error| format!("illegal chunked trailer: {error}"))?;
                return Ok(Body::Complete(body));
            }
            let mut left = size;
            while left > 0 {
                if self.buf.is_empty() && !self.more()? {
                    return Err("connection closed inside a chunk".into());
                }
                let take = (self.buf.len() as u128).min(left) as usize;
                body.extend(self.buf.drain(..take));
                left -= take as u128;
                if body.len() > ceiling {
                    return Ok(Body::PastCeiling);
                }
            }
            while self.buf.len() < 2 {
                if !self.more()? {
                    return Err("connection closed inside a chunk".into());
                }
            }
            if &self.buf[..2] != b"\r\n" {
                return Err("malformed chunk footer".into());
            }
            self.buf.drain(..2);
        }
    }

    /// One line including its CRLF, as h11's `maybe_extract_next_line` does.
    fn line_through_crlf(&mut self) -> Result<Vec<u8>, String> {
        let mut searched = 0;
        loop {
            if let Some(offset) = self.buf[searched..]
                .windows(2)
                .position(|pair| pair == b"\r\n")
            {
                let end = searched + offset + 2;
                if end > MAX_HEAD_BYTES {
                    return Err("chunk header is too long".into());
                }
                return Ok(self.buf.drain(..end).collect());
            }
            searched = self.buf.len().saturating_sub(1);
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err("chunk header is too long".into());
            }
            if !self.more()? {
                return Err("connection closed inside a chunked body".into());
            }
        }
    }
}

/// The end of h11's `\n\r?\n` blank-line match at or after `from`, if the
/// buffer holds one.
fn blank_line_end(buf: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index < buf.len() {
        if buf[index] == b'\n' {
            if buf.get(index + 1) == Some(&b'\n') {
                return Some(index + 2);
            }
            if buf.get(index + 1) == Some(&b'\r') && buf.get(index + 2) == Some(&b'\n') {
                return Some(index + 3);
            }
        }
        index += 1;
    }
    None
}

/// h11's `chunk_header`: 1-20 hex digits, an optional extension, optional
/// whitespace, CRLF.
fn parse_chunk_header(line: &[u8]) -> Result<u128, String> {
    let illegal = || "illegal chunk header".to_string();
    let body = line.strip_suffix(b"\r\n").ok_or_else(illegal)?;
    let digits = body.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 20 {
        return Err(illegal());
    }
    let rest = &body[digits..];
    let tail_ok = match rest.first() {
        None => true,
        // `;.*` matches anything but a newline, and a trailing `[ \t]*` is
        // absorbed by it.
        Some(b';') => !rest.contains(&b'\n'),
        Some(_) => rest.iter().all(|b| matches!(b, b' ' | b'\t')),
    };
    if !tail_ok {
        return Err(illegal());
    }
    let text = std::str::from_utf8(&body[..digits]).map_err(|_| illegal())?;
    u128::from_str_radix(text, 16).map_err(|_| illegal())
}

/// A whole response held in memory, for tests that read raw bytes.
#[cfg(test)]
pub(crate) struct Scripted {
    pub input: io::Cursor<Vec<u8>>,
    pub step: usize,
    pub sent: Vec<u8>,
}

#[cfg(test)]
impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let limit = buf.len().min(self.step);
        self.input.read(&mut buf[..limit])
    }
}

#[cfg(test)]
impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sent.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl Transport for Scripted {
    fn wait_until(&mut self, _deadline: Instant) -> io::Result<()> {
        Ok(())
    }
}

/// Read `raw` as a response to one request, as the transport would.
#[cfg(test)]
pub(crate) fn read_raw(
    raw: &[u8],
    step: usize,
    ceiling: usize,
    wants_body: impl FnOnce(u16, &[(String, Vec<u8>)]) -> bool,
) -> Result<Response, String> {
    let mut stream = Scripted {
        input: io::Cursor::new(raw.to_vec()),
        step,
        sent: Vec::new(),
    };
    exchange(
        &mut stream,
        b"POST / HTTP/1.1\r\n\r\n",
        Instant::now() + Duration::from_secs(5),
        ceiling,
        wants_body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read `raw` delivered in pieces of 1, 7 and 4096 bytes, and require the
    /// same result from each.
    fn read(raw: &[u8], ceiling: usize) -> Result<Response, String> {
        let reference = read_raw(raw, 4096, ceiling, |_, _| true);
        for step in [1, 7] {
            assert_eq!(
                read_raw(raw, step, ceiling, |_, _| true),
                reference,
                "delivery in {step}-byte pieces changed the result"
            );
        }
        reference
    }

    fn body_of(raw: &[u8]) -> Vec<u8> {
        match read(raw, 64 * 1024).expect("readable").body {
            Body::Complete(body) => body,
            other => panic!("expected a complete body, got {other:?}"),
        }
    }

    #[test]
    fn a_length_delimited_response_is_read() {
        let response = read(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            64,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Body::Complete(b"{}".to_vec()));
    }

    #[test]
    fn a_line_without_a_colon_is_no_answer_not_a_crash() {
        assert!(read(
            b"HTTP/1.1 503 X\r\nNotAHeaderLine\r\nContent-Length: 0\r\n\r\n",
            64
        )
        .is_err());
        assert!(read(b"HTTP/1.1 403 X\r\nContent-Type\r\n\r\n", 64).is_err());
    }

    #[test]
    fn an_invalid_field_name_is_no_answer() {
        assert!(read(
            b"HTTP/1.1 403 X\r\nWWW-Authenticate : Bearer\r\nContent-Length: 0\r\n\r\n",
            64
        )
        .is_err());
        assert!(read(
            b"HTTP/1.1 403 X\r\n: Bearer\r\nContent-Length: 0\r\n\r\n",
            64
        )
        .is_err());
    }

    #[test]
    fn a_folded_line_joins_the_previous_with_one_space() {
        let response = read(b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n \t gzip\r\nContent-Length: 0\r\n\r\n", 64).unwrap();
        assert_eq!(
            response.fields[0],
            ("Content-Encoding".to_string(), b"identity gzip".to_vec())
        );
        assert!(read(b"HTTP/1.1 200 OK\r\n folded-first: x\r\n\r\n", 64).is_err());
    }

    #[test]
    fn interim_responses_are_read_past_and_a_101_is_refused() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let response = read(raw, 64).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Body::Complete(b"{}".to_vec()));
        assert!(read(b"HTTP/1.1 101 Switching\r\nUpgrade: x\r\n\r\n", 64).is_err());
    }

    #[test]
    fn lengths_are_normalised_as_h11_normalises_them() {
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}"),
            b"{}"
        );
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\n{}"),
            b"{}"
        );
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 00000000000000000002\r\n\r\n{}"),
            b"{}"
        );
        for refused in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 000000000000000000002\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n{}",
        ] {
            assert!(
                read(refused, 64).is_err(),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[test]
    fn only_a_single_chunked_transfer_coding_is_read() {
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"),
            b"{}"
        );
        assert_eq!(body_of(b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=1 \r\n{}\r\n0\r\nX-Trailer: y\r\n\r\n"), b"{}");
        for refused in [
            &b"HTTP/1.1 403 X\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.0 403 X\r\nTransfer-Encoding: chunked\r\n\r\n{\"detail\":\"device is suspended\"}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n",
        ] {
            assert!(read(refused, 64).is_err(), "{}", String::from_utf8_lossy(refused));
        }
    }

    #[test]
    fn transfer_coding_wins_over_length_as_in_h11() {
        assert_eq!(body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"), b"{}");
    }

    #[test]
    fn line_endings_follow_h11() {
        assert_eq!(body_of(b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}"), b"{}");
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nContent-Length: 2\n\r\n{}"),
            b"{}"
        );
        assert!(
            read(b"\r\nHTTP/1.1 200 OK\r\n\r\n", 64).is_err(),
            "a leading blank line is no response line"
        );
    }

    #[test]
    fn values_keep_bytes_h11_keeps_and_refuse_those_it_refuses() {
        let response = read(b"HTTP/1.1 200 OK\r\nX-Site: caf\xc3\xa9\x01\r\nX-Tab: a\tb\r\nContent-Length: 0\r\n\r\n", 64).unwrap();
        assert_eq!(response.fields[0].1, b"caf\xc3\xa9\x01".to_vec());
        assert_eq!(response.fields[1].1, b"a\tb".to_vec());
        assert!(read(b"HTTP/1.1 200 OK\r\nX-Bad: a\x00b\r\n\r\n", 64).is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nX-Bad: a\x0bb\r\n\r\n", 64).is_err());
        assert!(read(b"HTTP/1.1 200 OK\r\nX-Bad: a\rb\r\n\r\n", 64).is_err());
    }

    #[test]
    fn status_lines_follow_h11() {
        assert_eq!(
            read(b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n", 64)
                .unwrap()
                .status,
            200
        );
        for refused in [
            &b"HTTP/1.1 99 X\r\n\r\n"[..],
            b"HTTP/1.1 099 X\r\n\r\n",
            b"HTTP/11 200 OK\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"http/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 200OK\r\n\r\n",
        ] {
            assert!(
                read(refused, 64).is_err(),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[test]
    fn bodies_stop_past_the_ceiling() {
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345", 4)
                .unwrap()
                .body,
            Body::PastCeiling
        );
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234", 4)
                .unwrap()
                .body,
            Body::Complete(b"1234".to_vec())
        );
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\n\r\n12345", 4).unwrap().body,
            Body::PastCeiling
        );
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\n\r\n1234", 4).unwrap().body,
            Body::Complete(b"1234".to_vec())
        );
        assert_eq!(read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n123\r\n2\r\n45\r\n0\r\n\r\n", 4).unwrap().body, Body::PastCeiling);
        assert!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n123", 64).is_err(),
            "cut short"
        );
    }

    #[test]
    fn statuses_without_a_body_read_none() {
        assert_eq!(
            read(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", 64)
                .unwrap()
                .body,
            Body::Complete(Vec::new())
        );
    }

    #[test]
    fn a_header_section_past_the_limit_is_no_answer() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES + 10));
        raw.extend_from_slice(b"\r\n\r\n");
        assert!(read(&raw, 64).is_err());
    }

    #[test]
    fn a_header_section_that_never_ends_is_refused_at_the_memory_bound() {
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 2 * MAX_HEAD_BYTES));
        let error = read_raw(&raw, 4096, 64, |_, _| true).unwrap_err();
        assert!(error.contains("too long"), "{error}");
    }

    #[test]
    fn a_chunk_size_line_that_never_ends_is_refused_at_the_memory_bound() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;".to_vec();
        raw.extend(std::iter::repeat_n(b'x', 2 * MAX_HEAD_BYTES));
        let error = read_raw(&raw, 4096, 64, |_, _| true).unwrap_err();
        assert!(error.contains("too long"), "{error}");
    }

    #[test]
    fn chunked_bodies_are_refused_when_cut_short_or_malformed() {
        for refused in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n000000000000000000002\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2x\r\n{}\r\n0\r\n\r\n",
        ] {
            assert!(read(refused, 64).is_err(), "{}", String::from_utf8_lossy(refused));
        }
        assert_eq!(
            body_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000000002\r\n{}\r\n0\r\n\n"),
            b"{}",
            "twenty hex digits, and a trailer ending in a bare LF"
        );
    }

    #[test]
    fn a_head_is_scanned_once_however_it_arrives() {
        // One byte per read across a head near the bound: rescanning from the
        // start on every read took over a second here, which a slow phone link
        // could turn into a missed deadline.
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 100_000));
        raw.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let started = Instant::now();
        assert!(read_raw(&raw, 1, 64, |_, _| true).is_ok());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_answer_sent_before_the_request_was_taken_is_read() {
        let mut stream = Scripted {
            input: io::Cursor::new(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            ),
            step: 4096,
            sent: Vec::new(),
        };
        let response = exchange(
            &mut RefusingWrites(&mut stream),
            b"POST / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(5),
            64,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(response.status, 403);
        let mut silent = Scripted {
            input: io::Cursor::new(Vec::new()),
            step: 4096,
            sent: Vec::new(),
        };
        let error = exchange(
            &mut RefusingWrites(&mut silent),
            b"POST / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(5),
            64,
            |_, _| true,
        )
        .unwrap_err();
        assert!(error.contains("cannot send the request"), "{error}");
    }

    struct RefusingWrites<'a>(&'a mut Scripted);

    impl Read for RefusingWrites<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for RefusingWrites<'_> {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for RefusingWrites<'_> {
        fn wait_until(&mut self, _deadline: Instant) -> io::Result<()> {
            Ok(())
        }
    }

    /// Ends with UnexpectedEof, as a TLS peer does that closes without
    /// close_notify.
    struct EndsWithoutCloseNotify(io::Cursor<Vec<u8>>);

    impl Read for EndsWithoutCloseNotify {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                read => Ok(read),
            }
        }
    }

    impl Write for EndsWithoutCloseNotify {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for EndsWithoutCloseNotify {
        fn wait_until(&mut self, _deadline: Instant) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_peer_closing_without_close_notify_ends_a_close_delimited_body() {
        let mut stream =
            EndsWithoutCloseNotify(io::Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec()));
        let response = exchange(
            &mut stream,
            b"POST / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(5),
            64,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(response.body, Body::Complete(b"{}".to_vec()));
    }

    #[test]
    fn the_request_names_its_host() {
        let target = parse_url("http://127.0.0.1:8010/runtime/telemetry").unwrap();
        let request = build_request(&target, &[("X-A", "b")], b"{}").unwrap();
        let text = String::from_utf8(request).unwrap();
        assert!(
            text.starts_with("POST /runtime/telemetry HTTP/1.1\r\nHost: 127.0.0.1:8010\r\n"),
            "{text}"
        );
        assert!(text.ends_with("Content-Length: 2\r\n\r\n{}"), "{text}");
    }

    #[test]
    fn the_tls_configuration_trusts_the_published_roots() {
        assert!(webpki_roots::TLS_SERVER_ROOTS.len() > 100);
        let config = tls_config();
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn a_101_before_a_final_response_is_still_refused() {
        let raw = b"HTTP/1.1 101 Switching\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert!(read(raw, 64).is_err());
    }

    #[test]
    fn a_padded_head_past_h11s_incomplete_limit_is_read_within_the_memory_bound() {
        // 120 KB on the wire, almost all of it whitespace around one value. The
        // memory bound is set where the Python producer's parser can still
        // accept such a head, not at its 102,400-byte incomplete limit.
        let mut raw = b"HTTP/1.1 200 OK\r\nX-Pad:".to_vec();
        raw.extend(std::iter::repeat_n(b' ', 120 * 1024));
        raw.extend_from_slice(b"a\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            read_raw(&raw, 64 * 1024, 64, |_, _| true).unwrap().status,
            200
        );
    }

    #[test]
    fn a_completed_chunk_size_line_past_the_memory_bound_is_refused() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;".to_vec();
        raw.extend(std::iter::repeat_n(b'x', MAX_HEAD_BYTES));
        raw.extend_from_slice(b"\r\n{}\r\n0\r\n\r\n");
        // Delivered whole, so only the completed line's own length can refuse it.
        let error = read_raw(&raw, raw.len(), 64, |_, _| true).unwrap_err();
        assert!(error.contains("too long"), "{error}");
    }

    #[test]
    fn a_chunk_size_line_is_scanned_once_however_it_arrives() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;".to_vec();
        raw.extend(std::iter::repeat_n(b'x', 100_000));
        raw.extend_from_slice(b"\r\n{}\r\n0\r\n\r\n");
        let started = Instant::now();
        assert!(read_raw(&raw, 1, 64, |_, _| true).is_ok());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
    }

    /// Fails every timeout reset once its writes have failed, as macOS does for
    /// a socket the peer has reset.
    struct ResetPeer(io::Cursor<Vec<u8>>);

    impl Read for ResetPeer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ResetPeer {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for ResetPeer {
        fn wait_until(&mut self, _deadline: Instant) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }
    }

    #[test]
    fn an_answer_is_read_after_a_reset_even_where_timeouts_cannot_be_set() {
        let mut stream = ResetPeer(io::Cursor::new(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        ));
        let response = exchange(
            &mut stream,
            b"POST / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(5),
            64,
            |_, _| true,
        )
        .unwrap();
        assert_eq!(response.status, 403);
    }

    #[test]
    fn urls_are_parsed_strictly() {
        let target = parse_url("https://product.example.invalid/runtime/telemetry").unwrap();
        assert_eq!(
            (
                target.tls,
                target.port,
                target.authority.as_str(),
                target.request_target.as_str()
            ),
            (true, 443, "product.example.invalid", "/runtime/telemetry")
        );
        let local = parse_url("http://127.0.0.1:8010/runtime/telemetry/sensor-status").unwrap();
        assert_eq!((local.host.as_str(), local.port), ("127.0.0.1", 8010));
        let v6 = parse_url("http://[::1]:8010/x").unwrap();
        assert_eq!(
            (v6.host.as_str(), v6.authority.as_str()),
            ("::1", "[::1]:8010")
        );
        for refused in [
            "ftp://h/x",
            "http://user@h/x",
            "http://h:0/x",
            "http://h x/",
            "http:///x",
            "http://[::1/x",
        ] {
            assert!(parse_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_header_value_that_would_split_the_request_is_not_sent() {
        let target = parse_url("http://127.0.0.1:1/x").unwrap();
        assert!(build_request(&target, &[("Authorization", "Bearer a\r\nX: y")], b"").is_err());
        assert!(build_request(&target, &[("Bad Name", "v")], b"").is_err());
    }
}
