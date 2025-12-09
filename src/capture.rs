use anyhow::{anyhow, bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    signal,
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tracing::{error, info, warn};
use url::Url;

const HEADER_DELIMITER: &[u8] = b"\r\n\r\n";
const MANIFEST_VERSION: &str = "1.1";

pub async fn run_proxy_capture(
    out: &str,
    proxy: &str,
    include: &[String],
    exclude: &[String],
    max_size: u64,
    intercept: bool,
    exit_after: Option<usize>,
) -> Result<()> {
    if intercept {
        warn!("TLS intercept is disabled in v1.1; proceeding without MITM.");
    }
    let addr = if proxy.starts_with(':') {
        format!("127.0.0.1{}", proxy)
    } else {
        proxy.to_string()
    };

    let base = PathBuf::from(out);
    prepare_shot_dirs(&base).await?;
    let max_bytes = max_size.min(usize::MAX as u64) as usize;
    let entry_limit = exit_after.or_else(|| {
        std::env::var("FLOW_RECORD_EXIT_AFTER")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
    });
    let state = Arc::new(CaptureState::new(
        base,
        include.to_vec(),
        exclude.to_vec(),
        max_bytes,
        addr.clone(),
        entry_limit,
    ));

    let listener = TcpListener::bind(&addr).await?;
    info!("Flow proxy listening on {}", addr);
    let mut tasks = JoinSet::new();
    let shutdown = signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((client, peer)) => {
                        let state = state.clone();
                        tasks.spawn(async move {
                            if let Err(err) = handle_connection(client, state).await {
                                error!("proxy error from {peer}: {err:?}");
                            }
                        });
                    }
                    Err(err) => {
                        warn!("listener error: {err:?}");
                        break;
                    }
                }
            }
            sig = &mut shutdown => {
                match sig {
                    Ok(()) => info!("shutdown signal received, stopping capture"),
                    Err(err) => warn!("failed waiting on shutdown signal: {err:?}"),
                }
                break;
            }
            _ = state.stop_notify.notified() => {
                info!("entry limit reached; stopping capture loop");
                break;
            }
        }
    }

    while tasks.join_next().await.is_some() {}
    state.write_manifest().await?;
    info!(
        "manifest written to {}",
        state.base.join("manifest.json").display()
    );
    Ok(())
}

async fn prepare_shot_dirs(base: &Path) -> Result<()> {
    for path in ["requests", "responses", "canonical", "proofs", "sig"] {
        fs::create_dir_all(base.join(path)).await?;
    }
    Ok(())
}

async fn handle_connection(mut client: TcpStream, state: Arc<CaptureState>) -> Result<()> {
    let mut request_buf = Vec::new();
    let header_len = read_until_headers(&mut client, &mut request_buf, state.max_size).await?;
    if header_len == 0 {
        return Ok(());
    }
    let header_str = std::str::from_utf8(&request_buf[..header_len])
        .context("request headers were not valid UTF-8")?;
    let parsed = ParsedRequest::parse(header_str)?;

    if parsed.expects_continue() {
        send_continue(&mut client).await?;
    }

    let body_kind = parsed.body_kind();
    read_body(
        &mut client,
        &mut request_buf,
        header_len,
        body_kind,
        state.max_size,
    )
    .await?;

    if parsed.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, request_buf, parsed, state).await
    } else {
        handle_plain_http(client, request_buf, parsed, state).await
    }
}

async fn handle_connect(
    mut client: TcpStream,
    request_bytes: Vec<u8>,
    parsed: ParsedRequest,
    state: Arc<CaptureState>,
) -> Result<()> {
    let (host_port, host_for_log) = parsed.connect_host()?;
    if !state.is_allowed(&host_port) {
        respond_with_status(&mut client, 403, "Forbidden", "filtered by flow\n").await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect(&host_port).await {
        Ok(stream) => stream,
        Err(err) => {
            respond_with_status(&mut client, 502, "Bad Gateway", "upstream connect failed\n")
                .await?;
            return Err(anyhow!("failed to CONNECT to {host_port}: {err}"));
        }
    };

    let response_bytes = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    client.write_all(response_bytes).await?;

    let (id, ts) = state.next_id();
    state
        .record_entry(
            &id,
            ts,
            &parsed.method,
            &host_for_log,
            "/",
            200,
            &request_bytes,
            response_bytes,
        )
        .await?;

    let _ = io::copy_bidirectional(&mut client, &mut upstream).await;
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(())
}

async fn handle_plain_http(
    mut client: TcpStream,
    request_bytes: Vec<u8>,
    parsed: ParsedRequest,
    state: Arc<CaptureState>,
) -> Result<()> {
    let target = parsed.http_target();
    info!(
        "proxy request {} {} via host {}",
        parsed.method, target.path, target.host_port
    );
    if !state.is_allowed(&target.host_port) {
        respond_with_status(&mut client, 403, "Forbidden", "filtered by flow\n").await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect(&target.host_port).await {
        Ok(stream) => stream,
        Err(err) => {
            respond_with_status(&mut client, 502, "Bad Gateway", "upstream connect failed\n")
                .await?;
            return Err(anyhow!("failed to reach {}: {err}", target.host_port));
        }
    };

    let outbound_request = rewrite_request_line(
        &request_bytes,
        &parsed.method,
        &parsed.version,
        &target.path,
    );
    upstream.write_all(&outbound_request).await?;

    let mut full_response = Vec::new();
    let mut upgrade = false;

    let final_status = loop {
        let (mut response_part, response_head) =
            read_response_message(&mut upstream, state.max_size).await?;
        let status = response_head.status;

        client.write_all(&response_part).await?;
        full_response.append(&mut response_part);

        if status == 101 {
            upgrade = true;
            break status;
        }

        if !(100..200).contains(&status) {
            break status;
        }
    };

    if upgrade {
        let _ = io::copy_bidirectional(&mut client, &mut upstream).await;
    }

    let (id, ts) = state.next_id();
    state
        .record_entry(
            &id,
            ts,
            &parsed.method,
            &target.canonical_host,
            &target.path,
            final_status,
            &request_bytes,
            &full_response,
        )
        .await?;
    Ok(())
}

fn rewrite_request_line(original: &[u8], method: &str, version: &str, path: &str) -> Vec<u8> {
    if let Some(pos) = original.windows(2).position(|w| w == b"\r\n") {
        let mut buf = Vec::with_capacity(original.len());
        buf.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
        buf.extend_from_slice(&original[pos + 2..]);
        buf
    } else {
        original.to_vec()
    }
}

async fn respond_with_status(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let payload = body.as_bytes();
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        body
    );
    client.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_continue(client: &mut TcpStream) -> Result<()> {
    client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    Ok(())
}

async fn read_response_message(
    stream: &mut TcpStream,
    max_size: usize,
) -> Result<(Vec<u8>, ParsedResponse)> {
    let mut buf = Vec::new();
    let header_len = read_until_headers(stream, &mut buf, max_size).await?;
    if header_len == 0 {
        bail!("upstream closed before sending response");
    }

    let header_str =
        std::str::from_utf8(&buf[..header_len]).context("response headers were not valid UTF-8")?;
    let parsed = ParsedResponse::parse(header_str)?;
    let body_kind = parsed.body_kind();
    read_body(stream, &mut buf, header_len, body_kind, max_size).await?;
    Ok((buf, parsed))
}

async fn read_body(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    header_len: usize,
    body_kind: BodyKind,
    max_size: usize,
) -> Result<()> {
    match body_kind {
        BodyKind::None => {}
        BodyKind::ContentLength(len) => {
            read_exact_bytes(stream, buf, header_len, len, max_size).await?;
        }
        BodyKind::Chunked => {
            read_chunked(stream, buf, header_len, max_size).await?;
        }
        BodyKind::UntilClose => {
            read_until_close(stream, buf, max_size).await?;
        }
    }
    Ok(())
}

async fn read_exact_bytes(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    header_len: usize,
    len: usize,
    max_size: usize,
) -> Result<()> {
    while buf.len() - header_len < len {
        read_into(stream, buf, max_size).await?;
    }
    Ok(())
}

async fn read_chunked(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    mut idx: usize,
    max_size: usize,
) -> Result<()> {
    loop {
        let size_line_end = loop {
            if let Some(pos) = find_crlf(buf, idx) {
                break pos;
            }
            read_into(stream, buf, max_size).await?;
        };
        let size_str = std::str::from_utf8(&buf[idx..size_line_end])
            .context("chunk size was not valid UTF-8")?
            .trim();
        let chunk_size =
            usize::from_str_radix(size_str, 16).context("chunk size was not valid hex")?;
        let chunk_data_start = size_line_end + 2;
        let chunk_data_end = chunk_data_start + chunk_size;
        while buf.len() < chunk_data_end + 2 {
            read_into(stream, buf, max_size).await?;
        }
        idx = chunk_data_end + 2;
        if chunk_size == 0 {
            loop {
                if find_double_crlf(buf, idx).is_some() {
                    return Ok(());
                }
                read_into(stream, buf, max_size).await?;
            }
        }
    }
}

async fn read_until_close(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    max_size: usize,
) -> Result<()> {
    loop {
        match read_into_allow_eof(stream, buf, max_size).await? {
            0 => return Ok(()),
            _ => continue,
        }
    }
}

async fn read_into(stream: &mut TcpStream, buf: &mut Vec<u8>, max_size: usize) -> Result<usize> {
    let mut tmp = [0u8; 8192];
    let n = stream.read(&mut tmp).await?;
    if n == 0 {
        bail!("connection closed unexpectedly");
    }
    buf.extend_from_slice(&tmp[..n]);
    ensure!(
        buf.len() <= max_size,
        "message exceeded configured max size"
    );
    Ok(n)
}

async fn read_into_allow_eof(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    max_size: usize,
) -> Result<usize> {
    let mut tmp = [0u8; 8192];
    let n = stream.read(&mut tmp).await?;
    if n > 0 {
        buf.extend_from_slice(&tmp[..n]);
        ensure!(
            buf.len() <= max_size,
            "message exceeded configured max size"
        );
    }
    Ok(n)
}

async fn read_until_headers(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    max_size: usize,
) -> Result<usize> {
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = find_double_crlf(buf, 0) {
            return Ok(pos + HEADER_DELIMITER.len());
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(0)
            } else {
                Err(anyhow!("EOF while reading headers"))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
        ensure!(
            buf.len() <= max_size,
            "message exceeded configured max size"
        );
    }
}

fn find_double_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)
        .and_then(|slice| slice.windows(4).position(|w| w == HEADER_DELIMITER))
        .map(|pos| start + pos)
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    buf.get(start..)
        .and_then(|slice| slice.windows(2).position(|w| w == b"\r\n"))
        .map(|pos| start + pos)
}

struct ParsedRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl ParsedRequest {
    fn parse(head: &str) -> Result<Self> {
        let mut lines = head.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| anyhow!("request missing start line"))?;
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| anyhow!("request missing method"))?
            .to_string();
        let target = parts
            .next()
            .ok_or_else(|| anyhow!("request missing target"))?
            .to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        let headers = parse_headers(lines)?;
        Ok(Self {
            method,
            target,
            version,
            headers,
        })
    }

    fn expects_continue(&self) -> bool {
        header_value(&self.headers, "expect")
            .map(|v| v.eq_ignore_ascii_case("100-continue"))
            .unwrap_or(false)
    }

    fn body_kind(&self) -> BodyKind {
        if let Some(te) = header_value(&self.headers, "transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                return BodyKind::Chunked;
            }
        }
        if let Some(cl) = header_value(&self.headers, "content-length") {
            if let Ok(len) = cl.parse::<usize>() {
                if len > 0 {
                    return BodyKind::ContentLength(len);
                }
            }
        }
        BodyKind::None
    }

    fn connect_host(&self) -> Result<(String, String)> {
        let raw = self.target.trim();
        if raw.is_empty() {
            bail!("CONNECT missing target host");
        }
        let (host, port) = parse_host_port(raw, 443);
        let rendered = render_host_port(&host, port);
        Ok((rendered.clone(), rendered))
    }

    fn http_target(&self) -> HttpTarget {
        let from_target = absolute_target(&self.target);
        let host_value = header_value(&self.headers, "host").map(str::to_string);
        let (host, port) = match (host_value, &from_target) {
            (Some(value), _) => parse_host_port(&value, 80),
            (None, Some(abs)) => (abs.host.clone(), abs.port),
            (None, None) => ("localhost".to_string(), 80),
        };
        let host_port = render_host_port(&host, port);
        let path = from_target.map(|abs| abs.path).unwrap_or_else(|| {
            if self.target.is_empty() {
                "/".to_string()
            } else {
                self.target.clone()
            }
        });

        HttpTarget {
            host_port: host_port.clone(),
            canonical_host: host_port,
            path,
        }
    }
}

struct HttpTarget {
    host_port: String,
    canonical_host: String,
    path: String,
}

struct AbsoluteTarget {
    host: String,
    port: u16,
    path: String,
}

struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
}

impl ParsedResponse {
    fn parse(head: &str) -> Result<Self> {
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| anyhow!("response missing status line"))?;
        let mut parts = status_line.split_whitespace();
        let _version = parts.next().unwrap_or("HTTP/1.1");
        let status = parts
            .next()
            .ok_or_else(|| anyhow!("response missing status code"))?
            .parse::<u16>()
            .context("invalid status code")?;
        let headers = parse_headers(lines)?;
        Ok(Self { status, headers })
    }

    fn body_kind(&self) -> BodyKind {
        if (100..200).contains(&self.status) || self.status == 204 || self.status == 304 {
            return BodyKind::None;
        }
        if let Some(te) = header_value(&self.headers, "transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                return BodyKind::Chunked;
            }
        }
        if let Some(cl) = header_value(&self.headers, "content-length") {
            if let Ok(len) = cl.parse::<usize>() {
                if len > 0 {
                    return BodyKind::ContentLength(len);
                }
                return BodyKind::None;
            }
        }
        BodyKind::UntilClose
    }
}

enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
    UntilClose,
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(headers)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn render_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_host_port(raw: &str, default_port: u16) -> (String, u16) {
    if raw.starts_with('[') {
        if let Some(end) = raw.find(']') {
            let host = raw[1..end].to_string();
            if let Some(rest) = raw[end + 1..].strip_prefix(':') {
                if let Ok(port) = rest.parse::<u16>() {
                    return (host, port);
                }
            }
            return (host, default_port);
        }
    }

    if let Some(pos) = raw.rfind(':') {
        let host_part = &raw[..pos];
        let port_part = &raw[pos + 1..];
        if host_part.contains(':') {
            return (raw.to_string(), default_port);
        }
        if let Ok(port) = port_part.parse::<u16>() {
            return (host_part.to_string(), port);
        }
        return (host_part.to_string(), default_port);
    }

    (raw.to_string(), default_port)
}

fn absolute_target(target: &str) -> Option<AbsoluteTarget> {
    if target.starts_with("http://") || target.starts_with("https://") {
        if let Ok(url) = Url::parse(target) {
            if let Some(host) = url.host_str() {
                let port = url.port_or_known_default().unwrap_or(80);
                let mut path = url.path().to_string();
                if let Some(q) = url.query() {
                    if !q.is_empty() {
                        path.push('?');
                        path.push_str(q);
                    }
                }
                return Some(AbsoluteTarget {
                    host: host.to_string(),
                    port,
                    path: if path.is_empty() {
                        "/".to_string()
                    } else {
                        path
                    },
                });
            }
        }
    }
    None
}

struct CaptureState {
    base: PathBuf,
    include: Vec<String>,
    exclude: Vec<String>,
    counter: AtomicU64,
    max_size: usize,
    started_at: DateTime<Utc>,
    listener: String,
    entries: Mutex<Vec<Entry>>,
    entry_limit: Option<usize>,
    entry_count: AtomicUsize,
    stop_notify: Notify,
}

impl CaptureState {
    fn new(
        base: PathBuf,
        include: Vec<String>,
        exclude: Vec<String>,
        max_size: usize,
        listener: String,
        entry_limit: Option<usize>,
    ) -> Self {
        Self {
            base,
            include,
            exclude,
            counter: AtomicU64::new(0),
            max_size,
            started_at: Utc::now(),
            listener,
            entries: Mutex::new(Vec::new()),
            entry_limit,
            entry_count: AtomicUsize::new(0),
            stop_notify: Notify::new(),
        }
    }

    fn is_allowed(&self, host: &str) -> bool {
        let include_pass = if self.include.is_empty() {
            true
        } else {
            self.include.iter().any(|needle| host.contains(needle))
        };
        let exclude_hit = self.exclude.iter().any(|needle| host.contains(needle));
        include_pass && !exclude_hit
    }

    fn next_id(&self) -> (String, DateTime<Utc>) {
        let ts = Utc::now();
        let suffix = self.counter.fetch_add(1, Ordering::SeqCst) % 1_000_000;
        let id = format!("{}{:06}", ts.timestamp_millis(), suffix);
        (id, ts)
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_entry(
        &self,
        id: &str,
        ts: DateTime<Utc>,
        method: &str,
        host: &str,
        path: &str,
        status: u16,
        request_bytes: &[u8],
        response_bytes: &[u8],
    ) -> Result<()> {
        let base = self.base.clone();
        let id_owned = id.to_string();
        let method_owned = method.to_string();
        let host_owned = host.to_string();
        let path_owned = path.to_string();
        let request = request_bytes.to_vec();
        let response = response_bytes.to_vec();
        let ts_string = ts.to_rfc3339();
        let ts_for_block = ts_string.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let requests = base.join(format!("requests/{id_owned}.req"));
            let responses = base.join(format!("responses/{id_owned}.res"));
            let canonical = base.join(format!("canonical/{id_owned}.jsonl"));
            std::fs::write(requests, &request)?;
            std::fs::write(responses, &response)?;
            let canonical_line = json!({
                "id": id_owned,
                "ts": ts_for_block,
                "req": {
                    "method": method_owned,
                    "host": host_owned,
                    "path": path_owned,
                },
                "res": {
                    "status": status,
                }
            });
            std::fs::write(canonical, canonical_line.to_string() + "\n")?;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(base.join("proofs/chain.ndjson"))?
                .write_all(
                    format!(
                        r#"{{"id":"{id_owned}","req_b3":"TODO","res_b3":"TODO","prev_b3":null}}"#
                    )
                    .as_bytes(),
                )?;
            Ok(())
        })
        .await??;
        let entry = Entry {
            id: id.to_string(),
            ts: ts_string,
            request_ref: format!("requests/{id}.req"),
            response_ref: format!("responses/{id}.res"),
            canonical_ref: format!("canonical/{id}.jsonl"),
            meta: EntryMeta {
                method: method.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                status,
                tags: vec!["capture".to_string()],
            },
        };
        self.entries.lock().await.push(entry);
        self.on_entry_recorded();
        Ok(())
    }

    async fn write_manifest(&self) -> Result<()> {
        let entries = self.entries.lock().await.clone();
        let manifest = Manifest {
            version: MANIFEST_VERSION.to_string(),
            created_at: self.started_at.to_rfc3339(),
            tool: ToolInfo {
                name: "flow".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capture: CaptureInfo {
                mode: "proxy".to_string(),
                listener: self.listener.clone(),
                filters: CaptureFilters {
                    include: self.include.clone(),
                    exclude: self.exclude.clone(),
                },
            },
            entries,
            integrity: IntegritySection {
                chain_b3: "TODO".to_string(),
            },
            signature: None,
        };
        let payload = serde_json::to_vec_pretty(&manifest)?;
        fs::write(self.base.join("manifest.json"), payload).await?;
        Ok(())
    }

    fn on_entry_recorded(&self) {
        let count = self.entry_count.fetch_add(1, Ordering::SeqCst) + 1;
        info!("recorded entry #{count}");
        if let Some(limit) = self.entry_limit {
            if count >= limit {
                info!("entry limit {limit} reached");
                self.stop_notify.notify_waiters();
            }
        }
    }
}

#[derive(Clone, Serialize)]
struct Entry {
    id: String,
    ts: String,
    request_ref: String,
    response_ref: String,
    canonical_ref: String,
    meta: EntryMeta,
}

#[derive(Clone, Serialize)]
struct EntryMeta {
    method: String,
    host: String,
    path: String,
    status: u16,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct Manifest {
    version: String,
    created_at: String,
    tool: ToolInfo,
    capture: CaptureInfo,
    entries: Vec<Entry>,
    integrity: IntegritySection,
    signature: Option<Value>,
}

#[derive(Serialize)]
struct ToolInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct CaptureInfo {
    mode: String,
    listener: String,
    filters: CaptureFilters,
}

#[derive(Serialize)]
struct CaptureFilters {
    include: Vec<String>,
    exclude: Vec<String>,
}

#[derive(Serialize)]
struct IntegritySection {
    chain_b3: String,
}
