use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::{ArgAction, Parser, ValueEnum};
use comfy_table::{presets::ASCII_MARKDOWN, Cell, Color, ContentArrangement, Table};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::Client as HttpClient;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(name = "netprofiler_lite")]
#[command(about = "Shareable object storage throughput benchmark")]
struct Cli {
    /// Path to config file (TOML). If omitted, reads ./netprofiler_lite.toml when present.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Ignore any config file
    #[arg(long, default_value_t = false)]
    no_config: bool,

    #[command(flatten)]
    compare: CompareArgs,
}

#[derive(Debug, Parser)]
struct CompareArgs {
    /// Comma-separated backend specs.
    /// S3: bucket:region
    /// R2: r2:bucket:account_id or r2:bucket (uses R2_ACCOUNT_ID)
    #[arg(long)]
    backends: Option<String>,

    /// Ensure bucket access and seed test objects if missing.
    /// Note: R2 buckets cannot be created via S3 API; only objects are seeded.
    #[arg(long)]
    ensure: bool,

    /// download, upload, or both
    #[arg(long, value_enum)]
    direction: Option<DirectionArg>,

    /// Parallel transfers per backend
    #[arg(long)]
    concurrency: Option<usize>,

    /// Duration per backend (seconds)
    #[arg(long)]
    duration: Option<u64>,

    /// Object key prefix (keys are {prefix}.0, {prefix}.1, ...)
    #[arg(long)]
    prefix: Option<String>,

    /// Number of objects to cycle through
    #[arg(long)]
    file_count: Option<usize>,

    /// Size of each object (MB). Used for seeding and upload payload sizing.
    #[arg(long)]
    file_size_mb: Option<usize>,

    /// Output format
    #[arg(long, value_enum)]
    output: Option<OutputArg>,

    /// Write a TOML report file (default: netprofiler_lite_report.toml)
    #[arg(long)]
    report_toml: Option<PathBuf>,

    /// Disable writing the TOML report file
    #[arg(long, default_value_t = false)]
    no_report_toml: bool,

    /// Disable ANSI colors in human output
    #[arg(long, default_value_t = false)]
    no_color: bool,

    /// Enable periodic progress during tests (human output only)
    #[arg(long, action = ArgAction::SetTrue)]
    progress: bool,

    /// Disable periodic progress during tests
    #[arg(long, action = ArgAction::SetTrue)]
    no_progress: bool,

    /// Progress update interval in milliseconds
    #[arg(long)]
    progress_interval_ms: Option<u64>,
}

impl Default for CompareArgs {
    fn default() -> Self {
        Self {
            backends: None,
            ensure: false,
            direction: None,
            concurrency: None,
            duration: None,
            prefix: None,
            file_count: None,
            file_size_mb: None,
            output: None,
            report_toml: None,
            no_report_toml: false,
            no_color: false,
            progress: false,
            no_progress: false,
            progress_interval_ms: None,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DirectionArg {
    Download,
    Upload,
    Both,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutputArg {
    Human,
    Json,
    Csv,
    Toml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Direction {
    Download,
    Upload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum BackendType {
    S3,
    R2,
    Http,
}

#[derive(Debug, Clone)]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[derive(Debug, Clone)]
struct BackendSpec {
    backend_type: BackendType,
    name: String,
    bucket: String,
    region_or_account: String,
}

#[derive(Debug, Clone)]
struct Backend {
    spec: BackendSpec,
    creds: Option<Credentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunConfig {
    concurrency: usize,
    duration_secs: u64,
    prefix: String,
    file_count: usize,
    file_size_mb: usize,
    progress: bool,
    progress_interval_ms: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct FileConfig {
    backends: Option<Vec<String>>,
    direction: Option<DirectionArg>,
    concurrency: Option<usize>,
    duration: Option<u64>,
    prefix: Option<String>,
    file_count: Option<usize>,
    file_size_mb: Option<usize>,
    output: Option<OutputArg>,
    report_toml: Option<PathBuf>,
    no_report_toml: Option<bool>,
    no_color: Option<bool>,
    progress: Option<bool>,
    progress_interval_ms: Option<u64>,
}

fn default_config_path() -> PathBuf {
    PathBuf::from("netprofiler_lite.toml")
}

fn load_file_config(path: &Path, required: bool) -> Result<Option<FileConfig>> {
    if !path.exists() {
        if required {
            return Err(anyhow!("config file not found: {}", path.display()));
        }
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    let cfg: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parse config file {}", path.display()))?;
    Ok(Some(cfg))
}

fn merge_compare(
    args: CompareArgs,
    file: Option<FileConfig>,
) -> Result<(String, CompareArgs, RunConfig)> {
    let file = file.unwrap_or_default();

    let backends = if let Some(b) = args.backends.clone() {
        b
    } else if let Some(list) = file.backends.clone() {
        list.into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        return Err(anyhow!(
            "no backends provided. Set 'backends = [..]' in netprofiler_lite.toml or pass --backends"
        ));
    };

    let direction = args
        .direction
        .or(file.direction)
        .unwrap_or(DirectionArg::Download);
    let concurrency = args.concurrency.or(file.concurrency).unwrap_or(256);
    let duration = args.duration.or(file.duration).unwrap_or(10);
    let prefix = args
        .prefix
        .clone()
        .or(file.prefix)
        .unwrap_or_else(|| "data-8m".to_string());
    let file_count = args.file_count.or(file.file_count).unwrap_or(100);
    let file_size_mb = args.file_size_mb.or(file.file_size_mb).unwrap_or(8);
    let output = args.output.or(file.output).unwrap_or(OutputArg::Human);
    let report_toml = if args.no_report_toml {
        None
    } else if let Some(p) = args.report_toml.clone() {
        Some(p)
    } else if let Some(p) = file.report_toml.clone() {
        Some(p)
    } else {
        Some(PathBuf::from("netprofiler_lite_report.toml"))
    };
    let no_color = args.no_color || file.no_color.unwrap_or(false);
    let interval_ms = args
        .progress_interval_ms
        .or(file.progress_interval_ms)
        .unwrap_or(1000);
    let progress = if args.no_progress {
        false
    } else if args.progress {
        true
    } else {
        file.progress.unwrap_or(true)
    };

    let args = CompareArgs {
        backends: Some(backends.clone()),
        ensure: args.ensure,
        direction: Some(direction),
        concurrency: Some(concurrency),
        duration: Some(duration),
        prefix: Some(prefix.clone()),
        file_count: Some(file_count),
        file_size_mb: Some(file_size_mb),
        output: Some(output),
        report_toml,
        no_report_toml: args.no_report_toml || file.no_report_toml.unwrap_or(false),
        no_color,
        progress: progress,
        no_progress: false,
        progress_interval_ms: Some(interval_ms),
    };

    let cfg = RunConfig {
        concurrency,
        duration_secs: duration,
        prefix,
        file_count,
        file_size_mb,
        progress: progress && matches!(output, OutputArg::Human),
        progress_interval_ms: interval_ms,
    };

    Ok((backends, args, cfg))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackendRunResult {
    timestamp: DateTime<Utc>,
    backend_type: BackendType,
    name: String,
    bucket: String,
    region_or_account: String,
    direction: Direction,
    concurrency: usize,
    duration_secs: f64,
    bytes: u64,
    transfers: u64,
    successes: u64,
    http_non_success: u64,
    network_errors: u64,
    http_4xx: u64,
    http_429: u64,
    http_5xx: u64,
    window_samples: u64,
    window_gbps_mean: f64,
    window_gbps_p50: f64,
    window_gbps_p90: f64,
    window_gbps_min: f64,
    window_gbps_max: f64,
    req_samples: u64,
    req_gbps_mean: f64,
    req_gbps_p50: f64,
    req_gbps_p90: f64,
    req_gbps_min: f64,
    req_gbps_max: f64,
    req_ms_mean: f64,
    req_ms_p50: f64,
    req_ms_p90: f64,
    req_ms_min: f64,
    req_ms_max: f64,
    throughput_gbps: f64,
    grade: String,
}

#[derive(Debug, Clone, Copy)]
struct RunOutcome {
    bytes: u64,
    transfers: u64,
    successes: u64,
    http_non_success: u64,
    network_errors: u64,
    http_4xx: u64,
    http_429: u64,
    http_5xx: u64,
    window_samples: u64,
    window_gbps_mean: f64,
    window_gbps_p50: f64,
    window_gbps_p90: f64,
    window_gbps_min: f64,
    window_gbps_max: f64,
    req_samples: u64,
    req_gbps_mean: f64,
    req_gbps_p50: f64,
    req_gbps_p90: f64,
    req_gbps_min: f64,
    req_gbps_max: f64,
    req_ms_mean: f64,
    req_ms_p50: f64,
    req_ms_p90: f64,
    req_ms_min: f64,
    req_ms_max: f64,
    throughput_gbps: f64,
    elapsed_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompareResult {
    timestamp: DateTime<Utc>,
    config: RunConfig,
    results: Vec<BackendRunResult>,
}

fn parse_backends(input: &str) -> Result<Vec<BackendSpec>> {
    let mut out = Vec::new();
    for raw in input.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if raw.starts_with("https://") || raw.starts_with("http://") {
            // Generic public HTTP origin; keys appended as /<key>
            let base = raw.trim_end_matches('/').to_string();
            let host = base
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("http");
            out.push(BackendSpec {
                backend_type: BackendType::Http,
                name: format!("http-{}", host),
                bucket: base,
                region_or_account: "".to_string(),
            });
            continue;
        }

        let parts: Vec<&str> = raw.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        if parts[0].eq_ignore_ascii_case("r2") {
            if !(2..=3).contains(&parts.len()) {
                return Err(anyhow!(
                    "invalid R2 backend spec '{}': use r2:bucket[:account_id]",
                    raw
                ));
            }
            let bucket = parts[1].to_string();
            let account_id = if parts.len() == 3 {
                parts[2].to_string()
            } else {
                std::env::var("R2_ACCOUNT_ID")
                    .context("R2_ACCOUNT_ID required when using r2:bucket")?
            };
            out.push(BackendSpec {
                backend_type: BackendType::R2,
                name: format!("r2-{}", bucket),
                bucket,
                region_or_account: account_id,
            });
            continue;
        }

        // S3: bucket:region
        if parts.len() != 2 {
            return Err(anyhow!(
                "invalid S3 backend spec '{}': use bucket:region",
                raw
            ));
        }
        let bucket = parts[0].to_string();
        let region = parts[1].to_string();
        out.push(BackendSpec {
            backend_type: BackendType::S3,
            name: format!("s3-{}-{}", bucket, region),
            bucket,
            region_or_account: region,
        });
    }
    if out.len() < 2 {
        return Err(anyhow!(
            "need at least 2 backends for compare; got {}",
            out.len()
        ));
    }
    Ok(out)
}

fn grade(gbps: f64) -> &'static str {
    // Match ~/sf_compute/metal-agent thresholds.
    if gbps >= 40.0 {
        "A+"
    } else if gbps >= 20.0 {
        "A"
    } else if gbps >= 10.0 {
        "B"
    } else if gbps >= 5.0 {
        "C"
    } else {
        "D"
    }
}

fn s3_creds_from_env() -> Option<Credentials> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
    Some(Credentials {
        access_key_id,
        secret_access_key,
        session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
    })
}

fn aws_profile() -> String {
    std::env::var("AWS_PROFILE")
        .or_else(|_| std::env::var("AWS_DEFAULT_PROFILE"))
        .unwrap_or_else(|_| "default".to_string())
}

fn aws_shared_credentials_file() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AWS_SHARED_CREDENTIALS_FILE") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".aws").join("credentials"))
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[s.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[s.len() - 1] == b'\'')
        {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn parse_ini(contents: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut section: Option<String> = None;

    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_string();
            section = Some(name);
            continue;
        }

        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim().to_ascii_lowercase();
        let val = strip_quotes(line[eq + 1..].trim()).to_string();
        let sec = section.clone().unwrap_or_else(|| "default".to_string());
        out.entry(sec).or_default().insert(key, val);
    }

    out
}

fn s3_creds_from_shared_file(profile: &str) -> Option<Credentials> {
    let path = aws_shared_credentials_file()?;
    let contents = std::fs::read_to_string(&path).ok()?;
    let ini = parse_ini(&contents);
    let sec = ini.get(profile)?;

    // Support both aws_* keys and uppercase variants if present.
    let access_key_id = sec
        .get("aws_access_key_id")
        .or_else(|| sec.get("access_key_id"))
        .cloned()?;
    let secret_access_key = sec
        .get("aws_secret_access_key")
        .or_else(|| sec.get("secret_access_key"))
        .cloned()?;
    let session_token = sec
        .get("aws_session_token")
        .or_else(|| sec.get("session_token"))
        .cloned();

    Some(Credentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

fn s3_creds() -> Option<Credentials> {
    s3_creds_from_env().or_else(|| s3_creds_from_shared_file(&aws_profile()))
}

fn r2_creds_from_env() -> Option<Credentials> {
    let access_key_id = std::env::var("R2_ACCESS_KEY_ID").ok()?;
    let secret_access_key = std::env::var("R2_SECRET_ACCESS_KEY").ok()?;
    Some(Credentials {
        access_key_id,
        secret_access_key,
        session_token: None,
    })
}

fn make_backend(spec: BackendSpec) -> Result<Backend> {
    let creds = match spec.backend_type {
        BackendType::S3 => s3_creds(),
        BackendType::R2 => {
            let c = r2_creds_from_env();
            if c.is_none() {
                return Err(anyhow!(
                    "R2 backend '{}' requires credentials (R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY). For no-credential partner runs, use the bucket public origin as an https://... backend (e.g. https://pub-<id>.r2.dev).",
                    spec.name
                ));
            }
            c
        }
        BackendType::Http => None,
    };
    Ok(Backend { spec, creds })
}

fn amz_dates(now: DateTime<Utc>) -> (String, String) {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    (amz_date, date_stamp)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn is_unreserved(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~')
}

fn pct_encode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn pct_encode_path(path: &str) -> String {
    path.split('/')
        .map(pct_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn canonical_query(params: &BTreeMap<String, String>) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (pct_encode(k), pct_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

fn s3_host(bucket: &str, region: &str) -> String {
    if region == "us-east-1" {
        format!("{}.s3.amazonaws.com", bucket)
    } else {
        format!("{}.s3.{}.amazonaws.com", bucket, region)
    }
}

fn r2_host(account_id: &str) -> String {
    format!("{}.r2.cloudflarestorage.com", account_id)
}

fn backend_region_for_signing(b: &Backend) -> &str {
    match b.spec.backend_type {
        BackendType::S3 => b.spec.region_or_account.as_str(),
        BackendType::R2 => "auto",
        BackendType::Http => "",
    }
}

fn backend_host(b: &Backend) -> String {
    match b.spec.backend_type {
        BackendType::S3 => s3_host(&b.spec.bucket, &b.spec.region_or_account),
        BackendType::R2 => r2_host(&b.spec.region_or_account),
        BackendType::Http => "".to_string(),
    }
}

fn canonical_uri_for_object(b: &Backend, key: &str) -> String {
    match b.spec.backend_type {
        BackendType::S3 => format!("/{}", pct_encode_path(key)),
        // S3-compatible endpoint uses path-style bucket addressing
        BackendType::R2 => format!("/{}/{}", pct_encode(&b.spec.bucket), pct_encode_path(key)),
        BackendType::Http => format!("/{}", pct_encode_path(key)),
    }
}

fn object_url(b: &Backend, key: &str, query: Option<&str>) -> String {
    if b.spec.backend_type == BackendType::Http {
        let base = b.spec.bucket.trim_end_matches('/');
        let path = pct_encode_path(key);
        match query {
            Some(q) if !q.is_empty() => format!("{}/{}?{}", base, path, q),
            _ => format!("{}/{}", base, path),
        }
    } else {
        let host = backend_host(b);
        let uri = canonical_uri_for_object(b, key);
        match query {
            Some(q) if !q.is_empty() => format!("https://{}{}?{}", host, uri, q),
            _ => format!("https://{}{}", host, uri),
        }
    }
}

fn presign_get_url(b: &Backend, key: &str, expires: u64, now: DateTime<Utc>) -> Result<String> {
    let Some(creds) = b.creds.as_ref() else {
        return Err(anyhow!(
            "missing credentials for {:?}; set env vars or rely on public objects",
            b.spec.backend_type
        ));
    };
    let service = "s3";
    let region = backend_region_for_signing(b);
    let host = backend_host(b);
    let uri = canonical_uri_for_object(b, key);
    let (amz_date, date_stamp) = amz_dates(now);

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let credential = format!("{}/{}", creds.access_key_id, credential_scope);

    let mut params = BTreeMap::new();
    params.insert(
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    );
    params.insert("X-Amz-Credential".to_string(), credential);
    params.insert("X-Amz-Date".to_string(), amz_date.clone());
    params.insert("X-Amz-Expires".to_string(), expires.to_string());
    params.insert("X-Amz-SignedHeaders".to_string(), "host".to_string());
    if let Some(ref token) = creds.session_token {
        params.insert("X-Amz-Security-Token".to_string(), token.clone());
    }
    let canonical_qs = canonical_query(&params);

    let canonical_headers = format!("host:{}\n", host);
    let signed_headers = "host";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let canonical_request = format!(
        "GET\n{}\n{}\n{}\n{}\n{}",
        uri, canonical_qs, canonical_headers, signed_headers, payload_hash
    );
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );
    let key_bytes = signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let sig = hmac_sha256(&key_bytes, string_to_sign.as_bytes());
    let signature = hex_lower(&sig);

    params.insert("X-Amz-Signature".to_string(), signature);
    let final_qs = canonical_query(&params);
    Ok(object_url(b, key, Some(&final_qs)))
}

fn sign_headers(
    b: &Backend,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &mut BTreeMap<String, String>,
    payload_hash: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    let Some(creds) = b.creds.as_ref() else {
        return Err(anyhow!(
            "missing credentials for {:?}; cannot sign request",
            b.spec.backend_type
        ));
    };
    let service = "s3";
    let region = backend_region_for_signing(b);
    let (amz_date, date_stamp) = amz_dates(now);
    headers.insert("host".to_string(), backend_host(b));
    headers.insert("x-amz-date".to_string(), amz_date.clone());
    headers.insert("x-amz-content-sha256".to_string(), payload_hash.to_string());
    if let Some(ref token) = creds.session_token {
        headers.insert("x-amz-security-token".to_string(), token.clone());
    }

    let mut canonical_headers = String::new();
    let mut signed_headers_list = Vec::new();
    for (k, v) in headers.iter() {
        let k_lc = k.to_ascii_lowercase();
        canonical_headers.push_str(&format!("{}:{}\n", k_lc, v.trim()));
        signed_headers_list.push(k_lc);
    }
    signed_headers_list.sort();
    signed_headers_list.dedup();
    let signed_headers = signed_headers_list.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
    );
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );
    let key_bytes = signing_key(&creds.secret_access_key, &date_stamp, region, service);
    let sig = hmac_sha256(&key_bytes, string_to_sign.as_bytes());
    let signature = hex_lower(&sig);
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.access_key_id, credential_scope, signed_headers, signature
    ))
}

async fn head_bucket(http: &HttpClient, b: &Backend) -> Result<reqwest::Response> {
    let host = backend_host(b);
    let url = format!("https://{}/", host);
    let now = Utc::now();
    let mut headers = BTreeMap::new();
    let empty_hash = sha256_hex(b"");
    let auth = sign_headers(b, "HEAD", "/", "", &mut headers, &empty_hash, now)?;

    let mut req = http.request(Method::HEAD, url);
    req = req.header("authorization", auth);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.send().await.context("head bucket")?;
    Ok(resp)
}

async fn create_bucket(http: &HttpClient, b: &Backend) -> Result<()> {
    if b.spec.backend_type != BackendType::S3 {
        return Err(anyhow!("bucket creation only supported for S3"));
    }
    if b.creds.is_none() {
        return Err(anyhow!(
            "missing AWS credentials; cannot create bucket {}",
            b.spec.bucket
        ));
    }
    let region = b.spec.region_or_account.as_str();
    let host = backend_host(b);
    let url = format!("https://{}/", host);
    let (body, content_type) = if region == "us-east-1" {
        (Bytes::new(), None)
    } else {
        let xml = format!(
            "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
            region
        );
        (Bytes::from(xml), Some("application/xml"))
    };
    let payload_hash = sha256_hex(&body);
    let now = Utc::now();
    let mut headers = BTreeMap::new();
    headers.insert("content-length".to_string(), body.len().to_string());
    if let Some(ct) = content_type {
        headers.insert("content-type".to_string(), ct.to_string());
    }
    let auth = sign_headers(b, "PUT", "/", "", &mut headers, &payload_hash, now)?;

    let mut req = http.request(Method::PUT, url).header("authorization", auth);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.body(body).send().await.context("create bucket")?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Err(anyhow!("create bucket failed ({}): {}", status, text))
    }
}

async fn head_object(http: &HttpClient, b: &Backend, key: &str) -> Result<reqwest::Response> {
    let host = backend_host(b);
    let uri = canonical_uri_for_object(b, key);
    let url = format!("https://{}{}", host, uri);
    let now = Utc::now();
    let mut headers = BTreeMap::new();
    let empty_hash = sha256_hex(b"");
    let auth = sign_headers(b, "HEAD", &uri, "", &mut headers, &empty_hash, now)?;
    let mut req = http
        .request(Method::HEAD, url)
        .header("authorization", auth);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    Ok(req.send().await.context("head object")?)
}

async fn put_object(http: &HttpClient, b: &Backend, key: &str, body: Bytes) -> Result<()> {
    let host = backend_host(b);
    let uri = canonical_uri_for_object(b, key);
    let url = format!("https://{}{}", host, uri);
    let payload_hash = sha256_hex(&body);
    let now = Utc::now();
    let mut headers = BTreeMap::new();
    headers.insert("content-length".to_string(), body.len().to_string());
    let auth = sign_headers(b, "PUT", &uri, "", &mut headers, &payload_hash, now)?;
    let mut req = http.request(Method::PUT, url).header("authorization", auth);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.body(body).send().await.context("put object")?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Err(anyhow!("put object failed ({}): {}", status, text))
    }
}

async fn ensure_bucket_and_objects(http: &HttpClient, b: &Backend, cfg: &RunConfig) -> Result<()> {
    if b.spec.backend_type == BackendType::Http {
        return Err(anyhow!("--ensure is not supported for http backends"));
    }
    if b.creds.is_none() {
        return Err(anyhow!(
            "--ensure requires credentials for {:?}. For S3 set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY; for R2 set R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY.\nIf you don't have credentials, omit --ensure and use public-read objects.",
            b.spec.backend_type
        ));
    }
    let resp = head_bucket(http, b).await?;
    if resp.status().is_success() {
        // ok
    } else if b.spec.backend_type == BackendType::S3 && resp.status().as_u16() == 404 {
        create_bucket(http, b).await?;
    } else if resp.status().as_u16() == 301 {
        let region_hdr = resp
            .headers()
            .get("x-amz-bucket-region")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown");
        return Err(anyhow!(
            "bucket region mismatch for {} (configured={} actual={})",
            b.spec.bucket,
            b.spec.region_or_account,
            region_hdr
        ));
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("head bucket failed ({}): {}", status, text));
    }

    let seed_count = cfg.file_count.min(100);
    let payload = Bytes::from(vec![0u8; cfg.file_size_mb * 1024 * 1024]);
    for i in 0..seed_count {
        let key = format!("{}.{}", cfg.prefix, i);
        let r = head_object(http, b, &key).await?;
        if r.status().is_success() {
            continue;
        }
        if r.status().as_u16() != 404 {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            return Err(anyhow!("head object failed ({}): {}", status, text));
        }
        put_object(http, b, &key, payload.clone()).await?;
    }

    Ok(())
}

async fn run_download(
    http: &HttpClient,
    urls: Arc<Vec<String>>,
    cfg: &RunConfig,
    label: &str,
) -> Result<RunOutcome> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let idx = Arc::new(AtomicUsize::new(0));
    // bytes_ok: only counts fully successful requests
    let bytes_ok = Arc::new(AtomicU64::new(0));
    // bytes_progress: counts bytes as they are consumed from the response stream
    // (used for window sampling and progress so we don't get "completion bursts")
    let bytes_progress = Arc::new(AtomicU64::new(0));
    let transfers = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));
    let http_non_success = Arc::new(AtomicU64::new(0));
    let network_errors = Arc::new(AtomicU64::new(0));
    let http_4xx = Arc::new(AtomicU64::new(0));
    let http_429 = Arc::new(AtomicU64::new(0));
    let http_5xx = Arc::new(AtomicU64::new(0));

    let window_gbps_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    let req_gbps_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let req_ms_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    let start = Instant::now();
    let until = start + Duration::from_secs(cfg.duration_secs);
    let mut handles = Vec::with_capacity(cfg.concurrency * 2);

    let stop = Arc::new(AtomicBool::new(false));

    // Window sampling is based on bytes completed so far.
    // Note: a small window can show bursty "max" due to buffering/completions.
    let sampler_task = {
        let stop = stop.clone();
        let bytes_progress = bytes_progress.clone();
        let window_gbps_samples = window_gbps_samples.clone();
        let until = until;
        tokio::spawn(async move {
            let mut last = bytes_progress.load(Ordering::Relaxed);
            let mut last_t = Instant::now();
            let tick = Duration::from_secs(1);
            while !stop.load(Ordering::Relaxed) && Instant::now() < until {
                tokio::time::sleep(tick).await;
                let now_b = bytes_progress.load(Ordering::Relaxed);
                let now_t = Instant::now();
                let dt = now_t.duration_since(last_t).as_secs_f64().max(0.000_001);
                let db = now_b.saturating_sub(last);
                let gbps = (db as f64 * 8.0) / dt / 1_000_000_000.0;
                if let Ok(mut v) = window_gbps_samples.lock() {
                    v.push(gbps);
                }
                last = now_b;
                last_t = now_t;
            }
        })
    };
    let progress_task = if cfg.progress {
        let stop = stop.clone();
        let bytes_progress = bytes_progress.clone();
        let transfers = transfers.clone();
        let successes = successes.clone();
        let label = label.to_string();
        let interval = Duration::from_millis(cfg.progress_interval_ms.max(200));
        let duration_secs = cfg.duration_secs;
        Some(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let elapsed = start.elapsed().as_secs_f64().max(0.001);
                let b = bytes_progress.load(Ordering::Relaxed);
                let t = transfers.load(Ordering::Relaxed);
                let ok = successes.load(Ordering::Relaxed);
                let gbps = (b as f64 * 8.0) / elapsed / 1_000_000_000.0;
                let left = duration_secs.saturating_sub(start.elapsed().as_secs());
                eprintln!(
                    "[{}] {:.0}s elapsed, {}s left | xfers={} ok={} bytes={} | {:.3} Gbps",
                    label, elapsed, left, t, ok, b, gbps
                );
                tokio::time::sleep(interval).await;
            }
        }))
    } else {
        None
    };

    while Instant::now() < until {
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tokio::task::yield_now().await;
                continue;
            }
        };

        let http = http.clone();
        let urls = urls.clone();
        let idx = idx.clone();
        let bytes_ok = bytes_ok.clone();
        let bytes_progress = bytes_progress.clone();
        let transfers = transfers.clone();
        let successes = successes.clone();
        let http_non_success = http_non_success.clone();
        let network_errors = network_errors.clone();
        let http_4xx = http_4xx.clone();
        let http_429 = http_429.clone();
        let http_5xx = http_5xx.clone();
        let req_gbps_samples = req_gbps_samples.clone();
        let req_ms_samples = req_ms_samples.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let i = idx.fetch_add(1, Ordering::Relaxed) % urls.len();
            let url = &urls[i];
            transfers.fetch_add(1, Ordering::Relaxed);
            let req_start = Instant::now();
            let resp = http.get(url).send().await;
            let Ok(resp) = resp else {
                network_errors.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if !resp.status().is_success() {
                http_non_success.fetch_add(1, Ordering::Relaxed);
                let code = resp.status().as_u16();
                if code == 429 {
                    http_429.fetch_add(1, Ordering::Relaxed);
                } else if (400..500).contains(&code) {
                    http_4xx.fetch_add(1, Ordering::Relaxed);
                } else if (500..600).contains(&code) {
                    http_5xx.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }

            let mut stream = resp.bytes_stream();
            let mut local: u64 = 0;
            while let Some(item) = stream.next().await {
                let Ok(chunk) = item else {
                    // roll back progress bytes for this request
                    bytes_progress.fetch_sub(local, Ordering::Relaxed);
                    return;
                };
                let n = chunk.len() as u64;
                local += n;
                bytes_progress.fetch_add(n, Ordering::Relaxed);
            }
            bytes_ok.fetch_add(local, Ordering::Relaxed);
            successes.fetch_add(1, Ordering::Relaxed);

            let secs = req_start.elapsed().as_secs_f64().max(0.000_001);
            let req_gbps = (local as f64 * 8.0) / secs / 1_000_000_000.0;
            let req_ms = secs * 1000.0;
            if let Ok(mut v) = req_gbps_samples.lock() {
                v.push(req_gbps);
            }
            if let Ok(mut v) = req_ms_samples.lock() {
                v.push(req_ms);
            }
        }));

        if handles.len() > cfg.concurrency * 4 {
            handles.retain(|h| !h.is_finished());
        }
    }

    let drain_start = Instant::now();
    let drain_timeout = Duration::from_secs(30);
    for h in handles {
        if drain_start.elapsed() > drain_timeout {
            h.abort();
        } else {
            let remaining = drain_timeout.saturating_sub(drain_start.elapsed());
            let _ = tokio::time::timeout(remaining, h).await;
        }
    }

    stop.store(true, Ordering::Relaxed);
    if let Some(t) = progress_task {
        let _ = t.await;
    }
    let _ = sampler_task.await;

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let total_bytes = bytes_ok.load(Ordering::Relaxed);
    let total_transfers = transfers.load(Ordering::Relaxed);
    let total_success = successes.load(Ordering::Relaxed);
    let total_http_non_success = http_non_success.load(Ordering::Relaxed);
    let total_network_errors = network_errors.load(Ordering::Relaxed);
    let total_http_4xx = http_4xx.load(Ordering::Relaxed);
    let total_http_429 = http_429.load(Ordering::Relaxed);
    let total_http_5xx = http_5xx.load(Ordering::Relaxed);
    let gbps = (total_bytes as f64 * 8.0) / elapsed / 1_000_000_000.0;

    let window_gbps = window_gbps_samples
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let (
        window_samples,
        window_gbps_mean,
        window_gbps_p50,
        window_gbps_p90,
        window_gbps_min,
        window_gbps_max,
    ) = stats(&window_gbps);

    let req_gbps = req_gbps_samples
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let req_ms = req_ms_samples.lock().map(|v| v.clone()).unwrap_or_default();
    let (req_samples, req_gbps_mean, req_gbps_p50, req_gbps_p90, req_gbps_min, req_gbps_max) =
        stats(&req_gbps);
    let (_, req_ms_mean, req_ms_p50, req_ms_p90, req_ms_min, req_ms_max) = stats(&req_ms);

    Ok(RunOutcome {
        bytes: total_bytes,
        transfers: total_transfers,
        successes: total_success,
        http_non_success: total_http_non_success,
        network_errors: total_network_errors,
        http_4xx: total_http_4xx,
        http_429: total_http_429,
        http_5xx: total_http_5xx,
        window_samples,
        window_gbps_mean,
        window_gbps_p50,
        window_gbps_p90,
        window_gbps_min,
        window_gbps_max,
        req_samples,
        req_gbps_mean,
        req_gbps_p50,
        req_gbps_p90,
        req_gbps_min,
        req_gbps_max,
        req_ms_mean,
        req_ms_p50,
        req_ms_p90,
        req_ms_min,
        req_ms_max,
        throughput_gbps: gbps,
        elapsed_secs: elapsed,
    })
}

async fn run_upload(http: &HttpClient, b: &Backend, cfg: &RunConfig) -> Result<RunOutcome> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let idx = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let transfers = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));
    let http_non_success = Arc::new(AtomicU64::new(0));
    let network_errors = Arc::new(AtomicU64::new(0));
    let http_4xx = Arc::new(AtomicU64::new(0));
    let http_429 = Arc::new(AtomicU64::new(0));
    let http_5xx = Arc::new(AtomicU64::new(0));

    let window_gbps_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    let req_gbps_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));
    let req_ms_samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    let payload = Bytes::from(vec![0u8; cfg.file_size_mb * 1024 * 1024]);
    let payload_hash = sha256_hex(&payload);

    let start = Instant::now();
    let until = start + Duration::from_secs(cfg.duration_secs);
    let mut handles = Vec::with_capacity(cfg.concurrency * 2);
    let bytes_per = (cfg.file_size_mb * 1024 * 1024) as u64;
    let prefix = cfg.prefix.clone();
    let b = b.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let sampler_task = {
        let stop = stop.clone();
        let bytes = bytes.clone();
        let window_gbps_samples = window_gbps_samples.clone();
        let until = until;
        tokio::spawn(async move {
            let mut last = bytes.load(Ordering::Relaxed);
            let mut last_t = Instant::now();
            let tick = Duration::from_secs(1);
            while !stop.load(Ordering::Relaxed) && Instant::now() < until {
                tokio::time::sleep(tick).await;
                let now_b = bytes.load(Ordering::Relaxed);
                let now_t = Instant::now();
                let dt = now_t.duration_since(last_t).as_secs_f64().max(0.000_001);
                let db = now_b.saturating_sub(last);
                let gbps = (db as f64 * 8.0) / dt / 1_000_000_000.0;
                if let Ok(mut v) = window_gbps_samples.lock() {
                    v.push(gbps);
                }
                last = now_b;
                last_t = now_t;
            }
        })
    };

    while Instant::now() < until {
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tokio::task::yield_now().await;
                continue;
            }
        };

        let http = http.clone();
        let b = b.clone();
        let idx = idx.clone();
        let bytes = bytes.clone();
        let transfers = transfers.clone();
        let successes = successes.clone();
        let http_non_success = http_non_success.clone();
        let network_errors = network_errors.clone();
        let http_4xx = http_4xx.clone();
        let http_429 = http_429.clone();
        let http_5xx = http_5xx.clone();
        let req_gbps_samples = req_gbps_samples.clone();
        let req_ms_samples = req_ms_samples.clone();
        let payload = payload.clone();
        let payload_hash = payload_hash.clone();
        let prefix = prefix.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let i = idx.fetch_add(1, Ordering::Relaxed);
            let key = format!("{}.{}-upload", prefix, i);
            let uri = canonical_uri_for_object(&b, &key);
            let host = backend_host(&b);
            let url = format!("https://{}{}", host, uri);

            let now = Utc::now();
            let mut headers = BTreeMap::new();
            headers.insert("content-length".to_string(), payload.len().to_string());
            let auth = match sign_headers(&b, "PUT", &uri, "", &mut headers, &payload_hash, now) {
                Ok(a) => a,
                Err(_) => return,
            };

            transfers.fetch_add(1, Ordering::Relaxed);
            let req_start = Instant::now();
            let mut req = http.request(Method::PUT, url).header("authorization", auth);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let resp = req.body(payload).send().await;
            let Ok(resp) = resp else {
                network_errors.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if resp.status().is_success() {
                bytes.fetch_add(bytes_per, Ordering::Relaxed);
                successes.fetch_add(1, Ordering::Relaxed);

                let secs = req_start.elapsed().as_secs_f64().max(0.000_001);
                let req_gbps = (bytes_per as f64 * 8.0) / secs / 1_000_000_000.0;
                let req_ms = secs * 1000.0;
                if let Ok(mut v) = req_gbps_samples.lock() {
                    v.push(req_gbps);
                }
                if let Ok(mut v) = req_ms_samples.lock() {
                    v.push(req_ms);
                }
                return;
            }

            http_non_success.fetch_add(1, Ordering::Relaxed);
            let code = resp.status().as_u16();
            if code == 429 {
                http_429.fetch_add(1, Ordering::Relaxed);
            } else if (400..500).contains(&code) {
                http_4xx.fetch_add(1, Ordering::Relaxed);
            } else if (500..600).contains(&code) {
                http_5xx.fetch_add(1, Ordering::Relaxed);
            }
        }));

        if handles.len() > cfg.concurrency * 4 {
            handles.retain(|h| !h.is_finished());
        }
    }

    let drain_start = Instant::now();
    let drain_timeout = Duration::from_secs(30);
    for h in handles {
        if drain_start.elapsed() > drain_timeout {
            h.abort();
        } else {
            let remaining = drain_timeout.saturating_sub(drain_start.elapsed());
            let _ = tokio::time::timeout(remaining, h).await;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = sampler_task.await;

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let total_bytes = bytes.load(Ordering::Relaxed);
    let total_transfers = transfers.load(Ordering::Relaxed);
    let total_success = successes.load(Ordering::Relaxed);
    let total_http_non_success = http_non_success.load(Ordering::Relaxed);
    let total_network_errors = network_errors.load(Ordering::Relaxed);
    let total_http_4xx = http_4xx.load(Ordering::Relaxed);
    let total_http_429 = http_429.load(Ordering::Relaxed);
    let total_http_5xx = http_5xx.load(Ordering::Relaxed);
    let gbps = (total_bytes as f64 * 8.0) / elapsed / 1_000_000_000.0;

    let window_gbps = window_gbps_samples
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let (
        window_samples,
        window_gbps_mean,
        window_gbps_p50,
        window_gbps_p90,
        window_gbps_min,
        window_gbps_max,
    ) = stats(&window_gbps);

    let req_gbps = req_gbps_samples
        .lock()
        .map(|v| v.clone())
        .unwrap_or_default();
    let req_ms = req_ms_samples.lock().map(|v| v.clone()).unwrap_or_default();
    let (req_samples, req_gbps_mean, req_gbps_p50, req_gbps_p90, req_gbps_min, req_gbps_max) =
        stats(&req_gbps);
    let (_, req_ms_mean, req_ms_p50, req_ms_p90, req_ms_min, req_ms_max) = stats(&req_ms);
    Ok(RunOutcome {
        bytes: total_bytes,
        transfers: total_transfers,
        successes: total_success,
        http_non_success: total_http_non_success,
        network_errors: total_network_errors,
        http_4xx: total_http_4xx,
        http_429: total_http_429,
        http_5xx: total_http_5xx,
        window_samples,
        window_gbps_mean,
        window_gbps_p50,
        window_gbps_p90,
        window_gbps_min,
        window_gbps_max,
        req_samples,
        req_gbps_mean,
        req_gbps_p50,
        req_gbps_p90,
        req_gbps_min,
        req_gbps_max,
        req_ms_mean,
        req_ms_p50,
        req_ms_p90,
        req_ms_min,
        req_ms_max,
        throughput_gbps: gbps,
        elapsed_secs: elapsed,
    })
}

fn ansi(color: &str, s: &str) -> String {
    format!("\x1b[{}m{}\x1b[0m", color, s)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    if max <= 3 {
        return s[..max].to_string();
    }
    format!("{}...", &s[..max - 3])
}

fn url_host(url: &str) -> String {
    let u = url.trim();
    let u = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("http://"))
        .unwrap_or(u);
    u.split('/').next().unwrap_or(u).to_string()
}

fn endpoint_id(backend_type: BackendType, bucket_or_base: &str) -> String {
    match backend_type {
        BackendType::S3 => {
            let b = bucket_or_base.split('-').last().unwrap_or(bucket_or_base);
            format!("s3:{}", b)
        }
        BackendType::R2 => {
            let b = bucket_or_base.split('-').last().unwrap_or(bucket_or_base);
            format!("r2:{}", b)
        }
        BackendType::Http => {
            let host = url_host(bucket_or_base);
            if host.ends_with(".r2.dev") {
                let stem = host.trim_end_matches(".r2.dev");
                format!("r2pub:{}", stem)
            } else {
                format!("http:{}", host)
            }
        }
    }
}

fn backend_label(backend_type: BackendType, bucket_or_base: &str) -> &'static str {
    match backend_type {
        BackendType::S3 => "S3",
        BackendType::R2 => "R2",
        BackendType::Http => {
            let host = url_host(bucket_or_base);
            if host.ends_with(".r2.dev") {
                "R2-public"
            } else {
                "HTTP"
            }
        }
    }
}

fn fmt_rate(successes: u64, transfers: u64) -> String {
    if transfers == 0 {
        return "0.0%".to_string();
    }
    format!("{:.1}%", (successes as f64) * 100.0 / (transfers as f64))
}

fn fmt_u64_compact(v: u64) -> String {
    const K: f64 = 1_000.0;
    const M: f64 = 1_000_000.0;
    const B: f64 = 1_000_000_000.0;
    let f = v as f64;
    if v >= 10_000_000_000 {
        format!("{:.1}B", f / B)
    } else if v >= 10_000_000 {
        format!("{:.1}M", f / M)
    } else if v >= 10_000 {
        format!("{:.1}K", f / K)
    } else {
        v.to_string()
    }
}

fn p90(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    let idx = (((n as f64) * 0.90).ceil() as usize).saturating_sub(1);
    values[idx.min(n - 1)]
}

fn p50(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len();
    values[(n - 1) / 2]
}

fn stats(values: &[f64]) -> (u64, f64, f64, f64, f64, f64) {
    // Returns: (count, mean, p50, p90, min, max)
    if values.is_empty() {
        return (0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }
    let mut sum = 0.0;
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for &v in values {
        sum += v;
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    let mean = sum / (values.len() as f64);
    let mut v50 = values.to_vec();
    let med = p50(&mut v50);
    let mut v90 = values.to_vec();
    let p90v = p90(&mut v90);
    (values.len() as u64, mean, med, p90v, min, max)
}

fn grade_color(grade: &str) -> &'static str {
    match grade {
        "A+" | "A" => "32", // green
        "B" => "33",        // yellow
        "C" | "D" => "31",  // red
        _ => "0",
    }
}

fn print_human(results: &CompareResult, no_color: bool, report_path: Option<&Path>) {
    println!(
        "Config: conc={} dur={}s prefix={} files={}x{}MB\n",
        results.config.concurrency,
        results.config.duration_secs,
        results.config.prefix,
        results.config.file_count,
        results.config.file_size_mb
    );

    println!("Legend:");
    println!("- thrpt: total goodput in Gbps (successful bytes only)");
    println!("- win(a/p90/max): 1s window goodput samples in Gbps (stream-progress bytes)");
    println!("- objGbps(p50/p90): per-success request goodput in Gbps for a single object");
    println!("- detail: reqms p50/p90 when healthy; otherwise error summary (e.g. 429=...,rl)\n");

    if let Some(p) = report_path {
        println!("Report: {}\n", p.display());
    }

    let mut rows = results.results.clone();
    fn dir_key(d: Direction) -> u8 {
        match d {
            Direction::Download => 0,
            Direction::Upload => 1,
        }
    }
    rows.sort_by(|a, b| {
        dir_key(a.direction)
            .cmp(&dir_key(b.direction))
            .then_with(|| {
                b.throughput_gbps
                    .partial_cmp(&a.throughput_gbps)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    fn errs_compact(r: &BackendRunResult) -> String {
        let other_http = r
            .http_non_success
            .saturating_sub(r.http_4xx)
            .saturating_sub(r.http_429)
            .saturating_sub(r.http_5xx);
        if r.network_errors == 0
            && r.http_4xx == 0
            && r.http_429 == 0
            && r.http_5xx == 0
            && other_http == 0
        {
            return "-".to_string();
        }

        let mut parts: Vec<String> = Vec::new();
        if r.network_errors > 0 {
            parts.push(format!("net={}", fmt_u64_compact(r.network_errors)));
        }
        if r.http_4xx > 0 {
            parts.push(format!("4xx={}", fmt_u64_compact(r.http_4xx)));
        }
        if r.http_429 > 0 {
            parts.push(format!("429={}", fmt_u64_compact(r.http_429)));
        }
        if r.http_5xx > 0 {
            parts.push(format!("5xx={}", fmt_u64_compact(r.http_5xx)));
        }
        if other_http > 0 {
            parts.push(format!("other={}", fmt_u64_compact(other_http)));
        }
        if r.http_429 > 0 {
            parts.push("rl".to_string());
        }
        truncate(&parts.join(","), 28)
    }

    let use_color = !no_color && std::io::stdout().is_terminal();

    let mut table = Table::new();
    table
        .load_preset(ASCII_MARKDOWN)
        // Avoid auto-wrapping into multi-line cells; truncate instead.
        .set_content_arrangement(ContentArrangement::Disabled)
        .set_header([
            "dir",
            "type",
            "endpoint",
            "region",
            "thrpt",
            "gr",
            "ok%",
            "win(a/p90/max)",
            "objGbps(p50/p90)",
            "detail",
        ]);

    for r in &rows {
        // Use comfy-table styling (not raw ANSI) for consistent alignment.
        let mut grade_cell = Cell::new(r.grade.clone());
        if use_color {
            grade_cell = match r.grade.as_str() {
                "A+" | "A" => grade_cell.fg(Color::Green),
                "B" => grade_cell.fg(Color::Yellow),
                "C" | "D" => grade_cell.fg(Color::Red),
                _ => grade_cell,
            };
        }

        let id = truncate(&endpoint_id(r.backend_type, &r.bucket), 18);
        let typ = backend_label(r.backend_type, &r.bucket);
        let region = if r.region_or_account.is_empty() {
            "-".to_string()
        } else {
            r.region_or_account.clone()
        };
        let rate = fmt_rate(r.successes, r.transfers);
        let mut ok_cell = Cell::new(rate.clone());
        if use_color {
            let pct = (r.successes as f64) * 100.0 / (r.transfers.max(1) as f64);
            ok_cell = if pct >= 99.0 {
                ok_cell.fg(Color::Green)
            } else if pct >= 90.0 {
                ok_cell.fg(Color::Yellow)
            } else {
                ok_cell.fg(Color::Red)
            };
        }
        let _gb = (r.bytes as f64) / 1_000_000_000.0;

        let errs = errs_compact(r);

        let win = if r.window_samples == 0 {
            "-".to_string()
        } else {
            format!(
                "{:.1}/{:.1}/{:.1}",
                r.window_gbps_mean, r.window_gbps_p90, r.window_gbps_max
            )
        };

        let obj_gbps = if r.req_samples == 0 {
            "-".to_string()
        } else {
            format!("{:.2}/{:.2}", r.req_gbps_p50, r.req_gbps_p90)
        };

        let req_ms = if r.req_samples == 0 {
            "-".to_string()
        } else {
            format!("{:.0}/{:.0}", r.req_ms_p50, r.req_ms_p90)
        };

        let detail = if errs == "-" {
            if req_ms == "-" {
                "-".to_string()
            } else {
                format!("reqms={}", req_ms)
            }
        } else {
            errs.clone()
        };

        let mut type_cell = Cell::new(typ.to_string());
        if use_color {
            type_cell = match typ {
                "S3" => type_cell.fg(Color::Cyan),
                "R2" => type_cell.fg(Color::Cyan),
                "R2-public" => type_cell.fg(Color::Magenta),
                "HTTP" => type_cell.fg(Color::Blue),
                _ => type_cell,
            };
        }

        let mut thrpt_cell = Cell::new(format!("{:.2}", r.throughput_gbps));
        if use_color {
            thrpt_cell = if r.throughput_gbps >= 10.0 {
                thrpt_cell.fg(Color::Green)
            } else if r.throughput_gbps >= 5.0 {
                thrpt_cell.fg(Color::Yellow)
            } else {
                thrpt_cell.fg(Color::Red)
            };
        }

        table.add_row(vec![
            Cell::new(match r.direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
            }),
            type_cell,
            Cell::new(id),
            Cell::new(region),
            thrpt_cell,
            grade_cell,
            ok_cell,
            Cell::new(win),
            Cell::new(obj_gbps),
            Cell::new(detail),
        ]);
    }

    println!("{}", table);

    for dir in [Direction::Download, Direction::Upload] {
        let mut tps: Vec<f64> = results
            .results
            .iter()
            .filter(|r| r.direction == dir)
            .map(|r| r.throughput_gbps)
            .collect();
        if tps.is_empty() {
            continue;
        }

        let n = tps.len() as f64;
        let sum: f64 = tps.iter().sum();
        let avg = sum / n;
        let mut sorted = tps.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let min = *sorted.first().unwrap_or(&0.0);
        let max = *sorted.last().unwrap_or(&0.0);
        let p90v = p90(&mut tps);

        let (ok_sum, tot_sum) = results
            .results
            .iter()
            .filter(|r| r.direction == dir)
            .fold((0u64, 0u64), |(ok, tot), r| {
                (ok + r.successes, tot + r.transfers)
            });
        let rate = fmt_rate(ok_sum, tot_sum);
        let g = grade(avg);
        let g = if !no_color && std::io::stdout().is_terminal() {
            ansi(grade_color(g), g)
        } else {
            g.to_string()
        };

        println!(
            "\n{:>8} stats: avg={:.2}Gbps {}  p90={:.2}  min={:.2}  max={:.2}  ok={}/{} ({})",
            match dir {
                Direction::Download => "download",
                Direction::Upload => "upload",
            },
            avg,
            g,
            p90v,
            min,
            max,
            fmt_u64_compact(ok_sum),
            fmt_u64_compact(tot_sum),
            rate
        );
    }

    for dir in [Direction::Download, Direction::Upload] {
        let best = results
            .results
            .iter()
            .filter(|r| r.direction == dir)
            .max_by(|a, b| {
                a.throughput_gbps
                    .partial_cmp(&b.throughput_gbps)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        if let Some(b) = best {
            println!(
                "\nRecommendation ({}): {} ({}/{}) @ {:.3} Gbps",
                match dir {
                    Direction::Download => "download",
                    Direction::Upload => "upload",
                },
                b.name,
                b.bucket,
                b.region_or_account,
                b.throughput_gbps
            );
        }
    }
}

fn print_csv(results: &CompareResult) {
    println!("timestamp,backend_type,name,bucket,region_or_account,direction,concurrency,duration_s,file_count,file_size_mb,bytes,transfers,successes,network_errors,http_non_success,http_4xx,http_429,http_5xx,req_samples,req_gbps_mean,req_gbps_p50,req_gbps_p90,req_gbps_min,req_gbps_max,req_ms_mean,req_ms_p50,req_ms_p90,req_ms_min,req_ms_max,throughput_gbps,grade");
    for r in &results.results {
        println!(
            "{},{:?},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.3},{:.3},{:.3},{:.3},{:.3},{:.6},{}",
            r.timestamp.to_rfc3339(),
            r.backend_type,
            r.name,
            r.bucket,
            r.region_or_account,
            match r.direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
            },
            r.concurrency,
            r.duration_secs,
            results.config.file_count,
            results.config.file_size_mb,
            r.bytes,
            r.transfers,
            r.successes,
            r.network_errors,
            r.http_non_success,
            r.http_4xx,
            r.http_429,
            r.http_5xx,
            r.req_samples,
            r.req_gbps_mean,
            r.req_gbps_p50,
            r.req_gbps_p90,
            r.req_gbps_min,
            r.req_gbps_max,
            r.req_ms_mean,
            r.req_ms_p50,
            r.req_ms_p90,
            r.req_ms_min,
            r.req_ms_max,
            r.throughput_gbps,
            r.grade
        );
    }
}

fn print_toml(results: &CompareResult) -> Result<()> {
    println!("{}", toml::to_string_pretty(results)?);
    Ok(())
}

fn write_toml_report(results: &CompareResult, path: &Path) -> Result<()> {
    let s = toml::to_string_pretty(results).context("serialize toml report")?;
    std::fs::write(path, s).with_context(|| format!("write report {}", path.display()))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let file_cfg = if cli.no_config {
        None
    } else {
        let path = cli.config.clone().unwrap_or_else(default_config_path);
        let required = cli.config.is_some();
        load_file_config(&path, required)?
    };

    let (backends_str, args, cfg) = merge_compare(cli.compare, file_cfg)?;
    if cfg.concurrency == 0 {
        return Err(anyhow!("concurrency must be >= 1"));
    }
    if cfg.duration_secs == 0 {
        return Err(anyhow!("duration must be >= 1"));
    }
    if cfg.file_count == 0 {
        return Err(anyhow!("file_count must be >= 1"));
    }
    if cfg.file_count > 10_000 {
        return Err(anyhow!("file_count too large (use <= 10000)"));
    }

    let specs = parse_backends(&backends_str)?;
    let direction = args.direction.unwrap_or(DirectionArg::Download);
    let output = args.output.unwrap_or(OutputArg::Human);

    let http = HttpClient::builder()
        .http1_only()
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4096)
        .tcp_nodelay(true)
        .build()
        .context("build http client")?;

    let mut backends = Vec::with_capacity(specs.len());
    for s in specs {
        backends.push(make_backend(s)?);
    }

    if matches!(direction, DirectionArg::Upload | DirectionArg::Both) {
        for b in &backends {
            if b.creds.is_none() {
                return Err(anyhow!(
                    "upload requires credentials for {}. Set AWS_* for S3 and/or R2_* for R2, or run with --direction download",
                    b.spec.name
                ));
            }
        }
    }

    if args.ensure {
        for b in &backends {
            ensure_bucket_and_objects(&http, b, &cfg).await?;
        }
    }

    let mut all_results = Vec::new();
    for b in &backends {
        if matches!(direction, DirectionArg::Download | DirectionArg::Both) {
            let mut urls = Vec::with_capacity(cfg.file_count);
            if b.creds.is_some() {
                let expires = cfg.duration_secs + 900;
                let now = Utc::now();
                for i in 0..cfg.file_count {
                    let key = format!("{}.{}", cfg.prefix, i);
                    urls.push(presign_get_url(b, &key, expires, now)?);
                }
            } else {
                eprintln!(
                    "[{}] No credentials found; using anonymous public URLs. Objects must be public-read.",
                    b.spec.name
                );
                for i in 0..cfg.file_count {
                    let key = format!("{}.{}", cfg.prefix, i);
                    urls.push(object_url(b, &key, None));
                }
            }

            if let Some(u) = urls.first() {
                let resp = http.get(u).send().await;
                let resp = resp.with_context(|| {
                    format!(
                        "preflight GET request failed for {} (url={})",
                        b.spec.name, u
                    )
                })?;
                let status = resp.status();
                if !status.is_success() {
                    return Err(anyhow!(
                        "preflight GET failed for {} (HTTP {}): expected objects like {}.0",
                        b.spec.name,
                        status,
                        cfg.prefix
                    ));
                }
            }

            let started = Utc::now();
            let o = run_download(&http, Arc::new(urls), &cfg, &format!("{}", b.spec.name)).await?;
            all_results.push(BackendRunResult {
                timestamp: started,
                backend_type: b.spec.backend_type,
                name: b.spec.name.clone(),
                bucket: b.spec.bucket.clone(),
                region_or_account: b.spec.region_or_account.clone(),
                direction: Direction::Download,
                concurrency: cfg.concurrency,
                duration_secs: o.elapsed_secs,
                bytes: o.bytes,
                transfers: o.transfers,
                successes: o.successes,
                http_non_success: o.http_non_success,
                network_errors: o.network_errors,
                http_4xx: o.http_4xx,
                http_429: o.http_429,
                http_5xx: o.http_5xx,
                window_samples: o.window_samples,
                window_gbps_mean: o.window_gbps_mean,
                window_gbps_p50: o.window_gbps_p50,
                window_gbps_p90: o.window_gbps_p90,
                window_gbps_min: o.window_gbps_min,
                window_gbps_max: o.window_gbps_max,
                req_samples: o.req_samples,
                req_gbps_mean: o.req_gbps_mean,
                req_gbps_p50: o.req_gbps_p50,
                req_gbps_p90: o.req_gbps_p90,
                req_gbps_min: o.req_gbps_min,
                req_gbps_max: o.req_gbps_max,
                req_ms_mean: o.req_ms_mean,
                req_ms_p50: o.req_ms_p50,
                req_ms_p90: o.req_ms_p90,
                req_ms_min: o.req_ms_min,
                req_ms_max: o.req_ms_max,
                throughput_gbps: o.throughput_gbps,
                grade: grade(o.throughput_gbps).to_string(),
            });
        }

        if matches!(direction, DirectionArg::Upload | DirectionArg::Both) {
            let started = Utc::now();
            let o = run_upload(&http, b, &cfg).await?;
            all_results.push(BackendRunResult {
                timestamp: started,
                backend_type: b.spec.backend_type,
                name: b.spec.name.clone(),
                bucket: b.spec.bucket.clone(),
                region_or_account: b.spec.region_or_account.clone(),
                direction: Direction::Upload,
                concurrency: cfg.concurrency,
                duration_secs: o.elapsed_secs,
                bytes: o.bytes,
                transfers: o.transfers,
                successes: o.successes,
                http_non_success: o.http_non_success,
                network_errors: o.network_errors,
                http_4xx: o.http_4xx,
                http_429: o.http_429,
                http_5xx: o.http_5xx,
                window_samples: o.window_samples,
                window_gbps_mean: o.window_gbps_mean,
                window_gbps_p50: o.window_gbps_p50,
                window_gbps_p90: o.window_gbps_p90,
                window_gbps_min: o.window_gbps_min,
                window_gbps_max: o.window_gbps_max,
                req_samples: o.req_samples,
                req_gbps_mean: o.req_gbps_mean,
                req_gbps_p50: o.req_gbps_p50,
                req_gbps_p90: o.req_gbps_p90,
                req_gbps_min: o.req_gbps_min,
                req_gbps_max: o.req_gbps_max,
                req_ms_mean: o.req_ms_mean,
                req_ms_p50: o.req_ms_p50,
                req_ms_p90: o.req_ms_p90,
                req_ms_min: o.req_ms_min,
                req_ms_max: o.req_ms_max,
                throughput_gbps: o.throughput_gbps,
                grade: grade(o.throughput_gbps).to_string(),
            });
        }
    }

    let result = CompareResult {
        timestamp: Utc::now(),
        config: cfg,
        results: all_results,
    };

    // Write report file (TOML) unless disabled
    if let Some(ref p) = args.report_toml {
        if !args.no_report_toml {
            write_toml_report(&result, p)?;
        }
    }

    match output {
        OutputArg::Human => {
            let report_path = args.report_toml.as_deref().filter(|_| !args.no_report_toml);
            print_human(&result, args.no_color, report_path);
        }
        OutputArg::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputArg::Csv => print_csv(&result),
        OutputArg::Toml => {
            print_toml(&result)?;
        }
    }

    Ok(())
}
