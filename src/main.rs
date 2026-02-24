use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::Client as HttpClient;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(name = "netprofiler_lite")]
#[command(about = "Shareable object storage throughput benchmark")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compare multiple object-storage backends
    Compare(CompareArgs),
}

#[derive(Debug, Parser)]
struct CompareArgs {
    /// Comma-separated backend specs.
    /// S3: bucket:region
    /// R2: r2:bucket:account_id or r2:bucket (uses R2_ACCOUNT_ID)
    #[arg(long)]
    backends: String,

    /// Ensure bucket access and seed test objects if missing.
    /// Note: R2 buckets cannot be created via S3 API; only objects are seeded.
    #[arg(long, default_value_t = false)]
    ensure: bool,

    /// download, upload, or both
    #[arg(long, value_enum, default_value_t = DirectionArg::Download)]
    direction: DirectionArg,

    /// Parallel transfers per backend
    #[arg(long, default_value_t = 256)]
    concurrency: usize,

    /// Duration per backend (seconds)
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Object key prefix (keys are {prefix}.0, {prefix}.1, ...)
    #[arg(long, default_value = "data-8m")]
    prefix: String,

    /// Number of objects to cycle through
    #[arg(long, default_value_t = 100)]
    file_count: usize,

    /// Size of each object (MB). Used for seeding and upload payload sizing.
    #[arg(long, default_value_t = 8)]
    file_size_mb: usize,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputArg::Human)]
    output: OutputArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DirectionArg {
    Download,
    Upload,
    Both,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputArg {
    Human,
    Json,
    Csv,
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
    throughput_gbps: f64,
    grade: String,
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
    if gbps >= 10.0 {
        "A+"
    } else if gbps >= 5.0 {
        "A"
    } else if gbps >= 2.0 {
        "B"
    } else if gbps >= 1.0 {
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
        BackendType::R2 => r2_creds_from_env(),
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
    }
}

fn backend_host(b: &Backend) -> String {
    match b.spec.backend_type {
        BackendType::S3 => s3_host(&b.spec.bucket, &b.spec.region_or_account),
        BackendType::R2 => r2_host(&b.spec.region_or_account),
    }
}

fn canonical_uri_for_object(b: &Backend, key: &str) -> String {
    match b.spec.backend_type {
        BackendType::S3 => format!("/{}", pct_encode_path(key)),
        BackendType::R2 => format!("/{}/{}", pct_encode(&b.spec.bucket), pct_encode_path(key)),
    }
}

fn object_url(b: &Backend, key: &str, query: Option<&str>) -> String {
    let host = backend_host(b);
    let uri = canonical_uri_for_object(b, key);
    match query {
        Some(q) if !q.is_empty() => format!("https://{}{}?{}", host, uri, q),
        _ => format!("https://{}{}", host, uri),
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
    headers.insert(
        "x-amz-content-sha256".to_string(),
        payload_hash.to_string(),
    );
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
    let mut req = http.request(Method::HEAD, url).header("authorization", auth);
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
) -> Result<(u64, u64, u64, f64, f64)> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let idx = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let transfers = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let until = start + Duration::from_secs(cfg.duration_secs);
    let mut handles = Vec::with_capacity(cfg.concurrency * 2);

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
        let bytes = bytes.clone();
        let transfers = transfers.clone();
        let successes = successes.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let i = idx.fetch_add(1, Ordering::Relaxed) % urls.len();
            let url = &urls[i];
            transfers.fetch_add(1, Ordering::Relaxed);

            let resp = http.get(url).send().await;
            let Ok(resp) = resp else { return; };
            if !resp.status().is_success() {
                return;
            }

            let mut stream = resp.bytes_stream();
            let mut local: u64 = 0;
            while let Some(item) = stream.next().await {
                let Ok(chunk) = item else { return; };
                local += chunk.len() as u64;
            }
            bytes.fetch_add(local, Ordering::Relaxed);
            successes.fetch_add(1, Ordering::Relaxed);
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

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let total_bytes = bytes.load(Ordering::Relaxed);
    let total_transfers = transfers.load(Ordering::Relaxed);
    let total_success = successes.load(Ordering::Relaxed);
    let gbps = (total_bytes as f64 * 8.0) / elapsed / 1_000_000_000.0;
    Ok((total_bytes, total_transfers, total_success, gbps, elapsed))
}

async fn run_upload(http: &HttpClient, b: &Backend, cfg: &RunConfig) -> Result<(u64, u64, u64, f64, f64)> {
    let sem = Arc::new(Semaphore::new(cfg.concurrency));
    let idx = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let transfers = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));

    let payload = Bytes::from(vec![0u8; cfg.file_size_mb * 1024 * 1024]);
    let payload_hash = sha256_hex(&payload);

    let start = Instant::now();
    let until = start + Duration::from_secs(cfg.duration_secs);
    let mut handles = Vec::with_capacity(cfg.concurrency * 2);
    let bytes_per = (cfg.file_size_mb * 1024 * 1024) as u64;
    let prefix = cfg.prefix.clone();
    let b = b.clone();

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
            let auth = match sign_headers(&b, "PUT", &uri, "", &mut headers, &payload_hash, now)
            {
                Ok(a) => a,
                Err(_) => return,
            };

            transfers.fetch_add(1, Ordering::Relaxed);
            let mut req = http.request(Method::PUT, url).header("authorization", auth);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            let resp = req.body(payload).send().await;
            let Ok(resp) = resp else { return; };
            if resp.status().is_success() {
                bytes.fetch_add(bytes_per, Ordering::Relaxed);
                successes.fetch_add(1, Ordering::Relaxed);
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

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let total_bytes = bytes.load(Ordering::Relaxed);
    let total_transfers = transfers.load(Ordering::Relaxed);
    let total_success = successes.load(Ordering::Relaxed);
    let gbps = (total_bytes as f64 * 8.0) / elapsed / 1_000_000_000.0;
    Ok((total_bytes, total_transfers, total_success, gbps, elapsed))
}

fn print_human(results: &CompareResult) {
    println!(
        "Config: concurrency={} duration={}s prefix={} file_count={} file_size_mb={}\n",
        results.config.concurrency,
        results.config.duration_secs,
        results.config.prefix,
        results.config.file_count,
        results.config.file_size_mb
    );

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

    for r in &rows {
        println!(
            "{:<8} {:<26} {:<3} {:>8.3} Gbps  ok={}/{} bytes={}  ({}/{})",
            match r.direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
            },
            r.name,
            r.grade,
            r.throughput_gbps,
            r.successes,
            r.transfers,
            r.bytes,
            r.bucket,
            r.region_or_account,
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
    println!("timestamp,backend_type,name,bucket,region_or_account,direction,concurrency,duration_s,file_count,file_size_mb,bytes,transfers,successes,throughput_gbps,grade");
    for r in &results.results {
        println!(
            "{},{:?},{},{},{},{},{},{:.3},{},{},{},{},{},{:.6},{}",
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
            r.throughput_gbps,
            r.grade
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Compare(args) => {
            if args.concurrency == 0 {
                return Err(anyhow!("--concurrency must be >= 1"));
            }
            if args.duration == 0 {
                return Err(anyhow!("--duration must be >= 1"));
            }
            if args.file_count == 0 {
                return Err(anyhow!("--file-count must be >= 1"));
            }
            if args.file_count > 10_000 {
                return Err(anyhow!("--file-count too large (use <= 10000)"));
            }

            let specs = parse_backends(&args.backends)?;
            let cfg = RunConfig {
                concurrency: args.concurrency,
                duration_secs: args.duration,
                prefix: args.prefix,
                file_count: args.file_count,
                file_size_mb: args.file_size_mb,
            };

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

            if matches!(args.direction, DirectionArg::Upload | DirectionArg::Both) {
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
                if matches!(args.direction, DirectionArg::Download | DirectionArg::Both) {
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
                        let status = http
                            .get(u)
                            .send()
                            .await
                            .map(|r| r.status())
                            .unwrap_or(reqwest::StatusCode::from_u16(0).unwrap());
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
                    let (bytes, transfers, successes, gbps, elapsed) =
                        run_download(&http, Arc::new(urls), &cfg).await?;
                    all_results.push(BackendRunResult {
                        timestamp: started,
                        backend_type: b.spec.backend_type,
                        name: b.spec.name.clone(),
                        bucket: b.spec.bucket.clone(),
                        region_or_account: b.spec.region_or_account.clone(),
                        direction: Direction::Download,
                        concurrency: cfg.concurrency,
                        duration_secs: elapsed,
                        bytes,
                        transfers,
                        successes,
                        throughput_gbps: gbps,
                        grade: grade(gbps).to_string(),
                    });
                }

                if matches!(args.direction, DirectionArg::Upload | DirectionArg::Both) {
                    let started = Utc::now();
                    let (bytes, transfers, successes, gbps, elapsed) =
                        run_upload(&http, b, &cfg).await?;
                    all_results.push(BackendRunResult {
                        timestamp: started,
                        backend_type: b.spec.backend_type,
                        name: b.spec.name.clone(),
                        bucket: b.spec.bucket.clone(),
                        region_or_account: b.spec.region_or_account.clone(),
                        direction: Direction::Upload,
                        concurrency: cfg.concurrency,
                        duration_secs: elapsed,
                        bytes,
                        transfers,
                        successes,
                        throughput_gbps: gbps,
                        grade: grade(gbps).to_string(),
                    });
                }
            }

            let result = CompareResult {
                timestamp: Utc::now(),
                config: cfg,
                results: all_results,
            };

            match args.output {
                OutputArg::Human => print_human(&result),
                OutputArg::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputArg::Csv => print_csv(&result),
            }
        }
    }

    Ok(())
}
