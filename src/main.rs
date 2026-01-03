use clap::{Parser, Subcommand};
use reqwest::{Client, header::HeaderMap};
use anyhow::{Result, anyhow};
use std::{collections::BTreeMap, time::Duration, path::{Path, PathBuf}};
use serde::Serialize;
use sha2::{Digest, Sha256};
use chrono::{Utc, Datelike};
use regex::Regex;
use url::Url;

use tracing::{info};
use tracing_subscriber::{EnvFilter, fmt};

const ASCII_ART: &str = r#"
   (DARKCAT ascii...)
"#;

// ---- CLI ----

#[derive(Parser)]
#[command(name = "DARKCAT")]
#[command(about = "Dark web recon claw - CLI tool for darkweb digital forensics", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a .onion or clearnet URL (passive recon only)
    Scan {
        /// URL to scan (with or without http/https)
        #[arg(short, long)]
        url: String,

        /// Evidence base directory (default: evidence)
        #[arg(long, default_value = "evidence")]
        evidence_dir: String,

        /// Save response body to file (default: true)
        #[arg(long, default_value_t = true)]
        save_body: bool,

        /// Save raw headers to file (default: true)
        #[arg(long, default_value_t = true)]
        save_headers: bool,

        /// Add output to daily CSV audit trail (default: true)
        #[arg(long, default_value_t = true)]
        csv: bool,

        /// Optional: Case ID for chain of custody (e.g. EXAM-2026-001)
        #[arg(long)]
        case_id: Option<String>,

        /// Optional: Examiner name/handle for chain of custody
        #[arg(long)]
        examiner: Option<String>,

        /// Optional: Free-text note for chain of custody
        #[arg(long)]
        note: Option<String>,
    },

    /// Check Tor connectivity
    Status,
}

// ---- Evidence structs ----

#[derive(Debug, Serialize)]
struct EvidenceRecord {
    tool: String,
    mode: String, // "passive-recon-only"
    fetched_at_utc: String, // ISO8601
    url: String,
    final_url: String,
    scheme: String,
    host: Option<String>,
    status: u16,
    http_version: String,

    // response
    headers: BTreeMap<String, String>,
    server_banner: Option<String>,
    title: Option<String>,
    content_length_bytes: usize,

    // integrity
    sha256_hex: String,

    // files
    body_saved: bool,
    body_file: Option<String>,
    sha256_file: Option<String>,
    headers_saved: bool,
    headers_file: Option<String>,
    json_file: String,

    // request metadata
    request: RequestParameters,

    // TLS (best effort)
    tls: Option<TlsSummary>,

    // chain of custody
    chain_of_custody: ChainOfCustody,
}

#[derive(Debug, Serialize)]
struct RequestParameters {
    user_agent: String,
    timeout_seconds: u64,
    proxy: String,
    tor_socks_ready_check: String,
}

#[derive(Debug, Serialize)]
struct TlsSummary {
    https: bool,
    details: String,
}

#[derive(Debug, Serialize)]
struct ChainOfCustody {
    case_id: Option<String>,
    examiner: Option<String>,
    note: Option<String>,
    collected_at_utc: String,
    integrity_method: String, // e.g. SHA-256(body)
    handling: String,         // narrative
}

// ---- Main ----

#[tokio::main]
async fn main() -> Result<()> {
    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    println!("{}", ASCII_ART);
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            url,
            evidence_dir,
            save_body,
            save_headers,
            csv,
            case_id,
            examiner,
            note,
        } => {
            let url = normalize_url(&url);
            info!("Scanning: {}", url);

            scan_and_write_evidence(
                &url,
                &evidence_dir,
                save_body,
                save_headers,
                csv,
                ChainOfCustodyInput { case_id, examiner, note },
            )
                .await?;
        }
        Commands::Status => {
            println!("Checking Tor connection...");
            check_tor_status().await?;
        }
    }

    Ok(())
}

// ---- Helpers ----

fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

fn sanitize_filename(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "unknown".to_string() } else { out }
}

fn extract_title(html: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title[^>]*>\s*(.*?)\s*</title>").ok()?;
    let caps = re.captures(html)?;
    let title = caps.get(1)?.as_str().trim();
    if title.is_empty() { None } else { Some(title.to_string()) }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn today_dir(base: &str) -> PathBuf {
    let now = Utc::now();
    let date = format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day());
    Path::new(base).join(date)
}

fn headers_to_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_string();
        let val = v.to_str().unwrap_or("<non-utf8>").to_string();
        map.insert(key, val);
    }
    map
}

fn headers_to_raw_text(headers: &BTreeMap<String, String>) -> String {
    // "raw-ish" (det er ikke bytes-identisk), men bevarer header-linjer og værdier læsbart
    let mut out = String::new();
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out
}

fn http_version_to_string(v: reqwest::Version) -> String {
    match v {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2",
        reqwest::Version::HTTP_3 => "HTTP/3",
        _ => "UNKNOWN",
    }
        .to_string()
}

// ---- Tor/HTTP ----

const TOR_PROXY: &str = "socks5h://127.0.0.1:9050";
const DEFAULT_UA: &str = "DARKCAT/0.1 (passive-recon-only; forensics-poc)";
const TIMEOUT_SECS: u64 = 30;

fn create_tor_client() -> Result<Client> {
    let client = Client::builder()
        .proxy(reqwest::Proxy::all(TOR_PROXY)?)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .user_agent(DEFAULT_UA)
        .build()?;
    Ok(client)
}

// ---- Chain of custody input ----

struct ChainOfCustodyInput {
    case_id: Option<String>,
    examiner: Option<String>,
    note: Option<String>,
}

// ---- Core scan + evidence writing ----

async fn scan_and_write_evidence(
    url: &str,
    evidence_base: &str,
    save_body: bool,
    save_headers: bool,
    write_csv: bool,
    coc_in: ChainOfCustodyInput,
) -> Result<()> {
    let client = create_tor_client()?;

    let fetched_at = Utc::now().to_rfc3339();
    let parsed = Url::parse(url).map_err(|e| anyhow!("Invalid URL '{}': {}", url, e))?;
    let host = parsed.host_str().map(|s| s.to_string());
    let scheme = parsed.scheme().to_string();

    // Passive recon only: single GET
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let http_version = http_version_to_string(resp.version());

    let headers_map = headers_to_map(resp.headers());
    let server_banner = headers_map.get("server").cloned();

    let body_bytes = resp.bytes().await?.to_vec();
    let content_length = body_bytes.len();
    let sha_hex = sha256_hex(&body_bytes);

    let title = extract_title(std::str::from_utf8(&body_bytes).unwrap_or(""));

    // TLS summary
    let tls = if scheme == "https" {
        Some(TlsSummary {
            https: true,
            details: "HTTPS used. Detailed TLS handshake/certificate fields are not captured in this PoC (reqwest backend dependent).".to_string(),
        })
    } else {
        None
    };

    // evidence/YYYY-MM-DD/
    let day_dir = today_dir(evidence_base);
    tokio::fs::create_dir_all(&day_dir).await?;

    let base_name = sanitize_filename(host.as_deref().unwrap_or("unknown"));

    // Files we may write
    let mut body_file_rel: Option<String> = None;
    let mut sha_file_rel: Option<String> = None;
    let mut headers_file_rel: Option<String> = None;

    if save_body {
        let body_filename = format!("{}.html", base_name);
        let sha_filename = format!("{}.html.sha256", base_name);

        tokio::fs::write(day_dir.join(&body_filename), &body_bytes).await?;
        tokio::fs::write(day_dir.join(&sha_filename), format!("{}\n", sha_hex)).await?;

        body_file_rel = Some(body_filename);
        sha_file_rel = Some(sha_filename);
    }

    if save_headers {
        let headers_filename = format!("{}.headers.txt", base_name);
        let raw_headers = headers_to_raw_text(&headers_map);
        tokio::fs::write(day_dir.join(&headers_filename), raw_headers).await?;
        headers_file_rel = Some(headers_filename);
    }

    // Chain of custody
    let chain = ChainOfCustody {
        case_id: coc_in.case_id,
        examiner: coc_in.examiner,
        note: coc_in.note,
        collected_at_utc: fetched_at.clone(),
        integrity_method: "SHA-256(response body)".to_string(),
        handling: "Passive recon only. Single HTTP GET over Tor SOCKS5 proxy. No credential use, no crawling, no exploitation. Evidence stored read-only in date-stamped folder with body hash.".to_string(),
    };

    // Request parameters
    let request = RequestParameters {
        user_agent: DEFAULT_UA.to_string(),
        timeout_seconds: TIMEOUT_SECS,
        proxy: TOR_PROXY.to_string(),
        tor_socks_ready_check: "curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip".to_string(),
    };

    // JSON evidence
    let json_filename = format!("{}.json", base_name);
    let json_path = day_dir.join(&json_filename);

    let record = EvidenceRecord {
        tool: "DARKCAT".to_string(),
        mode: "passive-recon-only".to_string(),
        fetched_at_utc: fetched_at,
        url: url.to_string(),
        final_url,
        scheme,
        host,
        status,
        http_version,
        headers: headers_map,
        server_banner,
        title,
        content_length_bytes: content_length,
        sha256_hex: sha_hex.clone(),
        body_saved: save_body,
        body_file: body_file_rel.clone(),
        sha256_file: sha_file_rel.clone(),
        headers_saved: save_headers,
        headers_file: headers_file_rel.clone(),
        json_file: json_filename.clone(),
        request,
        tls,
        chain_of_custody: chain,
    };

    let json = serde_json::to_string_pretty(&record)?;
    tokio::fs::write(&json_path, json).await?;
    info!("Evidence JSON written: {}", json_path.display());

    // CSV audit trail
    if write_csv {
        let csv_path = day_dir.join("index.csv");
        append_csv_row(&csv_path, &record).await?;
        info!("Audit CSV updated: {}", csv_path.display());
    }

    // Minimal console output
    println!("Status: {}", status);
    println!("Content length: {} bytes", content_length);
    println!("SHA-256: {}", sha_hex);
    if let Some(t) = &record.title { println!("Title: {}", t); }
    if let Some(s) = &record.headers.get("server") { println!("Server: {}", s); }
    println!("Evidence folder: {}", day_dir.display());

    Ok(())
}

async fn append_csv_row(path: &Path, record: &EvidenceRecord) -> Result<()> {
    let path = path.to_path_buf();

    // Flatten til CSV
    let fetched = record.fetched_at_utc.clone();
    let url = record.url.clone();
    let final_url = record.final_url.clone();
    let status = record.status.to_string();
    let len = record.content_length_bytes.to_string();
    let sha = record.sha256_hex.clone();
    let title = record.title.clone().unwrap_or_default();
    let server = record.headers.get("server").cloned().unwrap_or_default();
    let http_ver = record.http_version.clone();
    let mode = record.mode.clone();
    let case_id = record.chain_of_custody.case_id.clone().unwrap_or_default();
    let examiner = record.chain_of_custody.examiner.clone().unwrap_or_default();

    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::fs::OpenOptions;

        let file_exists = path.exists();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let mut wtr = csv::WriterBuilder::new()
            .has_headers(false) // vi skriver selv headers hvis needed
            .from_writer(file);

        if !file_exists {
            wtr.write_record([
                "fetched_at_utc",
                "url",
                "final_url",
                "status",
                "content_length_bytes",
                "sha256_hex",
                "title",
                "server_banner",
                "http_version",
                "mode",
                "case_id",
                "examiner",
            ])?;
        }

        wtr.write_record([
            fetched, url, final_url, status, len, sha, title, server, http_ver, mode, case_id, examiner
        ])?;

        wtr.flush()?;
        Ok(())
    }).await??;

    Ok(())
}

async fn check_tor_status() -> Result<()> {
    let client = create_tor_client()?;

    let resp = client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await
        .map_err(|e| anyhow!("Tor connection failed: {}", e))?;

    let text = resp.text().await?;
    println!("Tor connection active");
    println!("Response: {}", text);
    Ok(())
}
