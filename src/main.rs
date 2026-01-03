use clap::{Parser, Subcommand};
use reqwest::Client;
use anyhow::{Result, anyhow};
use std::time::Duration;

const ASCII_ART: &str = r#"
                                __
                         _,-;''';`'-,.
                      _/',  `;  `;    `\
      ,        _..,-''    '   `  `      `\
     | ;._.,,-' .| |,_        ,,          `\
     | `;'      ;' ;, `,   ; |    '  '  .   \
     `; __`  ,'__  ` ,  ` ;  |      ;        \
     ; (6_);  (6_) ; |   ,    \        '      |       /
    ;;   _,' ,.    ` `,   '    `-._           |   __//_________
     ,;.=..`_..=.,' -'          ,''        _,--''------''''
_pb__\,`"=,,,=="',___,,,-----'''----'_'_'_''-;''
-----------------------''''''\ \'''''   )   /'     DARKCAT
                              `\`,,,___/__/'_____,
                                `--,,,--,-,'''\
                               __,,-' /'       `
                             /'_,,--''
                            | (           Dark web recon claw
                             `'
"#;

#[derive(Parser)]
#[command(name = "DARKCAT")]
#[command(about = "Dark web recon claw - CLI tool for darkweb digital forensics", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a .onion URL
    Scan {
        /// The .onion URL to scan (with or without http/https)
        #[arg(short, long)]
        url: String,
    },
    /// Scan multiple URLs from a file (one per line)
    BatchScan {
        /// Path to file containing URLs (one per line)
        #[arg(short, long)]
        file: String,
    },
    /// Check Tor connectivity
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("{}", ASCII_ART);

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { url } => {
            let url = normalize_url(&url);
            println!("Scanning: {}", url);
            scan_onion(&url).await?;
        }
        Commands::BatchScan { file } => {
            println!("Batch scanning file: {}", file);
            batch_scan(&file).await?;
        }
        Commands::Status => {
            println!("Checking Tor connection...");
            check_tor_status().await?;
        }
    }

    Ok(())
}

fn normalize_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

async fn batch_scan(path: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::fs::File;

    let file = File::open(path).await
        .map_err(|e| anyhow!("Could not open file '{}': {}", path, e))?;
    let mut lines = BufReader::new(file).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let url = normalize_url(line);
        println!("\n=== Scanning: {} ===", url);
        if let Err(e) = scan_onion(&url).await {
            eprintln!("Scan failed for {}: {}", url, e);
        }
    }

    Ok(())
}

async fn scan_onion(url: &str) -> Result<()> {
    let client = create_tor_client()?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    println!("Status: {}", response.status());
    println!("Headers: {:#?}", response.headers());

    let body = response.text().await?;
    println!("Content length: {} bytes", body.len());

    Ok(())
}

async fn check_tor_status() -> Result<()> {
    let client = create_tor_client()?;

    let response = client
        .get("https://check.torproject.org/api/ip")
        .send()
        .await
        .map_err(|e| anyhow!("Tor connection failed: {}", e))?;

    let text = response.text().await?;
    println!("Tor connection active");
    println!("Response: {}", text);

    Ok(())
}

fn create_tor_client() -> Result<Client> {
    let client = Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(30))
        .build()?;

    Ok(client)
}
