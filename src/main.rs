use clap::{Parser, Subcommand};
use reqwest::Client;
use anyhow::Result;
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
        /// The .onion URL to scan
        #[arg(short, long)]
        url: String,
    },
    /// Scan multiple URLs from a file
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
            println!("🔍 Scanning: {}", url);
            scan_onion(&url).await?;
        }
        Commands::Status => {
            println!("🔄 Checking Tor connection...");
            check_tor_status().await?;
        }
        _ => {}
    }

    Ok(())
}


async fn scan_onion(url: &str) -> Result<()> {
    let client = create_tor_client()?;

    match client.get(url).send().await {
        Ok(response) => {
            println!("Status: {}", response.status());
            println!("Headers: {:#?}", response.headers());

            let body = response.text().await?;
            println!("📄 Content length: {} bytes", body.len());
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    Ok(())
}

async fn check_tor_status() -> Result<()> {
    let client = create_tor_client()?;

    match client.get("https://check.torproject.org/api/ip").send().await {
        Ok(response) => {
            let text = response.text().await?;
            println!("Tor connection active");
            println!("Response: {}", text);
        }
        Err(e) => {
            println!("Tor connection failed: {}", e);
        }
    }

    Ok(())
}

fn create_tor_client() -> Result<Client> {
    let client = Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
        .timeout(Duration::from_secs(30))
        .build()?;

    Ok(client)
}
