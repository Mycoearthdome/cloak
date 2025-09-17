use std::{collections::HashMap, fs::File, io::BufWriter};
use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Serialize;
use clap::{Parser, ValueEnum};
use std::process::Command;
use std::fmt;

/// IPv4 and IPv6 base URLs from IPdeny
const IPV4_BASE: &str = "https://www.ipdeny.com/ipblocks/data/aggregated";
const IPV6_BASE: &str = "https://www.ipdeny.com/ipv6/ipaddresses/aggregated";

/// Wrapper to serialize IpNetwork as a string
#[derive(Debug)]
struct SerIpNet(IpNetwork);

impl Serialize for SerIpNet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Debug, Serialize)]
struct CountryNets {
    ipv4: Vec<SerIpNet>,
    ipv6: Vec<SerIpNet>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ListChoice {
    Brics,
    Nato,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Action {
    Allow,
    Block,
}

// --- Implement Display for filename formatting ---
impl fmt::Display for ListChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListChoice::Brics => write!(f, "brics"),
            ListChoice::Nato => write!(f, "nato"),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Allow => write!(f, "allow"),
            Action::Block => write!(f, "block"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Which list to use: brics or nato
    #[arg(value_enum)]
    list: ListChoice,

    /// Whether to allow or block the list
    #[arg(value_enum)]
    action: Action,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let brics = [
        ("br", "Brazil"),
        ("ru", "Russia"),
        ("in", "India"),
        ("cn", "China"),
        ("za", "South Africa"),
    ];

    let nato = [
        ("al", "Albania"),
        ("be", "Belgium"),
        ("bg", "Bulgaria"),
        ("ca", "Canada"),
        ("hr", "Croatia"),
        ("cz", "Czechia"),
        ("dk", "Denmark"),
        ("ee", "Estonia"),
        ("fi", "Finland"),
        ("fr", "France"),
        ("de", "Germany"),
        ("gr", "Greece"),
        ("hu", "Hungary"),
        ("is", "Iceland"),
        ("it", "Italy"),
        ("lv", "Latvia"),
        ("lt", "Lithuania"),
        ("lu", "Luxembourg"),
        ("mt", "Malta"),
        ("nl", "Netherlands"),
        ("no", "Norway"),
        ("pl", "Poland"),
        ("pt", "Portugal"),
        ("ro", "Romania"),
        ("sk", "Slovakia"),
        ("si", "Slovenia"),
        ("es", "Spain"),
        ("se", "Sweden"),
        ("tr", "Türkiye"),
        ("gb", "United Kingdom"),
        ("us", "United States"),
    ];

    let countries: &[(&str, &str)] = match args.list {
        ListChoice::Brics => &brics,
        ListChoice::Nato => &nato,
    };

    let mut map: HashMap<String, CountryNets> = HashMap::new();

    for (cc, name) in countries {
        let ipv4_url = format!("{}/{}-aggregated.zone", IPV4_BASE, cc);
        let ipv6_url = format!("{}/{}-aggregated.zone", IPV6_BASE, cc);

        let ipv4: Vec<SerIpNet> = fetch_cidrs(&ipv4_url).await?
            .into_iter()
            .map(SerIpNet)
            .collect();

        let ipv6: Vec<SerIpNet> = fetch_cidrs(&ipv6_url).await?
            .into_iter()
            .map(SerIpNet)
            .collect();

        map.insert(cc.to_string(), CountryNets { ipv4, ipv6 });

        if let Some(entry) = map.get(&cc.to_string()) {
            println!(
                "{} ({}) -> {} IPv4 blocks, {} IPv6 blocks",
                name,
                cc.to_uppercase(),
                entry.ipv4.len(),
                entry.ipv6.len()
            );
        }
    }

    // --- Dump to JSON file ---
    let filename = format!("{}_ip_map.json", args.list);
    let file = File::create(&filename)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &map)?;
    println!("Wrote {}", filename);

    // --- Generate nftables rules ---
    let nft_filename = format!("{}_{}.nft", args.list, args.action);
    generate_nftables(&map, args.action, &nft_filename)?;
    println!("Wrote {}", nft_filename);

    // --- Ask user if they want to load rules ---
    println!("To load the rules manually, run:");
    println!("   sudo nft -f {}", nft_filename);
    println!("Do you want to load the rules now? [y/N]");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        println!("Loading rules into nftables...");
        let status = Command::new("sudo")
            .arg("nft")
            .arg("-f")
            .arg(&nft_filename)
            .status()
            .expect("failed to execute nft command");
        if status.success() {
            println!("Rules loaded successfully.");
        } else {
            println!("Failed to load rules. Try manually: sudo nft -f {}", nft_filename);
        }
    }

    Ok(())
}

async fn fetch_cidrs(url: &str) -> Result<Vec<IpNetwork>> {
    let body = reqwest::get(url)
        .await
        .with_context(|| format!("GET {}", url))?
        .text()
        .await
        .with_context(|| format!("read response body {}", url))?;

    let mut nets = Vec::new();
    for line in body.lines() {
        let token = line.trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(net) = token.parse::<IpNetwork>() {
            nets.push(net);
        }
    }
    Ok(nets)
}

fn generate_nftables(
    map: &HashMap<String, CountryNets>,
    action: Action,
    filename: &str,
) -> Result<()> {
    use std::io::Write;
    let mut file = File::create(filename)?;

    writeln!(file, "table inet filter {{")?;

    // IPv4 set
    writeln!(file, "  set country_ipv4 {{ type ipv4_addr; flags interval; elements = {{")?;
    for nets in map.values() {
        for ip in &nets.ipv4 {
            writeln!(file, "    {},", ip.0)?;
        }
    }
    writeln!(file, "  }} }}")?;

    // IPv6 set
    writeln!(file, "  set country_ipv6 {{ type ipv6_addr; flags interval; elements = {{")?;
    for nets in map.values() {
        for ip in &nets.ipv6 {
            writeln!(file, "    {},", ip.0)?;
        }
    }
    writeln!(file, "  }} }}")?;

    // Chain rules
    writeln!(file, "  chain input {{")?;
    writeln!(file, "    type filter hook input priority 0;")?;

    match action {
        Action::Block => {
            writeln!(file, "    ip saddr @country_ipv4 drop;")?;
            writeln!(file, "    ip6 saddr @country_ipv6 drop;")?;
            writeln!(file, "    accept;")?;
        }
        Action::Allow => {
            writeln!(file, "    ip saddr @country_ipv4 accept;")?;
            writeln!(file, "    ip6 saddr @country_ipv6 accept;")?;
            writeln!(file, "    drop;")?;
        }
    }

    writeln!(file, "  }}")?;
    writeln!(file, "}}")?;
    Ok(())
}
