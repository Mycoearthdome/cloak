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
    Eu,
    Asean,
    G7,
    G20,
    Opec,
    Africa
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
            ListChoice::Eu => write!(f, "eu"),
            ListChoice::Asean => write!(f, "asean"),
            ListChoice::G7 => write!(f, "g7"),
            ListChoice::G20 => write!(f, "g20"),
            ListChoice::Opec => write!(f, "opec"),
            ListChoice::Africa => write!(f, "african_union")
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

    let eu = [
        ("at", "Austria"),
        ("be", "Belgium"),
        ("bg", "Bulgaria"),
        ("hr", "Croatia"),
        ("cy", "Cyprus"),
        ("cz", "Czechia"),
        ("dk", "Denmark"),
        ("ee", "Estonia"),
        ("fi", "Finland"),
        ("fr", "France"),
        ("de", "Germany"),
        ("gr", "Greece"),
        ("hu", "Hungary"),
        ("ie", "Ireland"),
        ("it", "Italy"),
        ("lv", "Latvia"),
        ("lt", "Lithuania"),
        ("lu", "Luxembourg"),
        ("mt", "Malta"),
        ("nl", "Netherlands"),
        ("pl", "Poland"),
        ("pt", "Portugal"),
        ("ro", "Romania"),
        ("sk", "Slovakia"),
        ("si", "Slovenia"),
        ("es", "Spain"),
        ("se", "Sweden"),
    ];

    let asean = [
        ("id", "Indonesia"),
        ("my", "Malaysia"),
        ("ph", "Philippines"),
        ("sg", "Singapore"),
        ("th", "Thailand"),
        ("vn", "Vietnam"),
        ("mm", "Myanmar"),
        ("kh", "Cambodia"),
        ("la", "Laos"),
        ("bn", "Brunei"),
    ];

    let g7 = [
        ("ca", "Canada"),
        ("fr", "France"),
        ("de", "Germany"),
        ("it", "Italy"),
        ("jp", "Japan"),
        ("gb", "United Kingdom"),
        ("us", "United States"),
    ];

    let g20 = [
        ("ar", "Argentina"),
        ("au", "Australia"),
        ("br", "Brazil"),
        ("ca", "Canada"),
        ("cn", "China"),
        ("fr", "France"),
        ("de", "Germany"),
        ("in", "India"),
        ("id", "Indonesia"),
        ("it", "Italy"),
        ("jp", "Japan"),
        ("mx", "Mexico"),
        ("ru", "Russia"),
        ("sa", "Saudi Arabia"),
        ("za", "South Africa"),
        ("kr", "South Korea"),
        ("tr", "Türkiye"),
        ("gb", "United Kingdom"),
        ("us", "United States"),
        ("eu", "European Union"),
    ];

    let opec = [
        ("dz", "Algeria"),
        ("ao", "Angola"),
        ("cd", "Congo"),
        ("gq", "Equatorial Guinea"),
        ("ga", "Gabon"),
        ("iq", "Iraq"),
        ("kw", "Kuwait"),
        ("ly", "Libya"),
        ("ng", "Nigeria"),
        ("sa", "Saudi Arabia"),
        ("ae", "United Arab Emirates"),
        ("ve", "Venezuela"),
    ];

    let african_union = [
        ("dz", "Algeria"),
        ("ao", "Angola"),
        ("bj", "Benin"),
        ("bw", "Botswana"),
        ("bf", "Burkina Faso"),
        ("bi", "Burundi"),
        ("cm", "Cameroon"),
        ("cv", "Cape Verde"),
        ("cf", "Central African Republic"),
        ("td", "Chad"),
        ("km", "Comoros"),
        ("cg", "Congo"),
        ("cd", "Democratic Republic of the Congo"),
        ("ci", "Côte d'Ivoire"),
        ("dj", "Djibouti"),
        ("eg", "Egypt"),
        ("gq", "Equatorial Guinea"),
        ("er", "Eritrea"),
        ("sz", "Eswatini"),
        ("et", "Ethiopia"),
        ("ga", "Gabon"),
        ("gm", "Gambia"),
        ("gh", "Ghana"),
        ("gn", "Guinea"),
        ("gw", "Guinea-Bissau"),
        ("ke", "Kenya"),
        ("ls", "Lesotho"),
        ("lr", "Liberia"),
        ("ly", "Libya"),
        ("mg", "Madagascar"),
        ("mw", "Malawi"),
        ("ml", "Mali"),
        ("mr", "Mauritania"),
        ("mu", "Mauritius"),
        ("ma", "Morocco"),
        ("mz", "Mozambique"),
        ("na", "Namibia"),
        ("ne", "Niger"),
        ("ng", "Nigeria"),
        ("rw", "Rwanda"),
        ("st", "São Tomé and Príncipe"),
        ("sn", "Senegal"),
        ("sc", "Seychelles"),
        ("sl", "Sierra Leone"),
        ("so", "Somalia"),
        ("za", "South Africa"),
        ("ss", "South Sudan"),
        ("sd", "Sudan"),
        ("tz", "Tanzania"),
        ("tg", "Togo"),
        ("tn", "Tunisia"),
        ("ug", "Uganda"),
        ("zm", "Zambia"),
        ("zw", "Zimbabwe"),
    ];


    let countries: &[(&str, &str)] = match args.list {
        ListChoice::Brics => &brics,
        ListChoice::Nato => &nato,
        ListChoice::Eu => &eu,
        ListChoice::Asean => &asean,
        ListChoice::G7 => &g7,
        ListChoice::G20 => &g20,
        ListChoice::Opec => &opec,
        ListChoice::Africa => &african_union,

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
