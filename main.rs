use std::{collections::HashMap, fs::File, io::BufWriter};
use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Serialize;

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

#[tokio::main]
async fn main() -> Result<()> {
    let brics = [
        ("br", "Brazil"),
        ("ru", "Russia"),
        ("in", "India"),
        ("cn", "China"),
        ("za", "South Africa"),
    ];

    let mut map: HashMap<String, CountryNets> = HashMap::new();

    for (cc, name) in &brics {
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
    let file = File::create("brics_ip_map.json")?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &map)?;
    println!("Wrote brics_ip_map.json");

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
