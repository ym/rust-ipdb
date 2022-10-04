use ipdb::{self, Within};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    ip: String,

    #[arg(short, long)]
    within: bool,

    #[arg(short, long)]
    region: Option<String>,

    #[arg(short, long)]
    country: Option<String>,

    #[arg(short, long)]
    owner: Option<String>,

    #[arg(short, long)]
    isp: Option<String>,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let reader = ipdb::Reader::open_readfile("ipdb.ipdb").unwrap();

    if args.within {
        let cidr: String = args.ip.parse().unwrap();
        let ip_net = if args.ip.contains(':') {
            IpNetwork::V6(cidr.parse().unwrap())
        } else {
            IpNetwork::V4(cidr.parse().unwrap())
        };

        let iter: Within<Vec<u8>> = reader.within(ip_net).map_err(|e| e.to_string())?;
        for next in iter {
            let item = next.map_err(|e| e.to_string())?;
            if !args.region.is_none() {
                if item.info.region_name != args.region.as_ref().unwrap() {
                    continue;
                }
            }
            
            if !args.country.is_none() {
                if item.info.country_code != args.country.as_ref().unwrap() {
                    continue;
                }
            }

            if !args.owner.is_none() {
                if !item.info.owner_domain.contains(args.owner.as_ref().unwrap()) {
                    continue;
                }
            }
            
            if !args.isp.is_none() {
                if !item.info.isp_domain.contains(args.isp.as_ref().unwrap()) {
                    continue;
                }
            }

            println!("{} {:?}", item.ip_net, item.info);
        }
    } else {
        let ip: IpAddr = args.ip.parse().unwrap();
        let (data, prefixlen) = reader.lookup_prefix(ip, "EN".to_owned()).unwrap();

        println!("Prefix Length: {}", prefixlen);
        println!("{:#?}", data);
    }
    Ok(())
}
