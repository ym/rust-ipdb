use ipdb;
use std::net::IpAddr;

struct Args {
    ip: String,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;

    let mut ip = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Value(val) if ip.is_none() => {
                ip = Some(val.into_string()?);
            }
            Long("help") => {
                println!("Usage: ipdb-cli IP");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(Args {
        ip: ip.ok_or("missing argument IP")?,
    })
}

fn main() -> Result<(), lexopt::Error> {
    let args = parse_args()?;
    let reader = ipdb::Reader::open_readfile("ipdb.ipdb").unwrap();

    let ip: IpAddr = args.ip.parse().unwrap();
    let (data, prefixlen) = reader.lookup_prefix(ip, "EN".to_owned()).unwrap();

    println!("Prefix Length: {}", prefixlen);
    println!("{:#?}", data);

    Ok(())
}
