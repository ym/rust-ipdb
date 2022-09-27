#[macro_use]
extern crate criterion;
extern crate fake;
extern crate ipdb;
extern crate rayon;

use criterion::Criterion;
use fake::faker::internet::raw::IPv4;
use fake::locales::EN;
use fake::Fake;
use ipdb::Reader;
use rayon::prelude::*;

use std::net::IpAddr;
use std::str::FromStr;

// Generate `count` IPv4 addresses
#[must_use]
pub fn generate_ipv4(count: u64) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for _i in 0..count {
        let val: String = IPv4(EN).fake();
        let ip: IpAddr = FromStr::from_str(&val).unwrap();
        ips.push(ip);
    }
    ips
}

// Single-threaded
pub fn bench_ipdb(ips: &[IpAddr], reader: &ipdb::Reader<Vec<u8>>) {
    for ip in ips.iter() {
        let _ = reader.lookup(*ip, "EN".to_owned());
    }
}

// Using rayon for parallel execution
pub fn bench_par_ipdb(ips: &[IpAddr], reader: &ipdb::Reader<Vec<u8>>) {
    ips.par_iter().for_each(|ip| {
        let _ = reader.lookup(*ip, "EN".to_owned());
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let ips = generate_ipv4(100);
    let reader = Reader::open_readfile("ipdb.ipdb").unwrap();

    c.bench_function("ipdb", |b| b.iter(|| bench_ipdb(&ips, &reader)));
}

pub fn criterion_par_benchmark(c: &mut Criterion) {
    let ips = generate_ipv4(100);
    let reader = Reader::open_readfile("ipdb.ipdb").unwrap();

    c.bench_function("ipdb_par", |b| {
        b.iter(|| bench_par_ipdb(&ips, &reader))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10);

    targets = criterion_benchmark, criterion_par_benchmark
}

criterion_main!(benches);
