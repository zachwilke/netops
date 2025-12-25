use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use hickory_resolver::proto::rr::RecordType;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum DnsResult {
    A(Vec<IpAddr>),
    AAAA(Vec<IpAddr>),
    MX(Vec<(u16, String)>),
    TXT(Vec<String>),
    NS(Vec<String>),
}

pub async fn resolve(domain: &str, record_type: RecordType) -> Result<DnsResult, String> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    match resolver.lookup(domain, record_type).await {
        Ok(response) => {
            match record_type {
                RecordType::A => {
                    let ips: Vec<IpAddr> = response.iter().filter_map(|r| r.as_a().map(|a| IpAddr::V4(a.0))).collect();
                    Ok(DnsResult::A(ips))
                },
                RecordType::AAAA => {
                    let ips: Vec<IpAddr> = response.iter().filter_map(|r| r.as_aaaa().map(|a| IpAddr::V6(a.0))).collect();
                    Ok(DnsResult::AAAA(ips))
                },
                RecordType::MX => {
                    let mxs: Vec<(u16, String)> = response.iter().filter_map(|r| r.as_mx().map(|mx| (mx.preference(), mx.exchange().to_string()))).collect();
                    Ok(DnsResult::MX(mxs))
                },
                RecordType::TXT => {
                     let txts: Vec<String> = response.iter().filter_map(|r| r.as_txt().map(|txt| txt.to_string())).collect();
                     Ok(DnsResult::TXT(txts))
                },
                RecordType::NS => {
                    let nss: Vec<String> = response.iter().filter_map(|r| r.as_ns().map(|ns| ns.to_string())).collect();
                    Ok(DnsResult::NS(nss))
                },
                _ => Err("Unsupported record type".to_string()),
            }
        }
        Err(e) => Err(format!("DNS Lookup failed: {}", e)),
    }
}
