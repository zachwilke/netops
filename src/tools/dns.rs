use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use hickory_resolver::proto::rr::RecordType;
// Removed unused import: std::net::IpAddr

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub enum DnsResult {
    A(Vec<DnsRecord>),
    AAAA(Vec<DnsRecord>),
    MX(Vec<DnsRecord>),
    TXT(Vec<DnsRecord>),
    NS(Vec<DnsRecord>),
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
                    let recs: Vec<DnsRecord> = response.records().iter().filter_map(|r| r.data().and_then(|d| d.as_a()).map(|a| DnsRecord { value: a.0.to_string(), ttl: r.ttl() })).collect();
                    Ok(DnsResult::A(recs))
                },
                RecordType::AAAA => {
                    let recs: Vec<DnsRecord> = response.records().iter().filter_map(|r| r.data().and_then(|d| d.as_aaaa()).map(|a| DnsRecord { value: a.0.to_string(), ttl: r.ttl() })).collect();
                    Ok(DnsResult::AAAA(recs))
                },
                RecordType::MX => {
                    let recs: Vec<DnsRecord> = response.records().iter().filter_map(|r| r.data().and_then(|d| d.as_mx()).map(|mx| 
                        DnsRecord { value: format!("{} {}", mx.preference(), mx.exchange()), ttl: r.ttl() }
                    )).collect();
                    Ok(DnsResult::MX(recs))
                },
                RecordType::TXT => {
                     let recs: Vec<DnsRecord> = response.records().iter().filter_map(|r| r.data().and_then(|d| d.as_txt()).map(|txt| 
                        DnsRecord { value: txt.to_string(), ttl: r.ttl() }
                     )).collect();
                     Ok(DnsResult::TXT(recs))
                },
                RecordType::NS => {
                    let recs: Vec<DnsRecord> = response.records().iter().filter_map(|r| r.data().and_then(|d| d.as_ns()).map(|ns| 
                        DnsRecord { value: ns.to_string(), ttl: r.ttl() }
                    )).collect();
                    Ok(DnsResult::NS(recs))
                },
                _ => Err("Unsupported record type".to_string()),
            }
        }
        Err(e) => Err(format!("DNS Lookup failed: {}", e)),
    }
}
