use maxminddb::geoip2;
use std::net::IpAddr;
use std::sync::Arc;

pub struct GeoIpReader {
    reader: Arc<maxminddb::Reader<&'static [u8]>>,
}

impl GeoIpReader {
    pub fn new(db_bytes: &'static [u8]) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = maxminddb::Reader::from_source(db_bytes)?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    pub fn lookup_info(&self, ip: IpAddr) -> Option<(u32, String, Option<(f64, f64)>)> {
        match self.reader.lookup::<geoip2::Asn>(ip) {
            Ok(asn) => {
                let number = asn.autonomous_system_number;
                let org = asn.autonomous_system_organization.map(|s| s.to_string());
                
                if let (Some(n), Some(o)) = (number, org.clone()) {
                    // Try to determine location from Org name keywords
                    let base_loc = get_location_from_org(&o).or_else(|| {
                         // Fallback to specific ASNs if keyword failed
                        match n {
                            // Specific Overrides
                            15169 | 16509 | 13335 | 3356 | 174 | 209 | 714 | 7922 => Some((38.0, -97.0)), // US Center
                             _ => None,
                        }
                    });

                    // Add deterministic jitter based on IP to separate overlapping points
                    let loc = base_loc.map(|(lat, lon)| {
                         let (j_lat, j_lon) = get_ip_jitter(ip);
                         (lat + j_lat, lon + j_lon)
                    });

                    return Some((n, o, loc));
                }
                None
            },
            Err(_) => None,
        }
    }
}

fn get_location_from_org(org: &str) -> Option<(f64, f64)> {
    let lower = org.to_lowercase();
    
    // North America
    if lower.contains("google") || lower.contains("amazon") || lower.contains("microsoft") || lower.contains("apple") || lower.contains("cloudflare") || lower.contains("fastly") || lower.contains("akamai") || lower.contains("comcast") || lower.contains("verizon") || lower.contains("att") || lower.contains("charter") {
         return Some((38.0, -97.0)); // US
    }
    if lower.contains("canada") || lower.contains("rogers") || lower.contains("bell") { return Some((56.0, -106.0)); } // Canada
    
    // Europe
    if lower.contains("telekom") || lower.contains("germany") || lower.contains("hetzner") { return Some((51.0, 10.0)); }
    if lower.contains("london") || lower.contains("british") || lower.contains("virgin") || lower.contains("uk") || lower.contains("bt") { return Some((55.0, -3.0)); }
    if lower.contains("france") || lower.contains("orange") || lower.contains("ovh") { return Some((46.0, 2.0)); }
    if lower.contains("netherlands") || lower.contains("kpn") || lower.contains("lease") { return Some((52.0, 5.0)); }
    if lower.contains("russia") || lower.contains("rostelecom") { return Some((61.0, 105.0)); }
    if lower.contains("sweden") || lower.contains("telia") { return Some((60.0, 18.0)); }
    
    // Asia
    if lower.contains("china") || lower.contains("tencent") || lower.contains("alibaba") || lower.contains("huawei") { return Some((35.0, 105.0)); }
    if lower.contains("japan") || lower.contains("ntt") || lower.contains("kddi") || lower.contains("softbank") { return Some((36.0, 138.0)); }
    if lower.contains("korea") || lower.contains("sk") || lower.contains("kt") { return Some((35.0, 127.0)); }
    if lower.contains("india") || lower.contains("bharti") || lower.contains("jio") { return Some((20.0, 78.0)); }
    if lower.contains("singapore") { return Some((1.3, 103.8)); }
    
    // South America
    if lower.contains("brazil") || lower.contains("claro") || lower.contains("vivo") { return Some((-14.0, -51.0)); }
    
    // Oceania
    if lower.contains("australia") || lower.contains("telstra") || lower.contains("optus") { return Some((-25.0, 133.0)); }
    
    None
}

fn get_ip_jitter(ip: IpAddr) -> (f64, f64) {
    let bytes = match ip {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    
    if bytes.len() >= 4 {
        // Use last bytes for random-looking scatter
        let b1 = bytes[bytes.len() - 1] as f64;
        let b2 = bytes[bytes.len() - 2] as f64;
        
        // Jitter range: +/- 2.5 degrees
        let lat_off = (b1 % 50.0) / 10.0 - 2.5; 
        let lon_off = (b2 % 50.0) / 10.0 - 2.5;
        (lat_off, lon_off)
    } else {
        (0.0, 0.0)
    }

}
