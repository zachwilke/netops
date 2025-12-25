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
                
                if let (Some(n), Some(o)) = (number, org) {
                    // Approximate location logic (Simulated for visualization)
                    let loc = match n {
                        // US Tech Giants (Approx US Center)
                        15169 | 16509 | 13335 | 3356 | 174 | 209 | 714 | 7922 => Some((38.0, -97.0)),
                        // Europe
                        1299 | 3320 | 5511 | 2914 => Some((50.0, 10.0)),
                        // Asia
                        4134 | 4837 | 17621 => Some((35.0, 105.0)),
                        _ => None,
                    };
                    return Some((n, o, loc));
                }
                None
            },
            Err(_) => None,
        }
    }
}
