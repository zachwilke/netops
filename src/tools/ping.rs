use std::time::Duration;
use surge_ping::{IcmpPacket, PingIdentifier};
use tokio::sync::mpsc::Sender;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PingResult {
    pub seq: u16,
    pub ttl: u8,
    pub time: Duration,
    pub target: String,
}

pub struct PingTask {
    pub target: String,
    pub tx: Sender<Result<PingResult, String>>,
}

impl PingTask {
    pub async fn run(self) {
        let args: Vec<&str> = self.target.split_whitespace().collect();
        let mut host_str = "";
        let mut interval_ms = 1000;
        let mut payload_size = 56;
        
        let mut count: Option<u64> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "-i" => {
                    if i + 1 < args.len() {
                        // Standard ping takes seconds (e.g., 0.2)
                         if let Ok(v) = args[i+1].parse::<f64>() {
                             interval_ms = (v * 1000.0) as u64;
                         }
                         i += 2;
                    } else { i += 1; }
                }
                "-s" => {
                     if i + 1 < args.len() {
                         if let Ok(v) = args[i+1].parse::<usize>() {
                             payload_size = v;
                         }
                         i += 2;
                    } else { i += 1; }
                }
                "-c" => {
                     if i + 1 < args.len() {
                         if let Ok(v) = args[i+1].parse::<u64>() {
                             count = Some(v);
                         }
                         i += 2;
                    } else { i += 1; }
                }
                arg => {
                    if !arg.starts_with("-") {
                        host_str = arg;
                    }
                    i += 1;
                }
            }
        }
        
        if host_str.is_empty() {
             let _ = self.tx.send(Err("No target provided".to_string())).await;
             return;
        }

        // Hostname resolution
        let ip: IpAddr = match host_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // Try resolve
                // Usually we want port 0 or just lookup
                match tokio::net::lookup_host(format!("{}:0", host_str)).await {
                    Ok(mut addrs) => {
                         if let Some(socket_addr) = addrs.next() {
                             socket_addr.ip()
                         } else {
                             let _ = self.tx.send(Err(format!("Could not resolve {}", host_str))).await;
                             return;
                         }
                    }
                    Err(e) => {
                         let _ = self.tx.send(Err(format!("DNS Error: {}", e))).await;
                         return;
                    }
                }
            }
        };

        // Ping loop
        let mut seq = 0;

        loop {
            match surge_ping::ping(ip, &vec![0; payload_size]).await {
                Ok((icmp_packet, dur)) => {
                    let ttl = match icmp_packet {
                        IcmpPacket::V4(p) => p.get_ttl().unwrap_or(0),
                        IcmpPacket::V6(p) => p.get_max_hop_limit(),
                    };
                    
                    let result = PingResult {
                        seq,
                        ttl,
                        time: dur,
                        target: host_str.to_string(), // Return the hostname user typed
                    };
                    if self.tx.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                     if self.tx.send(Err(format!("Ping failed: {}", e))).await.is_err() {
                        break;
                    }
                }
            }
            seq = seq.wrapping_add(1);
            
            if let Some(c) = count {
                if seq as u64 >= c {
                    break;
                }
            }
            
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }
}
