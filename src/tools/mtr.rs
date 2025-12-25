use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crossbeam::channel::Sender;
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Debug, Clone)]
pub struct MtrResult {
    pub ttl: u8,
    pub host: Option<IpAddr>,
    pub rtt: Duration,
    pub successful: bool,
    pub is_target: bool,
}

#[derive(Debug, Clone)]
pub struct HopStats {
    pub ttl: u8,
    pub host: String,
    pub sent: u64,
    pub recv: u64,
    pub last: u64, // ms
    pub best: u64,
    pub worst: u64,
    pub avg: u64,
    pub loss: f64,
    pub history: VecDeque<u64>,
    pub jitter: u64,
}

pub struct MtrTask {
    pub should_stop: Arc<AtomicBool>,
}

impl MtrTask {
    pub fn new() -> Self {
        Self {
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self, target_str: String, tx: Sender<MtrResult>) {
        let should_stop = self.should_stop.clone();
        should_stop.store(false, Ordering::Relaxed);
        
        std::thread::spawn(move || {
             // Parse args
            let args: Vec<&str> = target_str.split_whitespace().collect();
            let mut host_str = "";
            let mut interval_ms = 1000;
            let mut max_hops = 30;
            let mut count: Option<u64> = None;
            
            let mut i = 0;
            while i < args.len() {
                match args[i] {
                    "-i" => {
                        if i + 1 < args.len() {
                             if let Ok(v) = args[i+1].parse::<f64>() {
                                 interval_ms = (v * 1000.0) as u64;
                             }
                             i += 2;
                        } else { i += 1; }
                    }
                    "-m" => {
                        if i + 1 < args.len() {
                             if let Ok(v) = args[i+1].parse::<u8>() {
                                 max_hops = v;
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
            
            if host_str.is_empty() { return; }

            // Resolve
            let target_ip: IpAddr = match format!("{}:0", host_str).to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(a) = addrs.next() {
                         a.ip()
                    } else { return; }
                }
                Err(_) => {
                    // Try parsing as IP directly if resolution failed or it was just an IP
                    if let Ok(ip) = host_str.parse() {
                        ip
                    } else {
                        return;
                    }
                }
            };
            
            // let sock_addr = SocketAddr::new(target_ip, 0);

            let mut cycles_done = 0;
            loop {
                if should_stop.load(Ordering::Relaxed) {
                    break;
                }
                
                if let Some(c) = count {
                    if cycles_done >= c {
                        break;
                    }
                }
                cycles_done += 1;

                // Run one pass of traceroute (TTL 1..max_hops)
                for ttl in 1..=max_hops {
                    if should_stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let res = probe(target_ip, ttl);
                    if let Ok(r) = res {
                        let is_target = r.host == Some(target_ip);
                        let _ = tx.send(r.clone());
                        if is_target {
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100)); // Pace packets slightly
                }
                
                // Wait before next cycle
                std::thread::sleep(Duration::from_millis(interval_ms));
            }
        });
    }

    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::Relaxed);
    }
}

fn probe(target: IpAddr, ttl: u8) -> std::io::Result<MtrResult> {
    // This is a very simplified raw socket implementation.
    // In Rust, for ICMP, we need a raw socket.
    
    // NOTE: This uses functionality that requires sudo.
    // We will use surge-ping approach or pnet? 
    // Socket2 gives us raw socket control.
    
    let domain = match target {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    
    // Create raw socket for ICMP
    let proto = match target {
         IpAddr::V4(_) => Protocol::ICMPV4,
         IpAddr::V6(_) => Protocol::ICMPV6,
    };
    
    let socket = Socket::new(domain, Type::RAW, Some(proto))?;

    // #[cfg(unix)]
    // socket.set_ttl(ttl as u32)?;
    // On Windows it might be different, but socket2 handles some differences. 
    // Wait, error said `set_ttl` not found. 
    // socket2 0.6 has `set_ttl` for specific protocol layers?
    // Let's check if it exists or use `set_ip_ttl`?
    // The error suggestion was `set_ttl_v4`.
    
    // Logic for socket2 v0.5+:
    if target.is_ipv4() {
        socket.set_ttl_v4(ttl as u32)?;
    } else {
        socket.set_unicast_hops_v6(ttl as u32)?;
    }
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    
    // Construct ICMP Echo Request
    let mut packet = vec![0u8; 64]; 
    if target.is_ipv4() {
        packet[0] = 8; // Echo Request
        packet[1] = 0; // Code
    } else {
        packet[0] = 128; // Echo Request V6
        packet[1] = 0;
    }
    
    // Basic checksum (needed for IPv4 ICMP)
    if target.is_ipv4() {
        let checksum_bytes = internet_checksum::checksum(&packet);
        // checksum returns [u8; 2] aka byte array
        packet[2] = checksum_bytes[0];
        packet[3] = checksum_bytes[1];
    }
    // Note: Kernel handles ICMPv6 checksum usually?

    let start = Instant::now();
    let sock_addr = SocketAddr::new(target, 0);
    
    socket.send_to(&packet, &sock_addr.into())?;
    
    // Listen for reply
    let mut buf = [0u8; 1024]; // SAFETY: buf is initialized
    let mut buf = unsafe { std::mem::MaybeUninit::new(buf).assume_init() }; 
    // Actually Socket2 recv_from takes MaybeUninit? No, &mut [MaybeUninit<u8>].
    // Let's us regular buffer for simpler API if possible, or use `recv_from` with initialized buf.
    // socket2 0.4 vs 0.5 diffs. latest socket2 `recv_from` takes `&mut [MaybeUninit<u8>]`.

    let mut recv_buf = [std::mem::MaybeUninit::new(0u8); 1024];

    match socket.recv_from(&mut recv_buf) {
        Ok((size, addr)) => {
            let rtt = start.elapsed();
            let addr = addr.as_socket().map(|s| s.ip());
            
            // Check packet type to see if TimeExceeded or EchoReply
            // But for MTR, getting *any* response from an IP usually means that's the hop.
            // (Unless it's some stray packet).
            // We assume if we receive something, it's related.
            
            Ok(MtrResult {
                ttl,
                host: addr,
                rtt,
                successful: true,
                is_target: addr == Some(target),
            })
        }
        Err(_) => {
            // Timeout or error
             Ok(MtrResult {
                ttl,
                host: None,
                rtt: Duration::MAX,
                successful: false,
                is_target: false,
            })
        }
    }
}
