use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::Packet;
use crossbeam::channel::Sender;
use std::thread;

#[derive(Debug, Clone)]
pub struct PacketSummary {
    pub time: String, // Simplified for now, could be SystemTime
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: String,
    pub info: String,
}

pub struct Sniffer {
    pub should_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub packet_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub in_packets: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub out_packets: std::sync::Arc<std::sync::atomic::AtomicU64>,
    
    // Bandwidth Counters (Bytes)
    pub wan_in_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub wan_out_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub lan_in_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub lan_out_bytes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    
    // Protocol Counters
    pub tcp_packets: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub udp_packets: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Sniffer {
    pub fn new() -> Self {
        Self {
            should_stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            packet_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            in_packets: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            out_packets: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            wan_in_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            wan_out_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            lan_in_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            lan_out_bytes: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            tcp_packets: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            udp_packets: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn start(&self, interface_name: String, tx: Sender<PacketSummary>, filter: String) {
        let should_stop = self.should_stop.clone();
        let packet_count = self.packet_count.clone();
        let in_packets = self.in_packets.clone();
        let out_packets = self.out_packets.clone();
        let wan_in = self.wan_in_bytes.clone();
        let wan_out = self.wan_out_bytes.clone();
        let lan_in = self.lan_in_bytes.clone();
        let lan_out = self.lan_out_bytes.clone();
        let tcp_count = self.tcp_packets.clone();
        let udp_count = self.udp_packets.clone();
        
        should_stop.store(false, std::sync::atomic::Ordering::Relaxed);
        
        // Lowercase filter for case-insensitive match
        let filter = filter.trim().to_lowercase();
        
        thread::spawn(move || {
            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| iface.name == interface_name)
                .expect("Interface not found");
            
            // Get local IPs and Network info
            let local_ips: Vec<std::net::IpAddr> = interface.ips.iter().map(|ip| ip.ip()).collect();
            let networks: Vec<(std::net::IpAddr, std::net::IpAddr)> = interface.ips.iter().map(|ip| (ip.ip(), ip.mask())).collect();
            
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unhandled channel type"),
                Err(e) => {
                    let _ = tx.send(PacketSummary {
                        time: "Error".to_string(),
                        source: "-".to_string(),
                        destination: "-".to_string(),
                        protocol: "ERR".to_string(),
                        length: "0".to_string(),
                        info: format!("Failed to create channel: {}", e),
                    });
                    return;
                }
            };

            loop {
                if should_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                
                match rx.next() {
                    Ok(packet) => {
                        packet_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let packet_len = packet.len() as u64;
                        let packet = EthernetPacket::new(packet).unwrap();
                        
                        // Direction & LAN/WAN Detection
                        let mut is_inbound = false;
                        let mut is_lan = false; // Default to WAN if not found in local net
                        
                        match packet.get_ethertype() {
                             EtherTypes::Ipv4 => {
                                if let Some(header) = Ipv4Packet::new(packet.payload()) {
                                    match header.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Tcp => {
                                            tcp_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        },
                                        IpNextHeaderProtocols::Udp => {
                                            udp_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        },
                                        _ => {}
                                    }

                                    let source = std::net::IpAddr::V4(header.get_source());
                                    let dest = std::net::IpAddr::V4(header.get_destination());
                                    
                                    if local_ips.contains(&dest) {
                                        is_inbound = true;
                                        // Check if source is in same subnet
                                        for (ip, mask) in &networks {
                                            if let (std::net::IpAddr::V4(src_ip), std::net::IpAddr::V4(net_ip), std::net::IpAddr::V4(net_mask)) = (source, ip, mask) {
                                                 // Simple check: apply mask
                                                 let src_u32 = u32::from(src_ip);
                                                 let net_u32 = u32::from(*net_ip);
                                                 let mask_u32 = u32::from(*net_mask);
                                                 if (src_u32 & mask_u32) == (net_u32 & mask_u32) {
                                                     is_lan = true;
                                                     break;
                                                 }
                                            }
                                        }
                                    } else if local_ips.contains(&source) {
                                        // Outbound
                                        // Check if dest is in same subnet
                                         for (ip, mask) in &networks {
                                            if let (std::net::IpAddr::V4(dst_ip), std::net::IpAddr::V4(net_ip), std::net::IpAddr::V4(net_mask)) = (dest, ip, mask) {
                                                 let dst_u32 = u32::from(dst_ip);
                                                 let net_u32 = u32::from(*net_ip);
                                                 let mask_u32 = u32::from(*net_mask);
                                                 if (dst_u32 & mask_u32) == (net_u32 & mask_u32) {
                                                     is_lan = true;
                                                     break;
                                                 }
                                            }
                                        }
                                    }
                                }
                             },
                             // Skipping IPv6 complexity for MVP brevity, defaulting to WAN/Inbound check similar to IPv4 if needed
                             // But let's just use existing inbound check for v6 and assume WAN for now
                              EtherTypes::Ipv6 => {
                                 if let Some(header) = Ipv6Packet::new(packet.payload()) {
                                    let dest = std::net::IpAddr::V6(header.get_destination());
                                    if local_ips.contains(&dest) {
                                        is_inbound = true;
                                    }
                                }
                             },
                             _ => {}
                        }
                        
                        if is_inbound {
                            in_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if is_lan {
                                lan_in.fetch_add(packet_len, std::sync::atomic::Ordering::Relaxed);
                            } else {
                                wan_in.fetch_add(packet_len, std::sync::atomic::Ordering::Relaxed);
                            }
                        } else {
                            out_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                             if is_lan {
                                lan_out.fetch_add(packet_len, std::sync::atomic::Ordering::Relaxed);
                            } else {
                                wan_out.fetch_add(packet_len, std::sync::atomic::Ordering::Relaxed);
                            }
                        }

                        let summary = parse_packet(&packet);
                        if let Some(s) = summary {
                            // Filter Logic
                            let mut matches = true;
                            if !filter.is_empty() {
                                matches = s.source.to_lowercase().contains(&filter) ||
                                          s.destination.to_lowercase().contains(&filter) ||
                                          s.protocol.to_lowercase().contains(&filter) ||
                                          s.info.to_lowercase().contains(&filter);
                            }
                            
                            if matches {
                                if tx.send(s).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        // eprintln!("An error occurred while reading: {}", e);
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        self.should_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn parse_packet(ethernet: &EthernetPacket) -> Option<PacketSummary> {
    let time = time::OffsetDateTime::now_utc().time().format(&time::format_description::parse("[hour]:[minute]:[second]").unwrap()).unwrap_or_default();
    
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                let source = header.get_source().to_string();
                let dest = header.get_destination().to_string();
                let _protocol = match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => "TCP",
                    IpNextHeaderProtocols::Udp => "UDP",
                    IpNextHeaderProtocols::Icmp => "ICMP",
                    _ => "IPv4",
                };
                
                let (info, proto_detail) = match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(header.payload()) {
                            (format!("{} -> {} [Seq={}]", tcp.get_source(), tcp.get_destination(), tcp.get_sequence()), "TCP")
                        } else {
                            ("Malformed TCP".to_string(), "TCP")
                        }
                    },
                     IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(header.payload()) {
                            (format!("{} -> {} [Len={}]", udp.get_source(), udp.get_destination(), udp.get_length()), "UDP")
                        } else {
                            ("Malformed UDP".to_string(), "UDP")
                        }
                    },
                    IpNextHeaderProtocols::Icmp => {
                         if let Some(icmp) = IcmpPacket::new(header.payload()) {
                            (format!("Type={:?} Code={:?}", icmp.get_icmp_type(), icmp.get_icmp_code()), "ICMP")
                        } else {
                            ("Malformed ICMP".to_string(), "ICMP")
                        }
                    }
                    _ => ("Unknown L4".to_string(), "IPv4"),
                };

                Some(PacketSummary {
                    time,
                    source,
                    destination: dest,
                    protocol: proto_detail.to_string(),
                    length: format!("{}", header.get_total_length()),
                    info,
                })
            } else {
                None
            }
        },
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                 let source = header.get_source().to_string();
                let dest = header.get_destination().to_string();
                 let (info, proto_detail) = match header.get_next_header() {
                    IpNextHeaderProtocols::Tcp => ("TCP (IPv6)".to_string(), "TCP"),
                    IpNextHeaderProtocols::Udp => ("UDP (IPv6)".to_string(), "UDP"),
                    IpNextHeaderProtocols::Icmpv6 => ("ICMPv6".to_string(), "ICMPv6"),
                    _ => ("IPv6".to_string(), "IPv6"),
                };
                 Some(PacketSummary {
                    time,
                    source,
                    destination: dest,
                    protocol: proto_detail.to_string(),
                    length: format!("{}", header.get_payload_length()),
                    info,
                })
            } else {
                 None
            }
        }
        _ => None // Ignore non-IP for simplicity in MVP
    }
}
