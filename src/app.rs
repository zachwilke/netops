use std::collections::{VecDeque, HashMap};
use std::net::IpAddr;
// use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::TableState;
use anyhow::Result;

use pnet_datalink::NetworkInterface;
use crate::tools::ping::{PingResult, PingTask};
use crate::tools::{interfaces, dns, sniffer, mtr, nmap, arpscan, geoip, connections};
use crate::tools::dns::DnsResult;

use tokio::sync::mpsc::{self, Receiver, error::TryRecvError};
use tui_input::Input;

use hickory_resolver::proto::rr::RecordType;

pub enum CurrentScreen {
    Dashboard,
    Ping,
    Dns,
    Sniffer,
    Mtr,
    Nmap,
    Connections,
    ArpScan,
    // Traceroute,
}

pub struct ConnectionInfo {
    pub remote_ip: IpAddr,
    pub asn_num: u32,
    pub asn_org: String,
    pub last_seen: std::time::Instant,
    pub packet_count: u64,
    pub protocol: String,
    pub location: Option<(f64, f64)>, // Lat, Lon
}

pub struct App {
    pub current_screen: CurrentScreen,
    pub should_quit: bool,
    pub show_help: bool,
    pub show_options: bool,
    pub options_scroll: usize,
    pub interfaces: Vec<NetworkInterface>,
    
    // Ping State
    pub ping_input: Input,
    pub ping_history: VecDeque<Result<PingResult, String>>,
    pub ping_rtt_history: VecDeque<u64>,
    pub ping_rx: Option<Receiver<Result<PingResult, String>>>,
    pub is_pinging: bool,

    // DNS State

    // DNS State
    pub dns_input: Input,
    pub dns_record_type: RecordType,
    pub dns_result: Option<Result<DnsResult, String>>,
    pub dns_rx: Option<Receiver<Result<DnsResult, String>>>,

    // Sniffer State
    pub sniffer: sniffer::Sniffer,
    pub sniffer_rx: Option<crossbeam::channel::Receiver<sniffer::PacketSummary>>,
    pub sniffer_packets: VecDeque<sniffer::PacketSummary>,
    pub sniffer_active: bool,
    pub selected_interface_index: usize,

    // MTR State
    pub mtr_input: Input,
    pub mtr_task: mtr::MtrTask,
    pub mtr_rx: Option<crossbeam::channel::Receiver<mtr::MtrResult>>,
    pub mtr_hops: Vec<mtr::HopStats>,
    pub mtr_active: bool,
    pub mtr_table_state: TableState,
    pub mtr_selected_hop: usize,

    // Nmap State
    pub nmap_input: Input,
    pub nmap_active: bool,
    pub nmap_rx: Option<crossbeam::channel::Receiver<String>>,
    pub nmap_output: VecDeque<String>,
    pub nmap_scroll: u16,

    // ArpScan State
    pub arpscan_input: Input,
    pub arpscan_active: bool,
    pub arpscan_rx: Option<crossbeam::channel::Receiver<String>>,
    pub arpscan_output: VecDeque<String>,
    pub arpscan_scroll: u16,

    // ASN / Connections
    pub geoip_reader: Option<geoip::GeoIpReader>,
    pub active_connections: HashMap<IpAddr, ConnectionInfo>,
    pub connections_rx: Option<crossbeam::channel::Receiver<Vec<connections::RawConnection>>>,
    pub globe_rotation: f64,

    // Dashboard Graph
    pub traffic_history: VecDeque<u64>,
    pub rx_history: VecDeque<u64>,
    pub tx_history: VecDeque<u64>,
    pub last_packet_count: u64,
    pub last_rx_count: u64,
    pub last_tx_count: u64,

    // Bandwidth History (Mbps - f64)
    pub wan_rx_history: VecDeque<f64>,
    pub wan_tx_history: VecDeque<f64>,
    pub lan_rx_history: VecDeque<f64>,
    pub lan_tx_history: VecDeque<f64>,

    pub last_wan_rx_bytes: u64,
    pub last_wan_tx_bytes: u64,
    pub last_lan_rx_bytes: u64,
    pub last_lan_tx_bytes: u64,

    // Protocol History (PPS)
    pub connection_count_history: VecDeque<u64>,

    pub last_tick_time: std::time::Instant,

    // Dashboard Background Ping
    pub db_ping_history: VecDeque<u64>,
    pub db_jitter_history: VecDeque<u64>,
    pub db_ping_rx: Option<tokio::sync::mpsc::Receiver<Result<PingResult, String>>>,
}

impl App {
    pub fn new() -> App {
        App {
            current_screen: CurrentScreen::Dashboard,
            should_quit: false,
            show_help: false,
            show_options: false,
            options_scroll: 0,
            interfaces: interfaces::get_interfaces(),
            
            ping_input: Input::default(),
            ping_history: VecDeque::with_capacity(50),
            ping_rtt_history: VecDeque::with_capacity(100),
            ping_rx: None,
            is_pinging: false,

            dns_input: Input::default(),
            dns_record_type: RecordType::A,
            dns_result: None,
            dns_rx: None,

            sniffer: sniffer::Sniffer::new(),
            sniffer_rx: None,
            sniffer_packets: VecDeque::with_capacity(1000),
            sniffer_active: false,
            selected_interface_index: 0,

            mtr_input: Input::default(),
            mtr_task: mtr::MtrTask::new(),
            mtr_rx: None,
            mtr_hops: Vec::new(),
            mtr_active: false,
            mtr_selected_hop: 0,
            mtr_table_state: TableState::default(),

            nmap_input: Input::default(),
            nmap_active: false,
            nmap_rx: None,
            nmap_output: VecDeque::with_capacity(1000),
            nmap_scroll: 0,



            arpscan_input: Input::default(),
            arpscan_active: false,
            arpscan_rx: None,
            arpscan_output: VecDeque::with_capacity(1000),
            arpscan_scroll: 0,

            geoip_reader: geoip::GeoIpReader::new(include_bytes!("../GeoLite2-ASN_20251224/GeoLite2-ASN.mmdb")).ok(),
            active_connections: HashMap::new(),
            connections_rx: None,
            globe_rotation: 0.0,

            traffic_history: VecDeque::from(vec![0; 100]), 
            rx_history: VecDeque::from(vec![0; 100]),
            tx_history: VecDeque::from(vec![0; 100]),
            last_packet_count: 0,
            last_rx_count: 0,
            last_tx_count: 0,

            wan_rx_history: VecDeque::from(vec![0.0; 100]),
            wan_tx_history: VecDeque::from(vec![0.0; 100]),
            lan_rx_history: VecDeque::from(vec![0.0; 100]),
            lan_tx_history: VecDeque::from(vec![0.0; 100]),

            last_wan_rx_bytes: 0,
            last_wan_tx_bytes: 0,
            last_lan_rx_bytes: 0,
            last_lan_tx_bytes: 0,

            connection_count_history: VecDeque::from(vec![0; 100]),


            last_tick_time: std::time::Instant::now(),
            
            db_ping_history: VecDeque::from(vec![0; 100]),
            db_jitter_history: VecDeque::from(vec![0; 100]),
            db_ping_rx: None,
        }
    }

    pub async fn tick(&mut self) {
        if let Some(rx) = &mut self.ping_rx {
            loop {
                match rx.try_recv() {
                    Ok(result) => {
                         if let Ok(ref res) = result {
                             self.ping_rtt_history.push_back(res.time.as_millis() as u64);
                             if self.ping_rtt_history.len() > 100 {
                                 self.ping_rtt_history.pop_front();
                             }
                         }
                         if result.is_ok() {
                             self.ping_history.push_back(result.clone());
                         } else {
                              self.ping_history.push_back(result);
                         }
                         
                         if self.ping_history.len() > 50 {
                             self.ping_history.pop_front();
                         }
                         #[cfg(debug_assertions)]
                         {
                            if self.ping_history.len() > 50 {
                                eprintln!("Ping history exceeded 50 items despite pop");
                            }
                         }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.is_pinging = false;
                        self.ping_rx = None;
                        break;
                    }
                }
            }
        }
        
        if let Some(rx) = &mut self.dns_rx {
            if let Ok(result) = rx.try_recv() {
               self.dns_result = Some(result);
               self.dns_rx = None; // One-shot
            }
        }

        if let Some(rx) = &self.sniffer_rx {
             while let Ok(packet) = rx.try_recv() {
                 self.sniffer_packets.push_back(packet.clone());
                 
                // (Connection tracking moved to dedicated netstat task)

                if self.sniffer_packets.len() > 1000 {
                    self.sniffer_packets.pop_front();
                }
                debug_assert!(self.sniffer_packets.len() <= 1000, "Sniffer packet history exceeded limit");
            }
        }

        // Handle Netstat connections
        if let Some(rx) = &self.connections_rx {
             if let Ok(conns) = rx.try_recv() {
                 let mut new_map = HashMap::new();
                 
                 for c in conns {
                     let clean_remote = c.remote_addr.replace(":", "."); 
                     let parts: Vec<&str> = clean_remote.rsplitn(2, '.').collect();
                     
                     if parts.len() == 2 {
                         let ip_str = parts[1];
                         if let Ok(ip) = ip_str.parse::<IpAddr>() {
                             if !ip.is_loopback() && !ip.is_unspecified() {
                                 let (asn_num, asn_org, location) = if let Some(existing) = self.active_connections.get(&ip) {
                                     (existing.asn_num, existing.asn_org.clone(), existing.location)
                                 } else {
                                      if let Some(reader) = &self.geoip_reader {
                                         reader.lookup_info(ip).unwrap_or((0, "Unknown".to_string(), None))
                                     } else {
                                         (0, "-".to_string(), None)
                                     }
                                 };
                                 
                                 new_map.insert(ip, ConnectionInfo {
                                     remote_ip: ip,
                                     asn_num,
                                     asn_org,
                                     last_seen: std::time::Instant::now(),
                                     packet_count: 0, 
                                     protocol: c.protocol,
                                     location,
                                 });
                             }
                         }
                     }
                 }
                 self.active_connections = new_map;
                 
                 // Update history
                 self.connection_count_history.push_back(self.active_connections.len() as u64);
                 if self.connection_count_history.len() > 100 {
                     self.connection_count_history.pop_front();
                 }
                 debug_assert!(self.connection_count_history.len() <= 100, "Connection count history exceeded limit");
             }
        }
        
        // Rotate Globe
        self.globe_rotation += 0.05;
        if self.globe_rotation > std::f64::consts::PI * 2.0 {
            self.globe_rotation -= std::f64::consts::PI * 2.0;
        }
        debug_assert!(self.globe_rotation >= 0.0, "Globe rotation should differ from negative");
        debug_assert!(self.globe_rotation < std::f64::consts::PI * 4.0, "Globe rotation growing unbounded");

        if let Some(rx) = &self.mtr_rx {
            while let Ok(res) = rx.try_recv() {
                // Update hop stats
                // Check if we have an entry for this TTL
                 if self.mtr_hops.len() < res.ttl as usize {
                    self.mtr_hops.resize(res.ttl as usize, mtr::HopStats {
                        ttl: res.ttl,
                        host: "???".to_string(),
                        sent: 0,
                        recv: 0,
                        last: 0,
                        best: 9999,
                        worst: 0,
                        avg: 0,
                        loss: 0.0,
                        history: VecDeque::new(),
                        jitter: 0,
                    });
                }
                
                let idx = (res.ttl - 1) as usize;
                if let Some(hop) = self.mtr_hops.get_mut(idx) {
                    hop.sent += 1;
                    if res.successful {
                        hop.recv += 1;
                        hop.host = res.host.map(|h| h.to_string()).unwrap_or("???".to_string());
                        let time = res.rtt.as_millis() as u64;
                        
                        // Jitter calc (abs diff from last)
                        let last_time = hop.last;
                        let jitter = if time > last_time { time - last_time } else { last_time - time };
                        // smooth avg jitter
                        if hop.recv > 1 {
                             hop.jitter = ((hop.jitter * (hop.recv - 1)) + jitter) / hop.recv;
                        } else {
                            hop.jitter = jitter;
                        }

                        hop.last = time;
                        if time < hop.best { hop.best = time; }
                        if time > hop.worst { hop.worst = time; }
                        hop.avg = ((hop.avg * (hop.recv - 1)) + time) / hop.recv;
                        
                        hop.history.push_back(time);
                        if hop.history.len() > 100 {
                            hop.history.pop_front();
                        }
                    }
                    hop.loss = ((hop.sent - hop.recv) as f64 / hop.sent as f64) * 100.0;
                }
            }
        }
        if let Some(rx) = &mut self.db_ping_rx {
             while let Ok(result) = rx.try_recv() {
                if let Ok(res) = result {
                     let time = res.time.as_millis() as u64;
                     
                     // Calc Jitter
            let prev_time = *self.db_ping_history.back().unwrap_or(&0);
                     // Careful with u64 sub
                     let jitter = if time > prev_time { time - prev_time } else { prev_time - time };
                     
                     self.db_jitter_history.push_back(jitter);
                      if self.db_jitter_history.len() > 100 {
                         self.db_jitter_history.pop_front();
                     }

                     self.db_ping_history.push_back(time);
                     if self.db_ping_history.len() > 100 {
                         self.db_ping_history.pop_front();
                     }
                }
             }
        }

        if let Some(rx) = &self.nmap_rx {
             while let Ok(line) = rx.try_recv() {
                 self.nmap_output.push_back(line);
                 if self.nmap_output.len() > 1000 {
                     self.nmap_output.pop_front();
                }
             }
        }

        if let Some(rx) = &self.arpscan_rx {
             while let Ok(line) = rx.try_recv() {
                 self.arpscan_output.push_back(line);
                 if self.arpscan_output.len() > 1000 {
                     self.arpscan_output.pop_front();
                }
             }
        }

        // Update Traffic Graph (Total, Rx, Tx)
        let current_count = self.sniffer.packet_count.load(std::sync::atomic::Ordering::Relaxed);
        let current_rx = self.sniffer.in_packets.load(std::sync::atomic::Ordering::Relaxed);
        let current_tx = self.sniffer.out_packets.load(std::sync::atomic::Ordering::Relaxed);
        
        let pps = current_count.saturating_sub(self.last_packet_count);
        let rx_pps = current_rx.saturating_sub(self.last_rx_count);
        let tx_pps = current_tx.saturating_sub(self.last_tx_count);
        
        self.last_packet_count = current_count;
        self.last_rx_count = current_rx;
        self.last_tx_count = current_tx;
        
        self.traffic_history.push_back(pps);
        self.rx_history.push_back(rx_pps);
        self.tx_history.push_back(tx_pps);
        
        if self.traffic_history.len() > 100 { self.traffic_history.pop_front(); }
        if self.rx_history.len() > 100 { self.rx_history.pop_front(); }
        if self.tx_history.len() > 100 { self.tx_history.pop_front(); }

        // Update Bandwidth (Mbps)
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_tick_time).as_secs_f64();
        if elapsed > 0.0 {
            let wan_rx = self.sniffer.wan_in_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let wan_tx = self.sniffer.wan_out_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let lan_rx = self.sniffer.lan_in_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let lan_tx = self.sniffer.lan_out_bytes.load(std::sync::atomic::Ordering::Relaxed);

            let wan_rx_bytes = wan_rx.saturating_sub(self.last_wan_rx_bytes);
            let wan_tx_bytes = wan_tx.saturating_sub(self.last_wan_tx_bytes);
            let lan_rx_bytes = lan_rx.saturating_sub(self.last_lan_rx_bytes);
            let lan_tx_bytes = lan_tx.saturating_sub(self.last_lan_tx_bytes);

            self.last_wan_rx_bytes = wan_rx;
            self.last_wan_tx_bytes = wan_tx;
            self.last_lan_rx_bytes = lan_rx;
            self.last_lan_tx_bytes = lan_tx;

            let mbps_factor = 8.0 / 1_000_000.0 / elapsed;
            
            self.wan_rx_history.push_back(wan_rx_bytes as f64 * mbps_factor);
            self.wan_tx_history.push_back(wan_tx_bytes as f64 * mbps_factor);
            self.lan_rx_history.push_back(lan_rx_bytes as f64 * mbps_factor);
            self.lan_tx_history.push_back(lan_tx_bytes as f64 * mbps_factor);
            
             if self.wan_rx_history.len() > 100 { self.wan_rx_history.pop_front(); }
             if self.wan_tx_history.len() > 100 { self.wan_tx_history.pop_front(); }
             if self.lan_rx_history.len() > 100 { self.lan_rx_history.pop_front(); }
             if self.lan_tx_history.len() > 100 { self.lan_tx_history.pop_front(); }
        }
        self.last_tick_time = now;
    }

    pub fn start_background_tasks(&mut self) {
        // 1. Start Sniffer (Auto-select first interface or loopback)
        if !self.interfaces.is_empty() {
            self.start_sniffer();
        }

        // 2. Start Background Ping (to 1.1.1.1)
        let (tx, rx) = mpsc::channel(100);
        self.db_ping_rx = Some(rx);
        let task = PingTask { target: "1.1.1.1".to_string(), tx };
        tokio::spawn(async move {
            task.run().await;
        });
        
        // 3. Start Connections Monitor
        self.start_connections_monitor();
    }

    pub fn start_sniffer(&mut self) {
        if self.sniffer_active {
            return;
        }
        
        if let Some(interface) = self.interfaces.get(self.selected_interface_index) {
             let (tx, rx) = crossbeam::channel::unbounded();
             self.sniffer_rx = Some(rx);
             
             assert!(self.selected_interface_index < self.interfaces.len(), "Selected interface index out of bounds");
             
             self.sniffer.start(interface.name.clone(), tx);
             self.sniffer_active = true;
        }
    }

    pub fn stop_sniffer(&mut self) {
        if self.sniffer_active {
            self.sniffer.stop();
            self.sniffer_active = false;
        }
    }

    pub fn start_mtr(&mut self) {
        if self.mtr_active { return; }
        
        let target = self.mtr_input.value().to_string();
        if target.is_empty() { return; }
        
        // Ensure we don't start MTR with invalid state even if UI allowed it
        debug_assert!(!target.trim().is_empty(), "MTR target must not be empty/whitespace");

        self.mtr_hops.clear();
        let (tx, rx) = crossbeam::channel::unbounded();
        self.mtr_rx = Some(rx);
        self.mtr_task.start(target, tx);
        self.mtr_active = true;
    }

    pub fn stop_mtr(&mut self) {
        if self.mtr_active {
            self.mtr_task.stop();
            self.mtr_active = false;
        }
    }

    pub fn start_nmap(&mut self) {
        if self.nmap_active { return; }
        
        let target = self.nmap_input.value().to_string();
        if target.is_empty() { return; }

        self.nmap_output.clear();
        self.nmap_output.push_back(format!("Starting nmap scan on: {}", target));
        
        // Use a channel for async output
        let (tx, rx) = crossbeam::channel::unbounded();
        self.nmap_rx = Some(rx);
        self.nmap_active = true;
        
        // Spawn thread for nmap execution
        std::thread::spawn(move || {
            let task = nmap::NmapTask::new(target, tx);
            task.run();
        });
    }

    pub fn get_tool_options(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        // Returns (Flag, Description, Template to Insert)
        match self.current_screen {
            CurrentScreen::Ping => vec![
                ("-i", "Interval (seconds)", " -i 0.5"),
                ("-s", "Payload Size (bytes)", " -s 128"),
                ("-c", "Count (limit)", " -c 5"),
            ],
            CurrentScreen::Mtr => vec![
                ("-i", "Interval (seconds)", " -i 1.0"),
                ("-m", "Max Hops", " -m 30"),
                ("-c", "Cycles", " -c 10"),
            ],
            CurrentScreen::Nmap => vec![
                ("-p", "Ports (e.g. 80,443)", " -p 80,443"),
                ("-F", "Fast Scan", " -F"),
                ("-sV", "Service Version", " -sV"),
                ("-Pn", "No Ping", " -Pn"),
                ("-O", "OS Detection", " -O"),
            ],
            CurrentScreen::ArpScan => vec![
                ("-l", "Localnet", " -l"),
                ("-I <iface>", "Interface", " -I en0"),
                ("-q", "Quiet", " -q"),
                ("-r", "Retry", " -r 3"),
            ],
            _ => vec![]
        }
    }

    pub fn stop_nmap(&mut self) {
        self.nmap_active = false;
        self.nmap_rx = None;
        self.nmap_output.push_back("Scan stopped/detached.".to_string());
    }

    pub fn start_arpscan(&mut self) {
        if self.arpscan_active { return; }
        
        let target = self.arpscan_input.value().to_string();
        if target.is_empty() { return; }

        self.arpscan_output.clear();
        self.arpscan_output.push_back(format!("Starting arp-scan with args: {}", target));
        
        // Use a channel for async output
        let (tx, rx) = crossbeam::channel::unbounded();
        self.arpscan_rx = Some(rx);
        self.arpscan_active = true;
        
        // Spawn thread for arpscan execution
        std::thread::spawn(move || {
            let task = arpscan::ArpScanTask::new(target, tx);
            task.run();
        });
    }

    pub fn stop_arpscan(&mut self) {
        self.arpscan_active = false;
        self.arpscan_rx = None;
        self.arpscan_output.push_back("Scan stopped/detached.".to_string());
    }

    pub fn start_connections_monitor(&mut self) {
        let (tx, rx) = crossbeam::channel::unbounded();
        self.connections_rx = Some(rx);
        let task = connections::ConnectionsTask::new(tx);
        std::thread::spawn(move || {
            task.run();
        });
    }

    // ... ping methods ...

    pub fn next_dns_record_type(&mut self) {
        self.dns_record_type = match self.dns_record_type {
            RecordType::A => RecordType::AAAA,
            RecordType::AAAA => RecordType::MX,
            RecordType::MX => RecordType::TXT,
            RecordType::TXT => RecordType::NS,
            _ => RecordType::A,
        };
    }

    pub fn start_dns_lookup(&mut self) {
        let domain = self.dns_input.value().to_string();
        if domain.is_empty() { return; }
        
        let record_type = self.dns_record_type;
        let (tx, rx) = mpsc::channel(1);
        self.dns_rx = Some(rx);
        self.dns_result = None; // Clear previous

        tokio::spawn(async move {
            let res = dns::resolve(&domain, record_type).await;
            let _ = tx.send(res).await;
        });
    }

    pub fn start_ping(&mut self) {
        if self.is_pinging {
            return; // Already pinging, maybe stop? 
        }
        
        let target = self.ping_input.value().to_string();
        if target.is_empty() {
            return;
        }

        self.ping_history.clear();
        let (tx, rx) = mpsc::channel(100);
        self.ping_rx = Some(rx);
        self.is_pinging = true;

        tokio::spawn(async move {
            let task = PingTask { target, tx };
            task.run().await;
        });
    }
    
    pub fn stop_ping(&mut self) {
        self.is_pinging = false;
        self.ping_rx = None; // Drop receiver, sender will error and stop loop
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}
