use std::process::Command;
use std::thread;
use std::time::Duration;
use crossbeam::channel::Sender;

#[derive(Debug, Clone)]
pub struct RawConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

pub struct ConnectionsTask {
    tx: Sender<Vec<RawConnection>>,
}

impl ConnectionsTask {
    pub fn new(tx: Sender<Vec<RawConnection>>) -> Self {
        Self { tx }
    }

    pub fn run(self) {
        loop {
            let output = Command::new("netstat")
                .args(&["-f", "inet", "-n"])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut connections = Vec::new();

                for line in stdout.lines().skip(2) { // Skip headers
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let proto = parts[0].to_string();
                        // netstat columns vary slightly by OS but usually: Proto Recv Send Local Foreign State
                        // macos: Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
                        
                        let local = parts[3].to_string();
                        let remote = parts[4].to_string();
                        let state = if parts.len() > 5 { parts[5].to_string() } else { "UNKNOWN".to_string() };

                        connections.push(RawConnection {
                            protocol: proto,
                            local_addr: local,
                            remote_addr: remote,
                            state,
                        });
                    }
                }

                if self.tx.send(connections).is_err() {
                    break;
                }
            }

            thread::sleep(Duration::from_secs(2));
        }
    }
}
