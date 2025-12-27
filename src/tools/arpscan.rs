use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use crossbeam::channel::Sender;

#[derive(Clone, Debug)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
}

pub struct ArpScanTask {
    pub target: String,
    pub tx: Sender<String>,
}

impl ArpScanTask {
    pub fn new(target: String, tx: Sender<String>) -> Self {
        Self { target, tx }
    }

    pub fn run(&self) {
        let args: Vec<&str> = self.target.split_whitespace().collect();
        
        // sudo is often needed for arp-scan due to raw socket usage
        // But the main app is run with sudo, so child process inherits permissions.
        let mut cmd = Command::new("arp-scan");
        cmd.args(&args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take().expect("Failed to capture stdout");
                let stderr = child.stderr.take().expect("Failed to capture stderr");

                let tx_out = self.tx.clone();
                let tx_err = self.tx.clone();

                // Stream stdout
                std::thread::spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        if let Ok(l) = line {
                            let _ = tx_out.send(l);
                        }
                    }
                });

                // Stream stderr
                std::thread::spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        if let Ok(l) = line {
                            let _ = tx_err.send(format!("ERR: {}", l));
                        }
                    }
                });
                
                // Wait for process to finish
                let _ = child.wait();
                let _ = self.tx.send("Done.".to_string());
            }
            Err(e) => {
                let _ = self.tx.send(format!("Failed to start arp-scan: {}", e));
                let _ = self.tx.send("Ensure 'arp-scan' is installed and in your PATH.".to_string());
            }
        }
    }
}
