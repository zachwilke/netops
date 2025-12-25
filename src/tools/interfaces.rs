use pnet_datalink::{self, NetworkInterface};

pub fn get_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}
