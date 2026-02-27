# WifiLite
## Simple high-level Wi-Fi management and connectivity utilities.

This crate provides a simple high-level asynchronous interface for managing Wi-Fi connections on Linux.
It includes network scanning, connection management, and data models
for representing Wi-Fi networks and interface configurations.

## What this is NOT
To ensure you are using the right tool for the job, please note that `wifilite`:
* is **not a Network Manager**: This crate is a **thin wrapper** around existing Linux Wi-Fi
  backends (such as `wpa_supplicant`). It does not manage DHCP,
  routing tables, or DNS.
* is **not for Low-level Control**: This crate **is not for you if you need Low-level control** over
  low-level 802.11 frames or hardware-specific driver parameters. It is designed for
  simple connectivity tasks, not for advanced packet manipulation.
* is **not for Real-Time Updates**: This crate is designed for discrete, asynchronous
  operations rather than constant telemetry. It provides high-level methods to
  `get_available`, `connect`, and `disconnect`; if you require a real-time stream
  of signal fluctuations or millisecond-level state changes, this is not the right tool.

## Backends
Currently, this crate supports:
* `wpa_supplicant` - use `WpaWifi` (Requires the daemon to be running, and permission to use it).

Pull Requests are welcome!

# Example

```toml
[dependencies]
wifilite = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

```rust
use wifilite::prelude::*;

#[tokio::main]
async fn main() -> Result<(), WifiError> {
    // Connect to system
    let wifi: WpaWifi = WpaWifi::new("wlan0").await?;
    
    // List available networks
    let networks: Vec<WifiNetwork> = wifi.get_available().await?;
    
    // Connect to a network
    wifi.connect(WifiAuth::Psk {
        ssid: "MyNetwork".to_string(),
        psk: "password".to_string(),
    }).await?;
    
    // Disconnect
    wifi.disconnect().await?;
    
    Ok(())
}
```
