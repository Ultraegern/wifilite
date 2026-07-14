# WifiLite

## Simple high-level Wi-Fi management and connectivity utilities

This crate provides a simple high-level async interface for managing Wi-Fi connections on Linux.  
Note that `wifilite` is just an ergonomic wrapper around the various backends.

Feel free to submit feature requests, bug reports, and pull requests on [GitHub](https://github.com/ultraegern/wifilite/issues)

## Backends

Currently, this crate supports:

* `wpa_supplicant` using `WpaWifi`

## Example

```toml
[dependencies]
wifilite = "0.1.1"
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
