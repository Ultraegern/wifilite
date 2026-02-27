//! WPA Supplicant backend for Wi-Fi management.
//!
//! This module provides a concrete implementation of the [`Wifi`] trait
//! using the wpa_supplicant daemon via the wifi-ctrl library. It manages Wi-Fi connections
//! on Linux systems by communicating with wpa_supplicant through its control interface socket.
//!
//! # Examples
//!
//! ```no_run
//! use wifilite::wpa_supplicant::WpaWifi;
//! use wifilite::{Wifi, WifiAuth};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let wifi = WpaWifi::new("wlan0").await?;
//!
//!     // Scan for available networks
//!     let networks = wifi.get_available().await?;
//!     println!("Found {} networks", networks.len());
//!
//!     // Connect to a network
//!     wifi.connect(WifiAuth::Psk {
//!         ssid: "MyNetwork".to_string(),
//!         psk: "password".to_string(),
//!     }).await?;
//!
//!     Ok(())
//! }
//! ```

use tokio::spawn;
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};
use wifi_ctrl::sta;

use crate::error::{WifiError, WifiResult};
use crate::{Wifi, WifiAuth, model::WifiNetwork};

/// Wi-Fi connection manager using wpa_supplicant backend.
///
/// `WpaWifi` implements the [`Wifi`] trait and manages Wi-Fi connections
/// through the wpa_supplicant daemon. It spawns background tasks to handle events
/// and connection state management.
///
/// # Examples
///
/// ```no_run
/// use wifilite::wpa_supplicant::WpaWifi;
/// use wifilite::Wifi;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let wifi = WpaWifi::new("wlan0").await?;
///     let networks = wifi.get_available().await?;
///     Ok(())
/// }
/// ```
pub struct WpaWifi {
    requester: sta::RequestClient,
    // Broadcast sender to allow connect() to subscribe to events
    event_tx: broadcast::Sender<sta::Broadcast>,
}

impl WpaWifi {
    /// Creates a new Wi-Fi manager instance for the specified interface.
    ///
    /// Connects to the wpa_supplicant control interface for the given network interface
    /// and spawns background tasks to handle event broadcasting and runtime management.
    ///
    /// The wpa_supplicant socket is expected to be located at
    /// `/var/run/wpa_supplicant/<interface>`.
    ///
    /// # Arguments
    ///
    /// * `interface` - The name of the network interface (e.g., "wlan0")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The wpa_supplicant control socket cannot be found
    /// - Connection to the control interface fails
    /// - Any underlying Wi-Fi control setup fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::wpa_supplicant::WpaWifi;
    ///
    /// async fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let wifi = WpaWifi::new("wlan0").await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(interface: &str) -> WifiResult<Self> {
        let wpa_path = format!("/var/run/wpa_supplicant/{}", interface);

        let mut setup = sta::WifiSetup::new()?;
        setup.set_socket_path(wpa_path);

        let broadcast = setup.get_broadcast_receiver();
        let requester = setup.get_request_client();
        let runtime = setup.complete();

        // Initialize a broadcast channel with a reasonable buffer size
        let (event_tx, _) = broadcast::channel(32);

        // Pass the sender to the listener
        spawn(Self::broadcast_listener(broadcast, event_tx.clone()));
        spawn(Self::runtime(runtime));

        Ok(Self {
            requester,
            event_tx,
        })
    }

    async fn runtime(runtime: sta::WifiStation) {
        if let Err(e) = runtime.run().await {
            eprintln!("WpaWifi::runtime: {e}");
        }
    }

    async fn broadcast_listener(
        mut broadcast_receiver: sta::BroadcastReceiver,
        tx: broadcast::Sender<sta::Broadcast>,
    ) {
        while let Ok(broadcast) = broadcast_receiver.recv().await {
            // Forward the event to any active connect() listeners
            let _ = tx.send(broadcast.clone());

            match broadcast {
                sta::Broadcast::Connected => println!("WiFi: Connected to a network"),
                sta::Broadcast::Disconnected => println!("WiFi: Disconnected"),
                sta::Broadcast::WrongPsk => eprintln!("WiFi Error: Incorrect Password"),
                sta::Broadcast::NetworkNotFound => eprintln!("WiFi Error: Network Not Found"),
                sta::Broadcast::Ready => println!("WiFi: wpa_supplicant control interface ready"),
                sta::Broadcast::Unknown(msg) => println!("WiFi: Other: {}", msg),
            }
        }
    }
}

impl Wifi for WpaWifi {
    async fn get_available(&self) -> WifiResult<Vec<WifiNetwork>> {
        let scan_results = self.requester.get_scan().await?;
        let mut networks: Vec<WifiNetwork> = WifiNetwork::group_scan_results(scan_results.to_vec());

        if let Ok(status) = self.requester.get_status().await
            && let Some(active_bssid) = status.get("bssid")
        {
            for net in &mut networks {
                if net.has_bssid(active_bssid) {
                    net.set_connected();
                }
            }
        }
        Ok(networks)
    }

    async fn connect(&self, auth: WifiAuth) -> WifiResult<()> {
        const TIMEOUT_SEC: u64 = 20;

        // 1. Subscribe to events BEFORE starting the connection process
        let mut rx = self.event_tx.subscribe();

        // 2. Clean up existing profiles
        let existing = self.requester.get_networks().await?;
        for net in existing {
            let _ = self.requester.remove_network(net.network_id).await;
        }

        // 3. Setup new network
        let id = self.requester.add_network().await?;
        if let Some(ssid) = auth.ssid() {
            self.requester.set_network_ssid(id, ssid.into()).await?;
        }

        if let Some(psk) = auth.psk() {
            self.requester.set_network_psk(id, psk.into()).await?;
        } else {
            self.requester
                .set_network_keymgmt(id, sta::KeyMgmt::None)
                .await?;
        }

        // 4. Trigger connection (This is the "202 Accepted" part)
        self.requester.select_network(id).await?;

        // 5. Block and wait for the "200 OK" status from the event stream
        // We use a 20-second timeout to prevent hanging forever
        let wait_for_connection = async {
            while let Ok(event) = rx.recv().await {
                match event {
                    sta::Broadcast::Connected => return Ok(()),
                    sta::Broadcast::WrongPsk => {
                        return Err(WifiError::AuthFailed(
                            auth.ssid().unwrap_or("Unknown").into(),
                            "Incorrect Password".into(),
                        ));
                    }
                    sta::Broadcast::NetworkNotFound => {
                        return Err(WifiError::NotFound(auth.ssid().unwrap_or("Unknown").into()));
                    }
                    sta::Broadcast::Disconnected => {
                        return Err(WifiError::Disconnected(
                            "Supplicant dropped connection during handshake".into(),
                        ));
                    }
                    _ => continue, // Ignore other events while waiting
                }
            }
            Err(WifiError::MessageChannelError(
                "Event broadcast stream closed".into(),
            ))
        };

        match timeout(Duration::from_secs(TIMEOUT_SEC), wait_for_connection).await {
            Ok(result) => result,
            Err(_) => Err(WifiError::Timeout(TIMEOUT_SEC)),
        }
    }

    async fn disconnect(&self) -> WifiResult<()> {
        const TIMEOUT_SEC: u64 = 10;

        // 1. Subscribe to events before commanding the hardware
        let mut rx = self.event_tx.subscribe();

        // 2. Fetch and remove all networks
        let networks = self.requester.get_networks().await?;

        // If there are no networks, we are effectively already disconnected
        if networks.is_empty() {
            return Ok(());
        }

        for net in networks {
            let _ = self.requester.remove_network(net.network_id).await;
        }

        // 3. Wait for the Disconnected signal from the broadcast listener
        let wait_for_disconnect = async {
            while let Ok(event) = rx.recv().await {
                match event {
                    // Once we see this, the radio has actually moved to a disconnected state
                    sta::Broadcast::Disconnected => return Ok(()),
                    _ => continue,
                }
            }
            Err(WifiError::MessageChannelError("Event stream closed".into()))
        };

        match timeout(Duration::from_secs(TIMEOUT_SEC), wait_for_disconnect).await {
            Ok(result) => result,
            Err(_) => {
                // If it times out, the networks are removed, but the radio might still
                // be hanging onto the last association.
                Err(WifiError::Timeout(TIMEOUT_SEC))
            }
        }
    }
}
