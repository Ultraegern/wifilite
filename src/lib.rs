//! # Simple high-level Wi-Fi management and connectivity utilities.
//!
//! This crate provides a simple high-level asynchronous interface for managing Wi-Fi connections on Linux.
//! It includes network scanning, connection management, and data models
//! for representing Wi-Fi networks and interface configurations.
//!
//! ## What this is NOT
//! To ensure you are using the right tool for the job, please note that `wifilite`:
//! * is **not a Network Manager**: This crate is a **thin wrapper** around existing Linux Wi-Fi
//!   backends (such as `wpa_supplicant`). It does not manage DHCP,
//!   routing tables, or DNS.
//! * is **not for Low-level Control**: This crate **is not for you if you need Low-level control** over
//!   low-level 802.11 frames or hardware-specific driver parameters. It is designed for
//!   simple connectivity tasks, not for advanced packet manipulation.
//! * is **not for Real-Time Updates**: This crate is designed for discrete, asynchronous
//!   operations rather than constant telemetry. It provides high-level methods to
//!   [`get_available`](Wifi), [`connect`](Wifi), and [`disconnect`](Wifi); if you require a real-time stream
//!   of signal fluctuations or millisecond-level state changes, this is not the right tool.
//!
//! ## Backends
//! Currently, this crate supports:
//! * `wpa_supplicant` - use [`WpaWifi`](wpa_supplicant::WpaWifi) (Requires the daemon to be running, and permission to use it).
//!
//! Pull Requests are welcome!
//!
//! # Example
//!
//! ```text
//! [dependencies]
//! wifilite = "0.1.0"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! ```no_run
//! use wifilite::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), WifiError> {
//!     // Connect to system
//!     let wifi: WpaWifi = WpaWifi::new("wlan0").await?;
//!     
//!     // List available networks
//!     let networks: Vec<WifiNetwork> = wifi.get_available().await?;
//!     
//!     // Connect to a network
//!     wifi.connect(WifiAuth::Psk {
//!         ssid: "MyNetwork".to_string(),
//!         psk: "password".to_string(),
//!     }).await?;
//!     
//!     // Disconnect
//!     wifi.disconnect().await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod model;
pub mod wpa_supplicant;

pub mod prelude {
    pub use crate::{
        Wifi, WifiAuth, error::WifiError, error::WifiResult, model::WifiNetwork,
        wpa_supplicant::WpaWifi,
    };
}

/// Error types for Wi-Fi operations.
pub mod error {
    use thiserror::Error;

    /// Errors that can occur during Wi-Fi operations.
    ///
    /// This enum represents all possible errors that can be returned when using the Wi-Fi
    /// management interface.
    #[derive(Debug, Error)]
    pub enum WifiError {
        /// Internal error from the underlying Wi-Fi control library.
        #[error("Wifi-Ctrl internal error: {0}")]
        WifiCtrl(#[from] wifi_ctrl::error::Error),

        /// Authentication failed with the specified credentials.
        #[error("Authentication failed for Network '{0}': {1}")]
        AuthFailed(String, String),

        /// The specified network was not found or is out of range.
        #[error("Network '{0}' not found or out of range")]
        NotFound(String),

        /// Connection attempt timed out.
        #[error("Connection timed out after {0} seconds while waiting for association")]
        Timeout(u64),

        /// Unexpectedly disconnected from the network.
        #[error("Unexpectedly disconnected: {0}")]
        Disconnected(String),

        /// The Wi-Fi service is in an invalid state.
        #[error("Invalid service state: {0}")]
        InvalidServiceState(String),

        /// Internal message channel error.
        #[error("Internal message channel error: {0}")]
        MessageChannelError(String),
    }

    /// Result type for Wi-Fi operations.
    pub type WifiResult<T> = std::result::Result<T, WifiError>;
}

use crate::error::WifiResult;
use crate::model::WifiNetwork;

/// Authentication credentials for connecting to a Wi-Fi network.
///
/// Represents the SSID and optional pre-shared key (PSK) needed to connect to a Wi-Fi network.
/// Supports both open networks (no password) and secured networks with PSK authentication.
///
/// # Examples
///
/// Open network:
/// ```
/// use wifilite::WifiAuth;
///
/// let auth = WifiAuth::Open { ssid: "MyWiFi".to_string() };
/// assert_eq!(auth.ssid(), Some("MyWiFi"));
/// assert_eq!(auth.psk(), None);
/// ```
///
/// Secured network:
/// ```
/// use wifilite::WifiAuth;
///
/// let auth = WifiAuth::Psk {
///     ssid: "SecureWiFi".to_string(),
///     psk: "password123".to_string(),
/// };
/// assert_eq!(auth.ssid(), Some("SecureWiFi"));
/// assert_eq!(auth.psk(), Some("password123"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiAuth {
    /// Open Wi-Fi network (no authentication required).
    Open { ssid: String },
    /// Secured Wi-Fi network with pre-shared key.
    Psk { ssid: String, psk: String },
}

impl WifiAuth {
    /// Returns the SSID of the network.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::WifiAuth;
    ///
    /// let auth = WifiAuth::Open { ssid: "TestNet".to_string() };
    /// assert_eq!(auth.ssid(), Some("TestNet"));
    /// ```
    pub fn ssid(&self) -> Option<&str> {
        match self {
            Self::Open { ssid } => Some(ssid),
            Self::Psk { ssid, .. } => Some(ssid),
        }
    }

    /// Returns the pre-shared key (password) if the network is secured.
    ///
    /// Returns `None` for open networks or if no PSK is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::WifiAuth;
    ///
    /// let open = WifiAuth::Open { ssid: "OpenNet".to_string() };
    /// assert_eq!(open.psk(), None);
    ///
    /// let secured = WifiAuth::Psk {
    ///     ssid: "SecureNet".to_string(),
    ///     psk: "secret".to_string(),
    /// };
    /// assert_eq!(secured.psk(), Some("secret"));
    /// ```
    pub fn psk(&self) -> Option<&str> {
        match self {
            Self::Open { .. } => None,
            Self::Psk { psk, .. } => Some(psk),
        }
    }
}

/// Interface for managing Wi-Fi connectivity.
///
/// Implementors provide methods to list networks, connect to networks, and manage connections.
///
/// # Examples
///
/// ```no_run
/// use wifilite::{Wifi, WifiAuth, wpa_supplicant::WpaWifi};
///
/// #[tokio::main]
/// async fn manage_wifi() -> Result<(), Box<dyn std::error::Error>> {
///     let wifi = WpaWifi::new("wlan0").await?;
///     
///     // List available networks
///     let networks = wifi.get_available().await?;
///     
///     // Connect to a network
///     wifi.connect(WifiAuth::Psk {
///         ssid: "MyNetwork".to_string(),
///         psk: "password".to_string(),
///     }).await?;
///     
///     // Disconnect
///     wifi.disconnect().await?;
///     
///     Ok(())
/// }
/// ```
#[allow(async_fn_in_trait)] // only used with concrete types, never dyn
pub trait Wifi {
    /// Scans and returns a list of available Wi-Fi networks.
    ///
    /// Performs a Wi-Fi scan to discover networks in range. Each network is represented
    /// as a [`WifiNetwork`] containing SSID, signal strength, and security information.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan operation fails or communication with the Wi-Fi
    /// backend fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::{Wifi, wpa_supplicant::WpaWifi};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let wifi = WpaWifi::new("wlan0").await?;
    ///     let networks = wifi.get_available().await?;
    ///     for network in networks {
    ///         println!("Found network: {:?}", network.ssid());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    async fn get_available(&self) -> WifiResult<Vec<WifiNetwork>>;

    /// Connects to a Wi-Fi network with the specified authentication credentials.
    ///
    /// Establishes a connection to the Wi-Fi network identified by the SSID in `auth`.
    /// For secured networks, the PSK (password) must be provided.
    ///
    /// The operation will:
    /// 1. Clean up any existing network profiles
    /// 2. Create a new network configuration with the provided credentials
    /// 3. Wait for the connection to be established (up to 20 seconds by default)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The network is not found or out of range
    /// - The credentials are invalid
    /// - The connection times out
    /// - The underlying Wi-Fi backend encounters an error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::{Wifi, WifiAuth, wpa_supplicant::WpaWifi};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let wifi = WpaWifi::new("wlan0").await?;
    ///
    ///     // Connect to an open network
    ///     wifi.connect(WifiAuth::Open {
    ///         ssid: "PublicWiFi".to_string(),
    ///     }).await?;
    ///
    ///     // Connect to a secured network
    ///     wifi.connect(WifiAuth::Psk {
    ///         ssid: "HomeNetwork".to_string(),
    ///         psk: "mypassword".to_string(),
    ///     }).await?;
    ///     Ok(())
    /// }
    /// ```
    async fn connect(&self, auth: WifiAuth) -> WifiResult<()>;

    /// Disconnects from the currently connected Wi-Fi network.
    ///
    /// Terminates the current Wi-Fi connection by removing all network profiles
    /// and waiting for the disconnection to be confirmed by the Wi-Fi backend.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The disconnection process fails
    /// - The backend does not confirm the disconnection within the timeout period (10 seconds)
    /// - There is no active connection
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::{Wifi, wpa_supplicant::WpaWifi};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let wifi = WpaWifi::new("wlan0").await?;
    ///     // ... (after connecting to a network)
    ///     wifi.disconnect().await?;
    ///     Ok(())
    /// }
    /// ```
    async fn disconnect(&self) -> WifiResult<()>;
}
#[cfg(test)]
mod tests {
    use super::*;

    mod wifi_auth {
        use super::*;

        #[test]
        fn open_network_ssid() {
            let auth = WifiAuth::Open {
                ssid: "TestNetwork".to_string(),
            };
            assert_eq!(auth.ssid(), Some("TestNetwork"));
            assert_eq!(auth.psk(), None);
        }

        #[test]
        fn psk_network_ssid_and_psk() {
            let auth = WifiAuth::Psk {
                ssid: "SecureNet".to_string(),
                psk: "password123".to_string(),
            };
            assert_eq!(auth.ssid(), Some("SecureNet"));
            assert_eq!(auth.psk(), Some("password123"));
        }

        #[test]
        fn open_networks_are_equal() {
            let auth1 = WifiAuth::Open {
                ssid: "MyNet".to_string(),
            };
            let auth2 = WifiAuth::Open {
                ssid: "MyNet".to_string(),
            };
            assert_eq!(auth1, auth2);
        }

        #[test]
        fn psk_networks_are_equal() {
            let auth1 = WifiAuth::Psk {
                ssid: "MyNet".to_string(),
                psk: "pass".to_string(),
            };
            let auth2 = WifiAuth::Psk {
                ssid: "MyNet".to_string(),
                psk: "pass".to_string(),
            };
            assert_eq!(auth1, auth2);
        }

        #[test]
        fn different_auth_types_not_equal() {
            let open = WifiAuth::Open {
                ssid: "MyNet".to_string(),
            };
            let psk = WifiAuth::Psk {
                ssid: "MyNet".to_string(),
                psk: "pass".to_string(),
            };
            assert_ne!(open, psk);
        }
    }

    mod wifi_errors {
        use crate::error::WifiError;

        #[test]
        fn error_display_formatting() {
            let err = WifiError::NotFound("NetworkXYZ".to_string());
            assert_eq!(
                err.to_string(),
                "Network 'NetworkXYZ' not found or out of range"
            );

            let err = WifiError::Timeout(30);
            assert_eq!(
                err.to_string(),
                "Connection timed out after 30 seconds while waiting for association"
            );

            let err = WifiError::InvalidServiceState("invalid_state".to_string());
            assert_eq!(err.to_string(), "Invalid service state: invalid_state");
        }
    }
}
