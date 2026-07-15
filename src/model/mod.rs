//! Data models for Wi-Fi networks and network interfaces.
//!
//! This module provides types for representing Wi-Fi networks, their security
//! capabilities, connection states, and network interface configurations.

mod ip_conn;
pub mod linux_ip_address;
mod misc;

pub use ip_conn::{Gateway, Ipv4Connection, Ipv6Connection};
pub use misc::{WifiBand, WifiFlag, WifiStatus};

use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    io,
    ops::Deref,
};

/// A map of network interfaces indexed by interface name.
///
/// Provides a convenient container for managing multiple network interfaces
/// and their configurations.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct InterfaceMap(pub BTreeMap<InterfaceName, NetworkInterface>);

/// A Linux network interface name (e.g., "eth0", "wlan0").
///
/// Validates that the interface name is non-empty.
///
/// # Examples
///
/// ```
/// use wifilite::model::InterfaceName;
///
/// let name = InterfaceName::new("wlan0")?;
/// assert_eq!(name.to_string(), "wlan0");
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// Creates a new interface name, validating it is non-empty.
    ///
    /// # Arguments
    ///
    /// * `name` - The interface name (e.g., "wlan0", "eth0")
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::InterfaceName;
    ///
    /// let name = InterfaceName::new("wlan0")?;
    /// assert_eq!(name.to_string(), "wlan0");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn new(name: impl Into<String>) -> io::Result<Self> {
        let name = name.into();
        if name.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interface name must not be empty",
            ))
        } else {
            Ok(InterfaceName(name))
        }
    }
}

impl Deref for InterfaceName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for InterfaceName {
    type Error = io::Error;

    fn try_from(s: String) -> io::Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&str> for InterfaceName {
    type Error = io::Error;

    fn try_from(s: &str) -> io::Result<Self> {
        Self::new(s)
    }
}

/// Configuration and status of a network interface.
///
/// Contains IPv4 and IPv6 address information for a network interface.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    /// Interface name
    name: InterfaceName,
    /// IPv4 addresses assigned to this interface
    ipv4: Vec<Ipv4Connection>,
    /// IPv6 addresses assigned to this interface
    ipv6: Vec<Ipv6Connection>,
}

impl NetworkInterface {
    /// Creates a new network interface configuration.
    ///
    /// # Arguments
    ///
    /// * `name` - The interface name
    /// * `ipv4` - List of IPv4 addresses assigned to this interface
    /// * `ipv6` - List of IPv6 addresses assigned to this interface
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::model::{NetworkInterface, InterfaceName, Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let iface = NetworkInterface::new(
    ///         InterfaceName::new("eth0")?,
    ///         vec![Ipv4Connection::new(
    ///             "192.168.1.100".parse()?,
    ///             24,
    ///             Gateway::Known("192.168.1.1".parse()?),
    ///         )],
    ///         vec![],
    ///     );
    ///     Ok(())
    /// }
    /// ```
    pub fn new(name: InterfaceName, ipv4: Vec<Ipv4Connection>, ipv6: Vec<Ipv6Connection>) -> Self {
        Self { name, ipv4, ipv6 }
    }
}

/// A discovered Wi-Fi network with its properties and capabilities.
///
/// Represents a single Wi-Fi network that can be connected to. Contains the SSID,
/// signal strength, security information, and one or more BSSIDs (physical access points).
///
/// # Examples
///
/// ```no_run
/// use wifilite::model::{WifiNetwork, WifiStatus, WifiBand, WifiFlag};
/// use std::collections::BTreeSet;
///
/// let network = WifiNetwork::new(
///     Some("MyNetwork".to_string()),
///     vec!["AA:BB:CC:DD:EE:FF".to_string()],
///     WifiStatus::Disconnected,
///     Some(-45), // signal strength in dBm
///     Some(WifiBand::Band5Ghz),
///     vec![WifiFlag::Wpa2, WifiFlag::Psk].into_iter().collect(),
/// );
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct WifiNetwork {
    /// Network SSID (name)
    ssid: Option<String>,
    /// List of BSSIDs (MAC addresses of access points broadcasting this SSID)
    bssids: Vec<String>,
    /// Current connection state
    state: WifiStatus,
    /// Strongest signal strength in dBm (negative value, higher is better)
    strength: Option<i32>,
    /// Frequency band of the strongest signal
    band: Option<WifiBand>,
    /// Security and capability flags
    flags: BTreeSet<WifiFlag>,
}

impl WifiNetwork {
    pub fn new(
        ssid: Option<String>,
        bssids: Vec<String>,
        state: WifiStatus,
        strength: Option<i32>,
        band: Option<WifiBand>,
        flags: BTreeSet<WifiFlag>,
    ) -> Self {
        Self {
            ssid,
            bssids,
            state,
            strength,
            band,
            flags,
        }
    }

    /// Returns the SSID if available.
    #[inline]
    pub fn ssid(&self) -> Option<&str> {
        self.ssid.as_deref()
    }

    /// Returns a Slice of BSSIDs associated with this network.
    #[inline]
    pub fn bssids(&self) -> &[String] {
        &self.bssids
    }

    #[inline]
    pub(crate) fn bssids_mut(&mut self) -> &mut Vec<String> {
        &mut self.bssids
    }

    /// Returns an iterator over the BSSIDs associated with this network.
    pub fn bssids_iter(&self) -> impl Iterator<Item = &str> {
        self.bssids.iter().map(|s| s.as_str())
    }

    /// Checks if the given BSSID is associated with this network.
    #[inline]
    pub fn has_bssid(&self, bssid: &str) -> bool {
        self.bssids.iter().any(|s| s == bssid)
    }

    /// Returns the current connection state of this network.
    #[inline]
    pub fn state(&self) -> WifiStatus {
        self.state
    }

    /// Returns the signal strength in dBm if available.
    ///
    /// Higher values (closer to 0) indicate stronger signals.
    #[inline]
    pub fn strength(&self) -> Option<i32> {
        self.strength
    }

    #[inline]
    pub(crate) fn strength_mut(&mut self) -> &mut Option<i32> {
        &mut self.strength
    }

    /// Marks this network as connected.
    #[inline]
    pub(crate) fn set_connected(&mut self) {
        self.state = WifiStatus::Connected;
    }
}

#[cfg(feature = "wpa_supplicant")]
impl From<wifi_ctrl::sta::ScanResult> for WifiNetwork {
    fn from(scan: wifi_ctrl::sta::ScanResult) -> Self {
        Self {
            ssid: Some(scan.name),
            bssids: vec![scan.mac],
            state: WifiStatus::Disconnected,
            strength: Some(scan.signal as i32),
            band: match scan.frequency.parse().ok() {
                Some(freq) => WifiBand::from_freq(freq),
                None => None,
            },
            flags: WifiFlag::parse_wifi_flags(&scan.flags),
        }
    }
}

/// Complete Wi-Fi status response containing network interfaces and available networks.
///
/// This type aggregates information about the system's network interfaces and
/// the available Wi-Fi networks in range.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiStatusResponse {
    /// Map of network interfaces and their configurations
    interfaces: InterfaceMap,
    /// List of available Wi-Fi networks
    wifi_networks: Vec<WifiNetwork>,
}

impl WifiStatusResponse {
    /// Creates a new Wi-Fi status response.
    ///
    /// # Arguments
    ///
    /// * `interfaces` - Map of network interfaces and their configurations
    /// * `wifi_networks` - List of available Wi-Fi networks
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::model::{WifiStatusResponse, InterfaceMap, WifiNetwork};
    ///
    /// let response = WifiStatusResponse::new(
    ///     InterfaceMap(std::collections::BTreeMap::new()),
    ///     vec![],
    /// );
    /// ```
    pub fn new(interfaces: InterfaceMap, wifi_networks: Vec<WifiNetwork>) -> Self {
        Self {
            interfaces,
            wifi_networks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod service_state {
        use super::*;
        #[test]
        fn parses_valid_states() {
            assert_eq!(
                WifiStatus::try_from("disconnected").unwrap(),
                WifiStatus::Disconnected
            );

            assert_eq!(
                WifiStatus::try_from("connected").unwrap(),
                WifiStatus::Connected
            );
        }

        #[test]
        fn rejects_invalid_state() {
            use crate::error::WifiError;

            let err = WifiStatus::try_from("nonsense").unwrap_err();

            match err {
                WifiError::InvalidServiceState(s) => assert_eq!(s, "nonsense"),
                _ => panic!("wrong error variant"),
            }
        }

        #[test]
        fn parses_all_valid_states() {
            assert_eq!(
                WifiStatus::try_from("disconnected").unwrap(),
                WifiStatus::Disconnected
            );
            assert_eq!(
                WifiStatus::try_from("connecting").unwrap(),
                WifiStatus::Connecting
            );
            assert_eq!(
                WifiStatus::try_from("connected").unwrap(),
                WifiStatus::Connected
            );
            assert_eq!(
                WifiStatus::try_from("disconnecting").unwrap(),
                WifiStatus::Disconnecting
            );
        }
    }

    mod wifi_network {
        use super::*;
        use std::collections::BTreeSet;

        #[test]
        fn wifi_network_creation() {
            let mut flags = BTreeSet::new();
            flags.insert(WifiFlag::Wpa2);
            flags.insert(WifiFlag::Psk);

            let network = WifiNetwork::new(
                Some("TestNet".to_string()),
                vec!["aa:bb:cc:dd:ee:ff".to_string()],
                WifiStatus::Disconnected,
                Some(-50),
                Some(WifiBand::Band2G4Hz),
                flags,
            );

            assert_eq!(network.ssid(), Some("TestNet"));
            assert_eq!(network.strength(), Some(-50));
            assert_eq!(network.state(), WifiStatus::Disconnected);
        }

        #[test]
        fn has_bssid() {
            let network = WifiNetwork::new(
                Some("TestNet".to_string()),
                vec![
                    "aa:bb:cc:dd:ee:ff".to_string(),
                    "11:22:33:44:55:66".to_string(),
                ],
                WifiStatus::Disconnected,
                Some(-50),
                None,
                BTreeSet::new(),
            );

            assert!(network.has_bssid("aa:bb:cc:dd:ee:ff"));
            assert!(network.has_bssid("11:22:33:44:55:66"));
            assert!(!network.has_bssid("ff:ff:ff:ff:ff:ff"));
        }

        #[test]
        fn set_connected_changes_state() {
            let mut network = WifiNetwork::new(
                Some("TestNet".to_string()),
                vec!["aa:bb:cc:dd:ee:ff".to_string()],
                WifiStatus::Disconnected,
                Some(-50),
                None,
                BTreeSet::new(),
            );

            assert_eq!(network.state(), WifiStatus::Disconnected);
            network.set_connected();
            assert_eq!(network.state(), WifiStatus::Connected);
        }

        #[test]
        fn bssids() {
            let bssids_vec = vec![
                "aa:bb:cc:dd:ee:ff".to_string(),
                "11:22:33:44:55:66".to_string(),
            ];
            let network = WifiNetwork::new(
                Some("TestNet".to_string()),
                bssids_vec.clone(),
                WifiStatus::Disconnected,
                Some(-50),
                None,
                BTreeSet::new(),
            );

            let bssids = network.bssids();
            assert_eq!(bssids.len(), 2);
            assert_eq!(bssids[0], "aa:bb:cc:dd:ee:ff");
            assert_eq!(bssids[1], "11:22:33:44:55:66");
        }

        #[test]
        fn bssids_iter() {
            let bssids_vec = vec![
                "aa:bb:cc:dd:ee:ff".to_string(),
                "11:22:33:44:55:66".to_string(),
            ];
            let network = WifiNetwork::new(
                Some("TestNet".to_string()),
                bssids_vec.clone(),
                WifiStatus::Disconnected,
                Some(-50),
                None,
                BTreeSet::new(),
            );

            let bssids: Vec<&str> = network.bssids_iter().collect();
            assert_eq!(bssids.len(), 2);
            assert_eq!(bssids[0], "aa:bb:cc:dd:ee:ff");
            assert_eq!(bssids[1], "11:22:33:44:55:66");
        }
    }

    mod interface_name {
        use super::*;
        use std::io;

        #[test]
        fn valid_interface_name() {
            let name = InterfaceName::new("eth0").unwrap();
            assert_eq!(name.deref(), "eth0");
        }

        #[test]
        fn empty_interface_name_fails() {
            let result = InterfaceName::new("");
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn interface_name_from_string() {
            let name = InterfaceName::try_from("wlan0".to_string()).unwrap();
            assert_eq!(name.deref(), "wlan0");
        }

        #[test]
        fn interface_name_from_str() {
            let name = InterfaceName::try_from("lo").unwrap();
            assert_eq!(name.deref(), "lo");
        }

        #[test]
        fn interface_name_display() {
            let name = InterfaceName::new("eth0").unwrap();
            assert_eq!(name.to_string(), "eth0");
        }

        #[test]
        fn interface_name_ordering() {
            let name1 = InterfaceName::new("eth0").unwrap();
            let name2 = InterfaceName::new("eth1").unwrap();
            let name3 = InterfaceName::new("wlan0").unwrap();

            assert!(name1 < name2);
            assert!(name2 < name3);
        }
    }

    mod gateway_serialization {
        use super::*;
        use serde_json::json;

        #[test]
        fn serialize_gateway_none() {
            let gateway: Gateway<std::net::Ipv4Addr> = Gateway::None;
            let value = serde_json::to_value(gateway).unwrap();
            assert_eq!(value, json!("none"));
        }

        #[test]
        fn serialize_gateway_unknown() {
            let gateway: Gateway<std::net::Ipv4Addr> = Gateway::Unknown;
            let value = serde_json::to_value(gateway).unwrap();
            assert_eq!(value, json!("unknown"));
        }

        #[test]
        fn serialize_gateway_known() {
            let gateway = Gateway::Known(std::net::Ipv4Addr::new(192, 168, 1, 1));
            let value = serde_json::to_value(gateway).unwrap();
            assert_eq!(value, json!("192.168.1.1"));
        }
    }
}
