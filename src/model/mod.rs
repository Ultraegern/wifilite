//! Data models for Wi-Fi networks and network interfaces.
//!
//! This module provides types for representing Wi-Fi networks, their security
//! capabilities, connection states, and network interface configurations.

pub mod linux_ip_address;

use crate::error::WifiError;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    io,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};
use wifi_ctrl::sta;

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

/// A map of network interfaces indexed by interface name.
///
/// Provides a convenient container for managing multiple network interfaces
/// and their configurations.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct InterfaceMap(pub BTreeMap<InterfaceName, NetworkInterface>);

/// Wi-Fi network security and capability flags.
///
/// Indicates which security protocols and features are supported by a network.
///
/// # Examples
///
/// ```
/// use wifilite::model::WifiFlag;
///
/// // These would typically be parsed from network scan results
/// let flags = vec![WifiFlag::Wpa2, WifiFlag::Psk];
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WifiFlag {
    /// WPA (Wi-Fi Protected Access) security protocol
    Wpa,
    /// WPA2 security protocol
    Wpa2,
    /// WPA3 security protocol (latest standard)
    Wpa3,
    /// Pre-Shared Key (personal/home network authentication)
    Psk,
    /// Enterprise authentication (login/identity based)
    Eap,
    /// CCMP encryption (AES, modern standard)
    Ccmp,
    /// TKIP encryption (legacy encryption method)
    Tkip,
    /// ESS (Extended Service Set) - Infrastructure mode with access point
    Ess,
    /// IBSS (Independent Basic Service Set) - Ad-hoc/peer-to-peer mode
    Ibss,
    /// Wi-Fi Protected Setup (PIN/button pairing)
    Wps,
    /// Other/unknown capability flag
    #[serde(untagged)]
    Other(String),
}

/// Wi-Fi frequency band designation.
///
/// Indicates which frequency band a network operates on.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum WifiBand {
    /// 2.4 GHz band (typical for older devices and longer range)
    #[serde(rename = "2.4GHz")]
    Band2G4Hz,
    /// 5 GHz band (faster speeds, shorter range)
    #[serde(rename = "5GHz")]
    Band5Ghz,
    /// 6 GHz band (Wi-Fi 6E and newer)
    #[serde(rename = "6GHz")]
    Band6Ghz,
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

/// Connection state of a Wi-Fi network.
///
/// # Examples
///
/// ```
/// use wifilite::model::WifiStatus;
///
/// let status = WifiStatus::Connected;
/// assert_eq!(status, WifiStatus::Connected);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WifiStatus {
    /// Not connected to this network
    Disconnected,
    /// In the process of connecting
    Connecting,
    /// Successfully connected
    Connected,
    /// In the process of disconnecting
    Disconnecting,
}

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

/// Representation of a network gateway.
///
/// Indicates whether a gateway is present, unknown, or explicitly none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gateway<T> {
    /// No gateway is configured
    None,
    /// Gateway with a known address
    Known(T),
    /// Gateway status is unknown
    Unknown,
}

/// An IPv4 network connection with address, prefix length, and optional gateway.
///
/// # Examples
///
/// ```
/// use wifilite::model::{Ipv4Connection, Gateway};
/// use std::net::Ipv4Addr;
///
/// let connection = Ipv4Connection::new(
///     "192.168.1.100".parse()?,
///     24,
///     Gateway::Known("192.168.1.1".parse()?),
/// );
/// # Ok::<(), std::net::AddrParseError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Connection {
    /// IPv4 address
    address: Ipv4Addr,
    /// Prefix length (CIDR notation, 0-32)
    prefix: u8,
    /// Gateway address
    gateway: Gateway<Ipv4Addr>,
}

/// An IPv6 network connection with address, prefix length, and optional gateway.
///
/// Similar to [`Ipv4Connection`] but for IPv6 addresses.
///
/// # Examples
///
/// ```
/// use wifilite::model::{Ipv6Connection, Gateway};
/// use std::net::Ipv6Addr;
///
/// let connection = Ipv6Connection::new(
///     "2001:db8::1".parse()?,
///     64,
///     Gateway::Unknown,
/// );
/// # Ok::<(), std::net::AddrParseError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Ipv6Connection {
    /// IPv6 address
    address: Ipv6Addr,
    /// Prefix length (CIDR notation, 0-128)
    prefix: u8,
    /// Gateway address
    gateway: Gateway<Ipv6Addr>,
}

impl WifiBand {
    /// Determines the Wi-Fi band from a frequency in MHz.
    ///
    /// Maps 802.11 channel frequencies to their corresponding Wi-Fi bands.
    ///
    /// # Arguments
    ///
    /// * `freq` - Frequency in MHz
    ///
    /// # Returns
    ///
    /// The corresponding Wi-Fi band, or `None` if the frequency doesn't match any band.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::WifiBand;
    ///
    /// // 2.4 GHz band
    /// assert_eq!(WifiBand::from_freq(2437), Some(WifiBand::Band2G4Hz));
    ///
    /// // 5 GHz band
    /// assert_eq!(WifiBand::from_freq(5180), Some(WifiBand::Band5Ghz));
    ///
    /// // 6 GHz band
    /// assert_eq!(WifiBand::from_freq(6000), Some(WifiBand::Band6Ghz));
    ///
    /// // Invalid frequency
    /// assert_eq!(WifiBand::from_freq(9999), None);
    /// ```
    pub fn from_freq(freq: i32) -> Option<Self> {
        match freq {
            2412..=2484 => Some(WifiBand::Band2G4Hz),
            5160..=5885 => Some(WifiBand::Band5Ghz),
            5925..=7125 => Some(WifiBand::Band6Ghz),
            _ => None,
        }
    }
}

impl From<sta::ScanResult> for WifiNetwork {
    fn from(scan: sta::ScanResult) -> Self {
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

impl WifiFlag {
    fn parse_wifi_flags(raw_flags: &str) -> BTreeSet<Self> {
        let mut flags = BTreeSet::new();

        // Clean the string (remove brackets and split by dash/space)
        let cleaned = raw_flags.replace('[', "").replace(']', " ");
        let parts: Vec<&str> = cleaned
            .split_whitespace()
            .flat_map(|s| s.split('-'))
            .collect();

        for part in parts {
            match part.to_uppercase().as_str() {
                "WPA" => flags.insert(WifiFlag::Wpa),
                "WPA2" => flags.insert(WifiFlag::Wpa2),
                "WPA3" => flags.insert(WifiFlag::Wpa3),
                "PSK" => flags.insert(WifiFlag::Psk),
                "EAP" => flags.insert(WifiFlag::Eap),
                "CCMP" => flags.insert(WifiFlag::Ccmp),
                "TKIP" => flags.insert(WifiFlag::Tkip),
                "ESS" => flags.insert(WifiFlag::Ess),
                "IBSS" => flags.insert(WifiFlag::Ibss),
                "WPS" => flags.insert(WifiFlag::Wps),
                _ => {
                    if !part.is_empty() {
                        flags.insert(WifiFlag::Other(part.to_string()));
                    }
                    true
                }
            };
        }
        flags
    }
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

impl<T> Serialize for Gateway<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Gateway::None => serializer.serialize_str("none"),
            Gateway::Unknown => serializer.serialize_str("unknown"),
            Gateway::Known(value) => value.serialize(serializer),
        }
    }
}

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

impl WifiNetwork {
    /// Creates a new Wi-Fi network entry.
    ///
    /// # Arguments
    ///
    /// * `ssid` - Network SSID (name)
    /// * `bssids` - MAC addresses of access points broadcasting this network
    /// * `state` - Current connection state
    /// * `strength` - Signal strength in dBm (optional)
    /// * `band` - Frequency band (optional)
    /// * `flags` - Security and capability flags
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

    /// Groups scan results by SSID, keeping the strongest signal for each network.
    ///
    /// Takes raw scan results and merges entries with the same SSID, updating
    /// signal strength to reflect the strongest signal observed across all BSSIDs.
    ///
    /// # Arguments
    ///
    /// * `scans` - Raw Wi-Fi scan results
    ///
    /// # Returns
    ///
    /// A deduplicated list of networks, one per unique SSID.
    pub fn group_scan_results(scans: Vec<sta::ScanResult>) -> Vec<WifiNetwork> {
        let mut grouped: BTreeMap<String, WifiNetwork> = BTreeMap::new();

        for scan in scans {
            let ssid = scan.name.clone();

            if let Some(network) = grouped.get_mut(&ssid) {
                // If the SSID exists, add this BSSID to the list
                network.bssids.push(scan.mac.clone());

                // Update strength to show the strongest signal of the group
                if let Some(current_strength) = network.strength
                    && (scan.signal as i32) > current_strength
                {
                    network.strength = Some(scan.signal as i32);
                }
            } else {
                // Otherwise, create a new entry using our From implementation
                grouped.insert(ssid, WifiNetwork::from(scan));
            }
        }

        grouped.into_values().collect()
    }

    /// Returns the SSID (network name) if available.
    ///
    /// # Examples
    ///
    /// ```
    /// # use wifilite::model::{WifiNetwork, WifiStatus};
    /// # use std::collections::BTreeSet;
    /// let network = WifiNetwork::new(
    ///     Some("MyNet".to_string()),
    ///     vec![],
    ///     WifiStatus::Disconnected,
    ///     None,
    ///     None,
    ///     BTreeSet::new()
    /// );
    /// assert_eq!(network.ssid(), Some("MyNet"));
    /// ```
    pub fn ssid(&self) -> Option<&str> {
        self.ssid.as_deref()
    }

    /// Returns an iterator over the BSSIDs (MAC addresses) for this network.
    ///
    /// # Examples
    ///
    /// ```
    /// # use wifilite::model::{WifiNetwork, WifiStatus};
    /// # use std::collections::BTreeSet;
    /// let network = WifiNetwork::new(
    ///     Some("MyNet".to_string()),
    ///     vec!["AA:BB:CC:DD:EE:FF".to_string()],
    ///     WifiStatus::Disconnected,
    ///     None,
    ///     None,
    ///     BTreeSet::new(),
    /// );
    /// assert_eq!(
    ///     network.bssids().collect::<Vec<_>>(),
    ///     vec!["AA:BB:CC:DD:EE:FF"])
    /// ;
    /// ```
    pub fn bssids(&self) -> impl Iterator<Item = &str> {
        self.bssids.iter().map(|s| s.as_str())
    }

    /// Returns the current connection state of this network.
    pub fn state(&self) -> WifiStatus {
        self.state
    }

    /// Returns the signal strength in dBm if available.
    ///
    /// Higher values (closer to 0) indicate stronger signals.
    pub fn strength(&self) -> Option<i32> {
        self.strength
    }

    /// Marks this network as connected.
    ///
    /// Used internally to update the network state after verifying a connection.
    pub(crate) fn set_connected(&mut self) {
        self.state = WifiStatus::Connected;
    }

    /// Checks if the given BSSID is one of the access points for this network.
    ///
    /// # Arguments
    ///
    /// * `bssid` - The BSSID (MAC address) to check
    pub fn has_bssid(&self, bssid: &str) -> bool {
        self.bssids.contains(&bssid.to_string())
    }
}

impl Ipv4Connection {
    /// Creates a new IPv4 connection configuration.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv4 address
    /// * `prefix` - The prefix length (0-32) in CIDR notation
    /// * `gateway` - The gateway address (if any)
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Ipv4Connection::new(
    ///     "192.168.1.100".parse()?,
    ///     24,
    ///     Gateway::Known("192.168.1.1".parse()?),
    /// );
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn new(address: Ipv4Addr, prefix: u8, gateway: Gateway<Ipv4Addr>) -> Self {
        Self {
            address,
            prefix,
            gateway,
        }
    }

    /// Creates a new IPv4 connection from an address and netmask.
    ///
    /// Converts the netmask to prefix length format automatically.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv4 address
    /// * `netmask` - The netmask (e.g., 255.255.255.0)
    /// * `gateway` - The gateway address (if any)
    ///
    /// # Errors
    ///
    /// Returns an error if the netmask is invalid (not a contiguous sequence of 1 bits).
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Ipv4Connection::new_from_netmask(
    ///     "192.168.1.100".parse()?,
    ///     "255.255.255.0".parse()?,
    ///     Gateway::Known("192.168.1.1".parse()?),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new_from_netmask(
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Gateway<Ipv4Addr>,
    ) -> io::Result<Self> {
        let prefix = Self::netmask_to_prefix(netmask)?;

        Ok(Self {
            address,
            prefix,
            gateway,
        })
    }

    fn netmask_to_prefix(netmask: Ipv4Addr) -> io::Result<u8> {
        let octets = netmask.octets();
        let mut prefix = 0;
        for &octet in &octets {
            let mut bits = octet;
            while bits & 0x80 != 0 {
                prefix += 1;
                bits <<= 1;
            }
            if bits != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Could not convert netmask {} to prefix", netmask),
                ));
            }
        }
        Ok(prefix)
    }

    /// Returns the IPv4 address.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// let addr = "192.168.1.100".parse::<Ipv4Addr>()?;
    /// let conn = Ipv4Connection::new(addr, 24, Gateway::None);
    /// assert_eq!(conn.address(), addr);
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Returns the prefix length (CIDR notation).
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns the gateway configuration.
    pub fn gateway(&self) -> Gateway<Ipv4Addr> {
        self.gateway
    }

    /// Returns the address in CIDR notation (e.g., "192.168.1.100/24").
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Ipv4Connection::new(
    ///     "192.168.1.100".parse()?,
    ///     24,
    ///     Gateway::None,
    /// );
    /// assert_eq!(conn.cidr(), "192.168.1.100/24");
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }

    /// Calculates the netmask from the prefix length.
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv4Connection, Gateway};
    /// use std::net::Ipv4Addr;
    ///
    /// let conn = Ipv4Connection::new(
    ///     "192.168.1.100".parse()?,
    ///     24,
    ///     Gateway::None,
    /// );
    /// let expected: Ipv4Addr = "255.255.255.0".parse()?;
    /// assert_eq!(conn.netmask(), expected);
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn netmask(&self) -> Ipv4Addr {
        if self.prefix == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }

        let mask = u32::MAX << (32 - self.prefix);
        Ipv4Addr::from(mask)
    }
}

impl Ipv6Connection {
    /// Creates a new IPv6 connection configuration.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv6 address
    /// * `prefix` - The prefix length (0-128) in CIDR notation
    /// * `gateway` - The gateway address (if any)
    ///
    /// # Examples
    ///
    /// ```
    /// use wifilite::model::{Ipv6Connection, Gateway};
    /// use std::net::Ipv6Addr;
    ///
    /// let conn = Ipv6Connection::new(
    ///     "2001:db8::1".parse()?,
    ///     64,
    ///     Gateway::Unknown,
    /// );
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    pub fn new(address: Ipv6Addr, prefix: u8, gateway: Gateway<Ipv6Addr>) -> Self {
        Self {
            address,
            prefix,
            gateway,
        }
    }

    /// Returns the IPv6 address.
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Returns the prefix length (CIDR notation).
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns the gateway configuration.
    pub fn gateway(&self) -> Gateway<Ipv6Addr> {
        self.gateway
    }

    /// Returns the address in CIDR notation (e.g., "2001:db8::1/64").
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }
}

impl Serialize for Ipv4Connection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Ipv4Connection", 2)?;
        s.serialize_field("address", &self.cidr())?;
        s.serialize_field("gateway", &self.gateway)?;
        s.end()
    }
}

impl Serialize for Ipv6Connection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Ipv6Connection", 2)?;
        s.serialize_field("address", &self.cidr())?;
        s.serialize_field("gateway", &self.gateway)?;
        s.end()
    }
}

impl TryFrom<&str> for WifiStatus {
    type Error = WifiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "disconnected" => Ok(Self::Disconnected),
            "connecting" => Ok(Self::Connecting),
            "connected" => Ok(Self::Connected),
            "disconnecting" => Ok(Self::Disconnecting),
            other => Err(WifiError::InvalidServiceState(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod ipv4 {
        use super::*;
        use serde_json::json;
        use std::net::Ipv4Addr;

        #[test]
        fn host_cidr_is_correct() {
            let ipv4 = Ipv4Connection {
                address: Ipv4Addr::new(192, 168, 1, 42),
                prefix: 24,
                gateway: Gateway::Known(Ipv4Addr::new(192, 168, 1, 1)),
            };

            assert_eq!(ipv4.cidr(), "192.168.1.42/24");
        }

        #[test]
        fn netmask_is_correct() {
            let ipv4 = Ipv4Connection {
                address: Ipv4Addr::new(10, 0, 0, 5),
                prefix: 16,
                gateway: Gateway::Unknown,
            };

            assert_eq!(ipv4.netmask(), Ipv4Addr::new(255, 255, 0, 0));
        }

        #[test]
        fn serialization_shape_is_stable() {
            let ipv4 = Ipv4Connection {
                address: Ipv4Addr::new(192, 168, 0, 10),
                prefix: 16,
                gateway: Gateway::Known(Ipv4Addr::new(192, 168, 0, 1)),
            };

            let value = serde_json::to_value(&ipv4).unwrap();

            assert_eq!(
                value,
                json!({
                    "address": "192.168.0.10/16",
                    "gateway": "192.168.0.1"
                })
            );
        }
    }

    mod ipv6 {
        use super::*;
        use serde_json::json;
        use std::net::Ipv6Addr;

        #[test]
        fn host_cidr_is_correct() {
            let ipv6 = Ipv6Connection {
                address: Ipv6Addr::new(
                    0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0xdead, 0xbeef,
                ),
                prefix: 64,
                gateway: Gateway::None,
            };

            assert_eq!(ipv6.cidr(), "2001:db8::dead:beef/64");
        }

        #[test]
        fn serialization_shape_is_stable() {
            let ipv6 = Ipv6Connection {
                address: Ipv6Addr::new(
                    0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
                ),
                prefix: 64,
                gateway: Gateway::Known(Ipv6Addr::new(
                    0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00ff,
                )),
            };

            let value = serde_json::to_value(&ipv6).unwrap();

            assert_eq!(
                value,
                json!({
                    "address": "fe80::1/64",
                    "gateway": "fe80::ff"
                })
            );
        }
    }

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

    mod wifi_flag_parsing {
        use super::*;

        #[test]
        fn parses_wpa2_psk_flags() {
            let flags = WifiFlag::parse_wifi_flags("[WPA2-PSK-CCMP]");
            assert!(flags.contains(&WifiFlag::Wpa2));
            assert!(flags.contains(&WifiFlag::Psk));
            assert!(flags.contains(&WifiFlag::Ccmp));
        }

        #[test]
        fn parses_wpa3_eap_flags() {
            let flags = WifiFlag::parse_wifi_flags("[WPA3-EAP-CCMP]");
            assert!(flags.contains(&WifiFlag::Wpa3));
            assert!(flags.contains(&WifiFlag::Eap));
            assert!(flags.contains(&WifiFlag::Ccmp));
        }

        #[test]
        fn parses_open_network_flags() {
            let flags = WifiFlag::parse_wifi_flags("[ESS]");
            assert!(flags.contains(&WifiFlag::Ess));
            assert!(!flags.contains(&WifiFlag::Psk));
            assert!(!flags.contains(&WifiFlag::Wpa));
        }

        #[test]
        fn handles_empty_flags() {
            let flags = WifiFlag::parse_wifi_flags("");
            assert!(flags.is_empty());
        }

        #[test]
        fn handles_brackets_and_spaces() {
            let flags = WifiFlag::parse_wifi_flags("[WPA-PSK] [CCMP] [TKIP]");
            assert!(flags.contains(&WifiFlag::Wpa));
            assert!(flags.contains(&WifiFlag::Psk));
            assert!(flags.contains(&WifiFlag::Ccmp));
            assert!(flags.contains(&WifiFlag::Tkip));
        }

        #[test]
        fn stores_unknown_flags() {
            let flags = WifiFlag::parse_wifi_flags("[CUSTOM-FLAG]");
            assert!(flags.contains(&WifiFlag::Other("CUSTOM".to_string())));
            assert!(flags.contains(&WifiFlag::Other("FLAG".to_string())));
        }
    }

    mod wifi_band_frequency {
        use super::*;

        #[test]
        fn frequency_to_2_4ghz_band() {
            assert_eq!(WifiBand::from_freq(2412), Some(WifiBand::Band2G4Hz));
            assert_eq!(WifiBand::from_freq(2437), Some(WifiBand::Band2G4Hz));
            assert_eq!(WifiBand::from_freq(2484), Some(WifiBand::Band2G4Hz));
        }

        #[test]
        fn frequency_to_5ghz_band() {
            assert_eq!(WifiBand::from_freq(5160), Some(WifiBand::Band5Ghz));
            assert_eq!(WifiBand::from_freq(5500), Some(WifiBand::Band5Ghz));
            assert_eq!(WifiBand::from_freq(5885), Some(WifiBand::Band5Ghz));
        }

        #[test]
        fn frequency_to_6ghz_band() {
            assert_eq!(WifiBand::from_freq(5925), Some(WifiBand::Band6Ghz));
            assert_eq!(WifiBand::from_freq(6425), Some(WifiBand::Band6Ghz));
            assert_eq!(WifiBand::from_freq(7125), Some(WifiBand::Band6Ghz));
        }

        #[test]
        fn invalid_frequencies() {
            assert_eq!(WifiBand::from_freq(1000), None);
            assert_eq!(WifiBand::from_freq(100000), None);
            assert_eq!(WifiBand::from_freq(5900), None);
        }

        #[test]
        fn boundary_frequencies() {
            assert_eq!(WifiBand::from_freq(2411), None); // below 2.4GHz
            assert_eq!(WifiBand::from_freq(2485), None); // above 2.4GHz
            assert_eq!(WifiBand::from_freq(5159), None); // below 5GHz
            assert_eq!(WifiBand::from_freq(5886), None); // above 5GHz
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
        fn bssids_iterator() {
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

            let bssids: Vec<&str> = network.bssids().collect();
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

    mod ipv4_netmask {
        use super::*;
        use std::net::Ipv4Addr;

        #[test]
        fn convert_netmask_to_prefix_24() {
            let result =
                Ipv4Connection::netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)).unwrap();
            assert_eq!(result, 24);
        }

        #[test]
        fn convert_netmask_to_prefix_16() {
            let result = Ipv4Connection::netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)).unwrap();
            assert_eq!(result, 16);
        }

        #[test]
        fn convert_netmask_to_prefix_8() {
            let result = Ipv4Connection::netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)).unwrap();
            assert_eq!(result, 8);
        }

        #[test]
        fn convert_netmask_to_prefix_32() {
            let result =
                Ipv4Connection::netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)).unwrap();
            assert_eq!(result, 32);
        }

        #[test]
        fn convert_netmask_to_prefix_0() {
            let result = Ipv4Connection::netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)).unwrap();
            assert_eq!(result, 0);
        }

        #[test]
        fn netmask_round_trip() {
            // Test that converting from prefix to netmask and back gives the same result
            for prefix in [8, 16, 24, 30, 32] {
                let conn =
                    Ipv4Connection::new(Ipv4Addr::new(192, 168, 0, 0), prefix, Gateway::Unknown);
                let netmask = conn.netmask();
                let result_prefix = Ipv4Connection::netmask_to_prefix(netmask).unwrap();
                assert_eq!(result_prefix, prefix, "Failed for prefix {}", prefix);
            }
        }

        #[test]
        fn from_netmask_creates_correct_prefix() {
            let conn = Ipv4Connection::new_from_netmask(
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(255, 255, 255, 0),
                Gateway::Known(Ipv4Addr::new(192, 168, 1, 1)),
            )
            .unwrap();

            assert_eq!(conn.prefix(), 24);
            assert_eq!(conn.address(), Ipv4Addr::new(192, 168, 1, 10));
        }

        #[test]
        fn netmask_from_prefix() {
            let conn = Ipv4Connection::new(Ipv4Addr::new(10, 0, 0, 5), 24, Gateway::Unknown);

            assert_eq!(conn.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        }

        #[test]
        fn netmask_zero_prefix() {
            let conn = Ipv4Connection::new(Ipv4Addr::new(10, 0, 0, 5), 0, Gateway::Unknown);

            assert_eq!(conn.netmask(), Ipv4Addr::new(0, 0, 0, 0));
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
