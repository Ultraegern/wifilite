//! Parsing and models for Linux network interface information.
//!
//! This module provides types and functions for parsing the output of the `ip -j address`
//! command, which returns JSON-formatted information about network interfaces and their
//! IP addresses on Linux systems.
//!
//! # Examples
//!
//! ```no_run
//! use wifilite::model::linux_ip_address::IpOutput;
//! use wifilite::model::InterfaceMap;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Fetch directly from the system
//!     let output = IpOutput::from_system().await?;
//!
//!     let interfaces = InterfaceMap::from(output);
//!     Ok(())
//! }
//! ```

use super::{
    Gateway, InterfaceMap, InterfaceName, Ipv4Connection, Ipv6Connection, NetworkInterface,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use tokio::process::Command;

/// IP address family (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4 address family
    Inet,
    /// IPv6 address family
    Inet6,
}

/// Operational state of a network interface.
///
/// Indicates the current state of the link and device operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OperState {
    /// Interface is operational and up
    Up,
    /// Interface is down
    Down,
    /// State is unknown
    Unknown,
    /// Interface is dormant (suspended or idle)
    Dormant,
    /// Interface is in test mode
    Testing,
    /// Lower layer is down
    #[serde(rename = "LOWERLAYERDOWN")]
    LowerLayerDown,

    /// Other operational state
    #[serde(other)]
    Other,
}

/// Hardware link type of a network interface.
///
/// Specifies the type of physical or virtual link used by the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkType {
    /// Ethernet or similar link
    Ether,
    /// Loopback interface
    Loopback,
    /// CAN bus interface
    Can,
    /// Dummy interface
    Dummy,
    /// Bridge interface
    Bridge,
    /// VLAN interface
    Vlan,
    /// TUN (tunnel) interface
    Tun,

    /// Other link type
    #[serde(other)]
    Other,
}

/// Interface flags indicating its capabilities and state.
///
/// Flags describe various properties and capabilities of a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum InterfaceFlag {
    /// Interface is up
    Up,
    /// Can broadcast
    Broadcast,
    /// Is a loopback interface
    Loopback,
    /// Point-to-point link
    PointToPoint,
    /// No ARP protocol
    Noarp,
    /// Interface is dynamic
    Dynamic,
    /// Supports multicast
    Multicast,
    /// Lower layer is up
    LowerUp,
    /// Echo capability
    Echo,

    /// Other interface flag
    #[serde(other)]
    Other,
}

/// Scope of an IP address (host-local, link-local, or global).
///
/// Indicates the scope within which an address is valid and routable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressScope {
    /// Address is only valid on this host
    Host,
    /// Address is valid on the link
    Link,
    /// Address is globally routable
    Global,

    /// Other address scope
    #[serde(other)]
    Other,
}

/// Address lifetime configuration for IPv6 addresses.
///
/// Represents the valid and preferred lifetime of an IPv6 address.
/// When set to `FOREVER`, the address has unlimited lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Lifetime(u32);

impl Lifetime {
    /// Constant representing unlimited lifetime.
    pub const FOREVER: u32 = u32::MAX;

    /// Checks if the lifetime is set to forever (unlimited).
    pub fn is_forever(self) -> bool {
        self.0 == Self::FOREVER
    }
}

/// Information about a single IP address assigned to an interface.
///
/// Contains the address itself along with prefix length, scope, and lifetime information.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AddrInfo {
    /// Address family (IPv4 or IPv6)
    pub family: AddressFamily,
    /// The IP address
    pub local: IpAddr,
    /// Prefix length (CIDR notation)
    pub prefixlen: u8,

    /// Broadcast address (IPv4 only)
    #[serde(default)]
    pub broadcast: Option<IpAddr>,

    /// Scope of this address
    pub scope: AddressScope,

    /// Address label
    #[serde(default)]
    pub label: Option<String>,

    /// Valid lifetime for this address
    pub valid_life_time: Lifetime,
    /// Preferred lifetime for this address
    pub preferred_life_time: Lifetime,
}

/// Low-level interface information from the Linux kernel.
///
/// Represents the raw output from `ip -j address` before conversion to higher-level types.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Interface {
    /// Interface index
    pub ifindex: u32,
    /// Interface name (e.g., "eth0", "wlan0")
    pub ifname: String,

    /// Interface flags
    pub flags: BTreeSet<InterfaceFlag>,

    /// Maximum transmission unit (packet size)
    pub mtu: u32,
    /// Queueing discipline
    pub qdisc: String,
    /// Operational state
    pub operstate: OperState,
    /// Interface group
    pub group: String,

    /// Transmit queue length
    #[serde(default)]
    pub txqlen: Option<u32>,

    /// Hardware link type
    #[serde(rename = "link_type")]
    pub link_type: LinkType,

    /// MAC address
    pub address: Option<String>,

    /// Broadcast address
    #[serde(default)]
    pub broadcast: Option<String>,

    /// IP addresses assigned to this interface
    #[serde(default)]
    pub addr_info: Vec<AddrInfo>,
}

/// Parsed output from the `ip -j address` command.
///
/// Contains information about all network interfaces and their addresses.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "Vec<Interface>")]
pub struct IpOutput {
    /// Map of interface names to interface information
    pub interfaces: BTreeMap<String, Interface>,
}

impl From<Vec<Interface>> for IpOutput {
    fn from(list: Vec<Interface>) -> Self {
        let interfaces = list
            .into_iter()
            .map(|iface| (iface.ifname.clone(), iface))
            .collect();

        Self { interfaces }
    }
}

impl IpOutput {
    /// Parses IP output from a JSON string.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string output from `ip -j address`
    ///
    /// # Errors
    ///
    /// Returns an error if JSON parsing fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wifilite::model::linux_ip_address::IpOutput;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let json = r#"[{"ifindex":1,"ifname":"lo",...}]"#;
    ///     let output = IpOutput::from_json(json)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Fetches IP information directly from the system using the `ip` command.
    ///
    /// Executes `ip -j address` to get JSON-formatted interface information
    /// directly from the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `ip` command is not available
    /// - The command execution fails
    /// - The output cannot be parsed as JSON
    ///```no_run
    /// use wifilite::model::linux_ip_address::IpOutput;
    ///
    /// async fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let output = IpOutput::from_system().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn from_system() -> io::Result<Self> {
        let output = Command::new("ip").args(["-j", "address"]).output().await?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "'ip -j address' exited with (exit_code, stdout, stderr) ({}, {}, {})",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let value = serde_json::from_slice(&output.stdout).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("JSON parse error: {}", e),
            )
        })?;

        Ok(value)
    }
}

impl From<IpOutput> for InterfaceMap {
    fn from(ip: IpOutput) -> Self {
        let mut out = BTreeMap::new();

        for (name, iface) in ip.interfaces {
            let ifname = match InterfaceName::try_from(name) {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Only keep Ethernet/WiFi-class devices
            if iface.link_type != LinkType::Ether {
                continue;
            }

            // Must have a MAC address
            if iface.address.is_none() {
                continue;
            }

            // Must not be kernel-virtual by naming convention
            let name = iface.ifname.as_str();

            if name.starts_with("docker")
                || name.starts_with("br-")
                || name.starts_with("veth")
                || name.starts_with("dummy")
                || name.starts_with("tun")
                || name.starts_with("tap")
                || name.starts_with("lo")
            {
                continue;
            }

            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();

            for addr in iface.addr_info {
                match addr.local {
                    std::net::IpAddr::V4(v4) => {
                        ipv4.push(Ipv4Connection::new(v4, addr.prefixlen, Gateway::Unknown));
                    }
                    std::net::IpAddr::V6(v6) => {
                        ipv6.push(Ipv6Connection::new(v6, addr.prefixlen, Gateway::Unknown));
                    }
                }
            }

            out.insert(ifname.clone(), NetworkInterface::new(ifname, ipv4, ipv6));
        }

        InterfaceMap(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    mod address_family {
        use super::*;

        #[test]
        fn parses_inet() {
            let json = r#"{"family":"inet","local":"192.168.1.1","prefixlen":24,"scope":"global","valid_life_time":4294967295,"preferred_life_time":4294967295}"#;
            let addr: AddrInfo = serde_json::from_str(json).unwrap();
            assert_eq!(addr.family, AddressFamily::Inet);
        }

        #[test]
        fn parses_inet6() {
            let json = r#"{"family":"inet6","local":"::1","prefixlen":128,"scope":"host","valid_life_time":4294967295,"preferred_life_time":4294967295}"#;
            let addr: AddrInfo = serde_json::from_str(json).unwrap();
            assert_eq!(addr.family, AddressFamily::Inet6);
        }
    }

    mod oper_state {
        use super::*;

        #[test]
        fn parses_states() {
            assert_eq!(
                serde_json::from_str::<OperState>(r#""UP""#).unwrap(),
                OperState::Up
            );
            assert_eq!(
                serde_json::from_str::<OperState>(r#""DOWN""#).unwrap(),
                OperState::Down
            );
            assert_eq!(
                serde_json::from_str::<OperState>(r#""UNKNOWN""#).unwrap(),
                OperState::Unknown
            );
            assert_eq!(
                serde_json::from_str::<OperState>(r#""DORMANT""#).unwrap(),
                OperState::Dormant
            );
        }
    }

    mod link_type {
        use super::*;

        #[test]
        fn parses_link_types() {
            assert_eq!(
                serde_json::from_str::<LinkType>(r#""ether""#).unwrap(),
                LinkType::Ether
            );
            assert_eq!(
                serde_json::from_str::<LinkType>(r#""loopback""#).unwrap(),
                LinkType::Loopback
            );
            assert_eq!(
                serde_json::from_str::<LinkType>(r#""bridge""#).unwrap(),
                LinkType::Bridge
            );
        }
    }

    mod lifetime {
        use super::*;

        #[test]
        fn lifetime_forever() {
            let lifetime = Lifetime(Lifetime::FOREVER);
            assert!(lifetime.is_forever());
        }

        #[test]
        fn lifetime_not_forever() {
            let lifetime = Lifetime(3600);
            assert!(!lifetime.is_forever());
        }

        #[test]
        fn lifetime_zero() {
            let lifetime = Lifetime(0);
            assert!(!lifetime.is_forever());
        }
    }

    mod addr_info {
        use super::*;
        use std::net::IpAddr;

        #[test]
        fn parses_ipv4_address() {
            let json = r#"{
                "family":"inet",
                "local":"192.168.1.1",
                "prefixlen":24,
                "scope":"global",
                "valid_life_time":4294967295,
                "preferred_life_time":4294967295
            }"#;
            let addr: AddrInfo = serde_json::from_str(json).unwrap();
            assert_eq!(addr.family, AddressFamily::Inet);
            assert_eq!(addr.local, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(addr.prefixlen, 24);
        }

        #[test]
        fn parses_ipv6_address() {
            let json = r#"{
                "family":"inet6",
                "local":"fe80::1",
                "prefixlen":64,
                "scope":"link",
                "valid_life_time":4294967295,
                "preferred_life_time":4294967295
            }"#;
            let addr: AddrInfo = serde_json::from_str(json).unwrap();
            assert_eq!(addr.family, AddressFamily::Inet6);
            assert_eq!(addr.prefixlen, 64);
        }
    }

    mod interface {
        use super::*;

        #[test]
        fn parses_interface() {
            let json = r#"{
                "ifindex":1,
                "ifname":"lo",
                "flags":["LOOPBACK","UP","RUNNING"],
                "mtu":65536,
                "qdisc":"noqueue",
                "operstate":"UP",
                "group":"default",
                "link_type":"loopback",
                "address":"00:00:00:00:00:00"
            }"#;
            let iface: Interface = serde_json::from_str(json).unwrap();
            assert_eq!(iface.ifname, "lo");
            assert_eq!(iface.ifindex, 1);
            assert_eq!(iface.mtu, 65536);
        }

        #[test]
        fn parses_ethernet_interface() {
            let json = r#"{
                "ifindex":2,
                "ifname":"eth0",
                "flags":["BROADCAST","RUNNING","MULTICAST"],
                "mtu":1500,
                "qdisc":"mq",
                "operstate":"UP",
                "group":"default",
                "link_type":"ether",
                "address":"aa:bb:cc:dd:ee:ff",
                "broadcast":"ff:ff:ff:ff:ff:ff"
            }"#;
            let iface: Interface = serde_json::from_str(json).unwrap();
            assert_eq!(iface.ifname, "eth0");
            assert_eq!(iface.link_type, LinkType::Ether);
            assert_eq!(iface.address, Some("aa:bb:cc:dd:ee:ff".to_string()));
        }
    }

    mod ip_output {
        use super::*;

        #[test]
        fn parses_simple_ip_output() {
            let json = r#"[
                {
                    "ifindex":1,
                    "ifname":"lo",
                    "flags":["LOOPBACK","UP"],
                    "mtu":65536,
                    "qdisc":"noqueue",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"loopback",
                    "addr_info":[]
                }
            ]"#;

            let output = IpOutput::from_json(json).unwrap();
            assert!(output.interfaces.contains_key("lo"));
        }

        #[test]
        fn from_json_with_addresses() {
            let json = r#"[
                {
                    "ifindex":2,
                    "ifname":"eth0",
                    "flags":["BROADCAST","RUNNING","MULTICAST"],
                    "mtu":1500,
                    "qdisc":"mq",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"ether",
                    "address":"aa:bb:cc:dd:ee:ff",
                    "addr_info":[
                        {
                            "family":"inet",
                            "local":"192.168.1.100",
                            "prefixlen":24,
                            "scope":"global",
                            "valid_life_time":4294967295,
                            "preferred_life_time":4294967295
                        }
                    ]
                }
            ]"#;

            let output = IpOutput::from_json(json).unwrap();
            assert!(output.interfaces.contains_key("eth0"));
            let eth0 = &output.interfaces["eth0"];
            assert_eq!(eth0.addr_info.len(), 1);
        }
    }

    mod interface_map_conversion {
        use super::*;

        #[test]
        fn filters_loopback_interface() {
            let json = r#"[
                {
                    "ifindex":1,
                    "ifname":"lo",
                    "flags":["LOOPBACK","UP"],
                    "mtu":65536,
                    "qdisc":"noqueue",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"loopback",
                    "addr_info":[]
                },
                {
                    "ifindex":2,
                    "ifname":"eth0",
                    "flags":["BROADCAST","RUNNING"],
                    "mtu":1500,
                    "qdisc":"mq",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"ether",
                    "address":"aa:bb:cc:dd:ee:ff",
                    "addr_info":[]
                }
            ]"#;

            let ip_output = IpOutput::from_json(json).unwrap();
            let interface_map = InterfaceMap::from(ip_output);

            // Loopback should be filtered out
            assert!(
                !interface_map
                    .0
                    .contains_key(&InterfaceName::new("lo").unwrap())
            );
            // eth0 should be included
            assert!(
                interface_map
                    .0
                    .contains_key(&InterfaceName::new("eth0").unwrap())
            );
        }

        #[test]
        fn filters_virtual_interfaces() {
            let json = r#"[
                {
                    "ifindex":2,
                    "ifname":"eth0",
                    "flags":["BROADCAST"],
                    "mtu":1500,
                    "qdisc":"mq",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"ether",
                    "address":"aa:bb:cc:dd:ee:ff",
                    "addr_info":[]
                },
                {
                    "ifindex":3,
                    "ifname":"docker0",
                    "flags":["BROADCAST"],
                    "mtu":1500,
                    "qdisc":"noop",
                    "operstate":"DOWN",
                    "group":"default",
                    "link_type":"ether",
                    "address":"02:42:ac:11:00:01",
                    "addr_info":[]
                }
            ]"#;

            let ip_output = IpOutput::from_json(json).unwrap();
            let interface_map = InterfaceMap::from(ip_output);

            // eth0 should be included
            assert!(
                interface_map
                    .0
                    .contains_key(&InterfaceName::new("eth0").unwrap())
            );
            // docker0 should be filtered
            assert!(
                !interface_map
                    .0
                    .contains_key(&InterfaceName::new("docker0").unwrap())
            );
        }

        #[test]
        fn converts_addresses_to_connections() {
            let json = r#"[
                {
                    "ifindex":2,
                    "ifname":"eth0",
                    "flags":["BROADCAST"],
                    "mtu":1500,
                    "qdisc":"mq",
                    "operstate":"UP",
                    "group":"default",
                    "link_type":"ether",
                    "address":"aa:bb:cc:dd:ee:ff",
                    "addr_info":[
                        {
                            "family":"inet",
                            "local":"192.168.1.100",
                            "prefixlen":24,
                            "scope":"global",
                            "valid_life_time":4294967295,
                            "preferred_life_time":4294967295
                        },
                        {
                            "family":"inet6",
                            "local":"fe80::1",
                            "prefixlen":64,
                            "scope":"link",
                            "valid_life_time":4294967295,
                            "preferred_life_time":4294967295
                        }
                    ]
                }
            ]"#;

            let ip_output = IpOutput::from_json(json).unwrap();
            let interface_map = InterfaceMap::from(ip_output);

            let eth0 = interface_map
                .0
                .get(&InterfaceName::new("eth0").unwrap())
                .unwrap();
            assert_eq!(eth0.ipv4.len(), 1);
            assert_eq!(eth0.ipv6.len(), 1);
        }
    }
}
