use serde::Serialize;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

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

impl Ipv4Connection {
    /// Creates a new IPv4 connection configuration.
    ///
    /// ## Example
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
    /// Returns an error if the netmask is invalid.
    ///
    /// ## Example
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
}
