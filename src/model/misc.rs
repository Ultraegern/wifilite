use crate::error::WifiError;
use serde::Serialize;
use std::collections::BTreeSet;

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

impl WifiFlag {
    pub(crate) fn parse_wifi_flags(raw_flags: &str) -> BTreeSet<Self> {
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
}
