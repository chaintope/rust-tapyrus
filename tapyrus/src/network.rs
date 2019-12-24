// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use tapyrus::network::NetworkId;
//! use tapyrus::consensus::encode::serialize;
//!
//! let network = NetworkId::from(1);
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0x01, 0xFF, 0xF0, 0x00]);
//! ```

use core::fmt;
use core::fmt::Display;
use core::str::FromStr;

use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::constants::ChainHash;
use crate::prelude::{String, ToOwned};

/// Network ID is identifier of the Tapyrus network
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkId(u32);

impl NetworkId {
    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tapyrus::network::NetworkId;
    ///
    /// let network = NetworkId::from(1);
    /// assert_eq!(network.magic(), 0x00F0FF01);
    /// ```
    pub fn magic(&self) -> u32 { (33550335 + self.0).swap_bytes() }
}

impl From<u32> for NetworkId {
    fn from(n: u32) -> Self { NetworkId(n) }
}

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// For production
    /// #[strum(serialize = "prod")]
    Prod,
    /// For development
    /// #[strum(serialize = "dev")]
    Dev,
}

impl Network {
    /// Converts a `Network` to its equivalent `bitcoind -chain` argument name.
    ///
    /// ```bash
    /// $ tapyrus-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Network::Prod => "prod",
            Network::Dev => "dev",
        }
    }

    /// Converts a `bitcoind -chain` argument name to its equivalent `Network`.
    ///
    /// ```bash
    /// $ tapyrus-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        use Network::*;

        let network = match core_arg {
            "prod" => Prod,
            "dev" => Dev,
            _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }
}

#[cfg(feature = "serde")]
pub mod as_core_arg {
    //! Module for serialization/deserialization of network variants into/from Bitcoin Core values
    #![allow(missing_docs)]

    use serde;

    use crate::Network;

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(network.to_core_arg())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl<'de> serde::de::Visitor<'de> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"tapyrus network encoded as a string (either main, test, signet or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "tapyrus network encoded as a string (either main, test, signet or regtest)"
                )
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(pub String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Network::*;

        let network = match s {
            "prod" => Prod,
            "dev" => Dev,
            _ => return Err(ParseNetworkError(s.to_owned())),
        };
        Ok(network)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Network::*;

        let s = match *self {
            Prod => "prod",
            Dev => "dev",
        };
        write!(f, "{}", s)
    }
}

/// Error in parsing network from chain hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownChainHashError(ChainHash);

impl Display for UnknownChainHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown chain hash: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownChainHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(test)]
mod tests {
    use super::{Network, NetworkId};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::p2p::ServiceFlags;

    #[test]
    fn serialize_test() {
        // Production
        assert_eq!(serialize(&NetworkId::from(1).magic()), &[0x01, 0xff, 0xf0, 0x00]);
        // Public Testnet
        assert_eq!(serialize(&NetworkId::from(1939510133).magic()), &[0x75, 0x9a, 0x83, 0x74]);
        // Regtest
        assert_eq!(serialize(&NetworkId::from(1905960821).magic()), &[0x73, 0x9a, 0x97, 0x74]);
        // Paradium
        assert_eq!(serialize(&NetworkId::from(101).magic()), &[0x01, 0xff, 0xf0, 0x64]);

        // Production
        assert_eq!(deserialize(&[0x01, 0xff, 0xf0, 0x00]).ok(), Some(NetworkId::from(1).magic()));
        // Public Testnet
        assert_eq!(
            deserialize(&[0x75, 0x9a, 0x83, 0x74]).ok(),
            Some(NetworkId::from(1939510133).magic())
        );
        // Regtest
        assert_eq!(
            deserialize(&[0x73, 0x9a, 0x97, 0x74]).ok(),
            Some(NetworkId::from(1905960821).magic())
        );
        // Paradium
        assert_eq!(deserialize(&[0x01, 0xff, 0xf0, 0x64]).ok(), Some(NetworkId::from(101).magic()));
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Prod.to_string(), "prod");
        assert_eq!(Network::Dev.to_string(), "dev");

        assert_eq!("prod".parse::<Network>().unwrap(), Network::Prod);
        assert_eq!("dev".parse::<Network>().unwrap(), Network::Dev);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![(Prod, "prod"), (Dev, "dev")];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
    }

    #[test]
    fn from_to_core_arg() {
        let expected_pairs = [(Network::Prod, "prod"), (Network::Dev, "dev")];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_core_arg(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "actual_serde")]
        struct T {
            #[serde(with = "crate::network::as_core_arg")]
            pub network: Network,
        }

        serde_test::assert_tokens(
            &T { network: Network::Prod },
            &[
                serde_test::Token::Struct { name: "T", len: 1 },
                serde_test::Token::Str("network"),
                serde_test::Token::Str("prod"),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
