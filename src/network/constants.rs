// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::network::constants::Network;
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0x01, 0xFF, 0xF0, 0x00]);
//! ```

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 70001;
/// Bitfield of services provided by this node
pub const SERVICES: u64 = 0;
/// User agent as it appears in the version message
pub const USER_AGENT: &'static str = "bitcoin-rust v0.1";

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
    pub enum Network {
        /// Classic Bitcoin
        Bitcoin <-> "bitcoin",
        /// Bitcoin's testnet
        Testnet <-> "testnet",
        /// Bitcoin's regtest
        Regtest <-> "regtest",
        /// Paradium
        Paradium <-> "paradium"
    }
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Bitcoin), Network::from_magic(0x00F0FF01));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0x00F0FF01 => Some(Network::Bitcoin),
            0x74839A75 => Some(Network::Testnet),
            0x74979A73 => Some(Network::Regtest),
            0x64F0FF01 => Some(Network::Paradium),
            _ => None
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.magic(), 0x00F0FF01);
    /// ```
    pub fn magic(&self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above
        match *self {
            Network::Bitcoin => 0x00F0FF01,
            Network::Testnet => 0x74839A75,
            Network::Regtest => 0x74979A73,
            Network::Paradium => 0x64F0FF01,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Network;
    use consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        assert_eq!(
            serialize(&Network::Bitcoin.magic()),
            &[0x01, 0xff, 0xf0, 0x00]
        );
        assert_eq!(
            serialize(&Network::Testnet.magic()),
            &[0x75, 0x9a, 0x83, 0x74]
        );
        assert_eq!(
            serialize(&Network::Regtest.magic()),
            &[0x73, 0x9a, 0x97, 0x74]
        );
        assert_eq!(
            serialize(&Network::Paradium.magic()),
            &[0x01, 0xff, 0xf0, 0x64]
        );

        assert_eq!(
            deserialize(&[0x01, 0xff, 0xf0, 0x00]).ok(),
            Some(Network::Bitcoin.magic())
        );
        assert_eq!(
            deserialize(&[0x75, 0x9a, 0x83, 0x74]).ok(),
            Some(Network::Testnet.magic())
        );
        assert_eq!(
            deserialize(&[0x73, 0x9a, 0x97, 0x74]).ok(),
            Some(Network::Regtest.magic())
        );
        assert_eq!(
            deserialize(&[0x01, 0xff, 0xf0, 0x64]).ok(),
            Some(Network::Paradium.magic())
        );
    }

  #[test]
  fn string_test() {
      assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
      assert_eq!(Network::Testnet.to_string(), "testnet");
      assert_eq!(Network::Regtest.to_string(), "regtest");
      assert_eq!(Network::Paradium.to_string(), "paradium");

      assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
      assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
      assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
      assert_eq!("paradium".parse::<Network>().unwrap(), Network::Paradium);
      assert!("fakenet".parse::<Network>().is_err());
  }
}

