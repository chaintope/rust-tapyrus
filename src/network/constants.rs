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
// Changes for rust-tapyrus is licensed as below.
// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
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
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use tapyrus::network::constants::NetworkId;
//! use tapyrus::consensus::encode::serialize;
//!
//! let network = NetworkId::from(1);
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0x01, 0xFF, 0xF0, 0x00]);
//! ```

use std::{fmt, io, ops};

use consensus::encode::{self, Encodable, Decodable};

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 10000;
/// Bitfield of services provided by this node
pub const SERVICES: u64 = 0;
/// User agent as it appears in the version message
pub const USER_AGENT: &'static str = "tapyrus-rust v0.1";

/// Network ID is identifier of the Tapyrus network
#[derive(Clone)]
pub struct NetworkId(u32);

impl NetworkId {
    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tapyrus::network::constants::NetworkId;
    ///
    /// let network = NetworkId::from(1);
    /// assert_eq!(network.magic(), 0x00F0FF01);
    /// ```
    pub fn magic(&self) -> u32 {
        (33550335 + self.0).swap_bytes()
    }
}

impl From<u32> for NetworkId {
    fn from(n: u32) -> Self {
        NetworkId(n)
    }
}

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
    pub enum Network {
        /// For production
        Prod <-> "prod",
        /// For development
        Dev <-> "dev"
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(&self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if *self == ServiceFlags::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }

        let mut flags = self.clone();
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    flags.remove(ServiceFlags::$f);
                }
            }
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(WITNESS);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self {
        ServiceFlags(f)
    }
}

impl Into<u64> for ServiceFlags {
    fn into(self) -> u64 {
        self.0
    }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self.remove(rhs)
    }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.remove(rhs);
    }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        self.0.consensus_encode(&mut s)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(&mut d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkId, Network, ServiceFlags};
    use consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        // Production
        assert_eq!(
            serialize(&NetworkId::from(1).magic()),
            &[0x01, 0xff, 0xf0, 0x00]
        );
        // Public Testnet
        assert_eq!(
            serialize(&NetworkId::from(1939510133).magic()),
            &[0x75, 0x9a, 0x83, 0x74]
        );
        // Regtest
        assert_eq!(
            serialize(&NetworkId::from(1905960821).magic()),
            &[0x73, 0x9a, 0x97, 0x74]
        );
        // Paradium
        assert_eq!(
            serialize(&NetworkId::from(101).magic()),
            &[0x01, 0xff, 0xf0, 0x64]
        );

        // Production
        assert_eq!(
            deserialize(&[0x01, 0xff, 0xf0, 0x00]).ok(),
            Some(NetworkId::from(1).magic())
        );
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
        assert_eq!(
            deserialize(&[0x01, 0xff, 0xf0, 0x64]).ok(),
            Some(NetworkId::from(101).magic())
        );
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
}

