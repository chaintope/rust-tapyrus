// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Addresses
//!
//! Support for ordinary base58 Bitcoin addresses and private keys
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//!
//! use tapyrus::network::constants::Network;
//! use tapyrus::util::address::Address;
//! use tapyrus::util::key;
//! use tapyrus::secp256k1::Secp256k1;
//! use tapyrus::secp256k1::rand::thread_rng;
//!
//! // Generate random key pair
//! let s = Secp256k1::new();
//! let public_key = key::PublicKey {
//!     compressed: true,
//!     key: s.generate_keypair(&mut thread_rng()).1,
//! };
//!
//! // Generate pay-to-pubkey-hash address
//! let address = Address::p2pkh(&public_key, Network::Prod);
//! ```

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use hashes::Hash;
use hashes::hex::FromHex;

use hash_types::{PubkeyHash, ScriptHash};
use blockdata::opcodes;
use blockdata::script::{Builder, ColorIdentifier, Script};
use network::constants::Network;
use util::base58;
use util::key;

/// Address error.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Base58 encoding error
    Base58(base58::Error),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write!(f, "base58: {}", e),
            Error::UncompressedPubkey => write!(f,
                "an uncompressed pubkey was used where it is not allowed",
            ),
        }
    }
}

#[allow(deprecated)]
impl ::std::error::Error for Error {
    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::Base58(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressType {
    /// pay-to-pubkey-hash
    P2pkh,
    /// pay-to-script-hash
    P2sh,
    /// colored-pay-to-pubkey-hash
    Cp2pkh,
    /// colored-pay-to-script-hash
    Cp2sh,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
            AddressType::Cp2pkh => "cp2pkh",
            AddressType::Cp2sh => "cp2sh",
        })
    }
}

impl FromStr for AddressType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            "cp2pkh" => Ok(AddressType::Cp2pkh),
            "cp2sh" => Ok(AddressType::Cp2sh),
            _ => Err(()),
        }
    }
}

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// pay-to-pkhash address
    PubkeyHash(PubkeyHash),
    /// P2SH address
    ScriptHash(ScriptHash),
    /// CP2PKH address
    ColoredPubkeyHash(ColorIdentifier, PubkeyHash),
    /// CP2SH address
    ColoredScriptHash(ColorIdentifier, ScriptHash),
}

impl Payload {
    /// Get a [Payload] from an output script (scriptPubkey).
    pub fn from_script(script: &Script) -> Option<Payload> {
        Some(if script.is_p2pkh() {
            Payload::PubkeyHash(PubkeyHash::from_slice(&script.as_bytes()[3..23]).unwrap())
        } else if script.is_p2sh() {
            Payload::ScriptHash(ScriptHash::from_slice(&script.as_bytes()[2..22]).unwrap())
        } else if script.is_cp2pkh() {
            let bytes = script.as_bytes();
            let color_id = ColorIdentifier::from_slice(&bytes[1..34]).unwrap();
            Payload::ColoredPubkeyHash(color_id, PubkeyHash::from_slice(&bytes[38..58]).unwrap())
        } else if script.is_cp2sh() {
            let bytes = script.as_bytes();
            let color_id = ColorIdentifier::from_slice(&bytes[1..34]).unwrap();
            Payload::ColoredScriptHash(color_id, ScriptHash::from_slice(&bytes[37..57]).unwrap())
        } else {
            return None;
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Payload::PubkeyHash(ref hash) => Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            Payload::ScriptHash(ref hash) => Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            Payload::ColoredPubkeyHash(ref color_id, ref hash) => Builder::new()
                .push_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap())
                .push_opcode(opcodes::all::OP_COLOR)
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            Payload::ColoredScriptHash(ref color_id, ref hash) => Builder::new()
                .push_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap())
                .push_opcode(opcodes::all::OP_COLOR)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUAL),
        }
        .into_script()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A Bitcoin address
pub struct Address {
    /// The type of the address
    pub payload: Payload,
    /// The network on which this address is usable
    pub network: Network,
}
serde_string_impl!(Address, "a Bitcoin address");

impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn p2pkh(pk: &key::PublicKey, network: Network) -> Address {
        let mut hash_engine = PubkeyHash::engine();
        pk.write_into(&mut hash_engine);

        Address {
            network: network,
            payload: Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine)),
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn p2sh(script: &Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::ScriptHash(ScriptHash::hash(&script[..])),
        }
    }

    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn cp2pkh(color_id: &ColorIdentifier, pk: &key::PublicKey, network: Network) -> Address {
        let mut hash_engine = PubkeyHash::engine();
        pk.write_into(&mut hash_engine);

        Address {
            network: network,
            payload: Payload::ColoredPubkeyHash(color_id.clone(), PubkeyHash::from_engine(hash_engine)),
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn cp2sh(color_id: &ColorIdentifier, script: &Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::ColoredScriptHash(color_id.clone(), ScriptHash::hash(&script[..])),
        }
    }

    /// Get the address type of the address.
    /// None if unknown or non-standard.
    pub fn address_type(&self) -> Option<AddressType> {
        match self.payload {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
            Payload::ColoredPubkeyHash(_, _)=> Some(AddressType::Cp2pkh),
            Payload::ColoredScriptHash(_, _)=> Some(AddressType::Cp2sh),
        }
    }

    /// Check whether or not the address is following Bitcoin
    /// standardness rules.
    ///
    /// Segwit addresses with unassigned witness versions or non-standard
    /// program sizes are considered non-standard.
    pub fn is_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Get an [Address] from an output script (scriptPubkey).
    pub fn from_script(script: &Script, network: Network) -> Option<Address> {
        Some(Address {
            payload: Payload::from_script(script)?,
            network: network,
        })
    }

    /// Generates a script pubkey spending to this address
    pub fn script_pubkey(&self) -> Script {
        self.payload.script_pubkey()
    }
}

impl Display for Address {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = match self.network {
                    Network::Prod => 0,
                    Network::Dev => 111,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(ref hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = match self.network {
                    Network::Prod => 5,
                    Network::Dev => 196,
                };
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ColoredPubkeyHash(ref color_id, ref hash) => {
                let mut prefixed = [0; 54];
                prefixed[0] = match self.network {
                    Network::Prod => 1,
                    Network::Dev => 112,
                };
                prefixed[1..34].copy_from_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap());
                prefixed[34..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
            Payload::ColoredScriptHash(ref color_id, ref hash) => {
                let mut prefixed = [0; 54];
                prefixed[0] = match self.network {
                    Network::Prod => 6,
                    Network::Dev => 197,
                };
                prefixed[1..34].copy_from_slice(&Vec::from_hex(&format!("{}", color_id)).unwrap());
                prefixed[34..].copy_from_slice(&hash[..]);
                base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
            }
        }
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Address, Error> {
        // Base58
        if s.len() > 80 {
            return Err(Error::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::from_check(s)?;

        let (network, payload) = match data.len() {
            21 => {
                match data[0] {
                    0 => (
                        Network::Prod,
                        Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
                    ),
                    5 => (
                        Network::Prod,
                        Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
                    ),
                    111 => (
                        Network::Dev,
                        Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
                    ),
                    196 => (
                        Network::Dev,
                        Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
                    ),
                    x => return Err(Error::Base58(base58::Error::InvalidVersion(vec![x]))),
                }
            }
            54 => {
                match data[0] {
                    1 => (
                        Network::Prod,
                        Payload::ColoredPubkeyHash(ColorIdentifier::from_slice(&data[1..34]).unwrap(), PubkeyHash::from_slice(&data[34..]).unwrap()),
                    ),
                    6 => (
                        Network::Prod,
                        Payload::ColoredScriptHash(ColorIdentifier::from_slice(&data[1..34]).unwrap(), ScriptHash::from_slice(&data[34..]).unwrap()),
                    ),
                    112 => (
                        Network::Dev,
                        Payload::ColoredPubkeyHash(ColorIdentifier::from_slice(&data[1..34]).unwrap(), PubkeyHash::from_slice(&data[34..]).unwrap()),
                    ),
                    197 => (
                        Network::Dev,
                        Payload::ColoredScriptHash(ColorIdentifier::from_slice(&data[1..34]).unwrap(), ScriptHash::from_slice(&data[34..]).unwrap()),
                    ),
                    x => return Err(Error::Base58(base58::Error::InvalidVersion(vec![x]))),
                }
            }
            _ => return Err(Error::Base58(base58::Error::InvalidLength(data.len())))
        };

        Ok(Address { network, payload })
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::string::ToString;

    use hashes::hex::FromHex;

    use blockdata::script::Script;
    use network::constants::Network::{Prod, Dev};
    use util::key::PublicKey;

    use super::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_key (($hex:expr) => (PublicKey::from_slice(&hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));
    macro_rules! hex_pubkeyhash (($hex:expr) => (PubkeyHash::from_hex(&$hex).unwrap()));
    macro_rules! hex_scripthash (($hex:expr) => (ScriptHash::from_hex(&$hex).unwrap()));

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), addr.network).as_ref(),
            Some(addr),
            "script round-trip failed for {}",
            addr,
        );
        //TODO: add serde roundtrip after no-strason PR
    }

    #[test]
    fn test_address_type() {
        let p2pkh = Address {
            network: Prod,
            payload: Payload::PubkeyHash(hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };
        assert_eq!(format!("{}", p2pkh.address_type().unwrap()), "p2pkh");
        assert_eq!(AddressType::from_str("p2pkh").unwrap(), AddressType::P2pkh);

        let p2sh = Address {
            network: Prod,
            payload: Payload::ScriptHash(hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };
        assert_eq!(format!("{}", p2sh.address_type().unwrap()), "p2sh");
        assert_eq!(AddressType::from_str("p2sh").unwrap(), AddressType::P2sh);

        let color_id = ColorIdentifier::from_hex("c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e").unwrap();

        let cp2pkh = Address {
            network: Prod,
            payload: Payload::ColoredPubkeyHash(color_id.clone(), hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };
        assert_eq!(format!("{}", cp2pkh.address_type().unwrap()), "cp2pkh");
        assert_eq!(AddressType::from_str("cp2pkh").unwrap(), AddressType::Cp2pkh);

        let cp2sh = Address {
            network: Prod,
            payload: Payload::ColoredScriptHash(color_id.clone(), hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };
        assert_eq!(format!("{}", cp2sh.address_type().unwrap()), "cp2sh");
        assert_eq!(AddressType::from_str("cp2sh").unwrap(), AddressType::Cp2sh);
    }

    #[test]
    fn test_p2pkh_address_58() {
        let addr = Address {
            network: Prod,
            payload: Payload::PubkeyHash(hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );
        assert_eq!(&addr.to_string(), "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = hex_key!("048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let addr = Address::p2pkh(&key, Prod);
        assert_eq!(&addr.to_string(), "1QJVDzdqb1VpbDK7uDeyVXy9mR27CJiyhY");

        let key = hex_key!(&"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::p2pkh(&key, Dev);
        assert_eq!(&addr.to_string(), "mqkhEMH6NCeYjFybv7pvFC22MFeaNT9AQC");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_address_58() {
        let addr = Address {
            network: Prod,
            payload: Payload::ScriptHash(hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
        assert_eq!(&addr.to_string(), "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = hex_script!("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae");
        let addr = Address::p2sh(&script, Dev);

        assert_eq!(&addr.to_string(), "2N3zXjbwdTcPsJiy8sUK9FhWJhqQCxA8Jjr");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_cp2pkh_address() {
        let color_id = ColorIdentifier::from_hex("c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e").unwrap();

        let addr = Address {
            network: Prod,
            payload: Payload::ColoredPubkeyHash(color_id, hex_pubkeyhash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("21c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0ebc76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );
        assert_eq!(&addr.to_string(), "vxgHyieT46FQMYAvmNM6BsmwNNXMTPk2C6StiVD3Cmy45ge5gftf5f417CehuVWVo5KfBbgtGyLn9j");
        assert_eq!(addr.address_type(), Some(AddressType::Cp2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_cp2pkh_from_key() {
        let key = hex_key!("048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183");
        let color_id = ColorIdentifier::from_hex("c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e").unwrap();
        let addr = Address::cp2pkh(&color_id, &key, Prod);
        assert_eq!(&addr.to_string(), "vxgHyieT46FQMYAvmNM6BsmwNNXMTPk2C6StiVD3Cmy463vKtag2nkNBtGeqUNzBuXWtgUctod91ag");

        let key = hex_key!(&"03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f");
        let addr = Address::cp2pkh(&color_id, &key, Dev);
        assert_eq!(&addr.to_string(), "22VZyRTDaMem4DcgBgRZgbo7PZm45gXSMWzHrYiYE9j1qVUiHVfNFhik8yY4YzpArPc3Hufwe5oeWgmg");
        assert_eq!(addr.address_type(), Some(AddressType::Cp2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_cp2sh_address() {
        let color_id = ColorIdentifier::from_hex("c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0e").unwrap();

        let addr = Address {
            network: Prod,
            payload: Payload::ColoredScriptHash(color_id, hex_scripthash!("162c5ea71c0b23f5b9022ef047c4a86470a5b070")),
        };

        assert_eq!(
            addr.script_pubkey(),
            hex_script!("21c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0ebca914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
        assert_eq!(&addr.to_string(), "4Zxhb33iSoydtcKzWc7hpoRjtJh2W9otwDeqP5PbZHGoq7m3fwysg7ec2TJ2RRuheF8PgQqrGKDjdij");
        assert_eq!(addr.address_type(), Some(AddressType::Cp2sh));
        roundtrips(&addr);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        // P2PKH
        let addr = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        // P2SH
        let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );

        // CP2PKH
        let addr = Address::from_str("vxgHyieT46FQMYAvmNM6BsmwNNXMTPk2C6StiVD3Cmy45ge5gftf5f417CehuVWVo5KfBbgtGyLn9j").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("vxgHyieT46FQMYAvmNM6BsmwNNXMTPk2C6StiVD3Cmy45ge5gftf5f417CehuVWVo5KfBbgtGyLn9j".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("21c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0ebc76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        // CP2SH
        let addr = Address::from_str("4Zxhb33iSoydtcKzWc7hpoRjtJh2W9otwDeqP5PbZHGoq7m3fwysg7ec2TJ2RRuheF8PgQqrGKDjdij").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("4Zxhb33iSoydtcKzWc7hpoRjtJh2W9otwDeqP5PbZHGoq7m3fwysg7ec2TJ2RRuheF8PgQqrGKDjdij".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("21c36db65fd59fd356f6729140571b5bcd6bb3b83492a16e1bf0a3884442fc3c8a0ebca914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );
    }
}
