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

//! # Rust Bitcoin Library
//!
//! This is a library for which supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!

#![crate_name = "tapyrus"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

// Experimental features we need
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#![allow(bare_trait_objects)]
#![allow(ellipsis_inclusive_range_patterns)]

// Re-exported dependencies.
#[macro_use] pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;

#[cfg(feature = "serde")] #[macro_use] extern crate serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_json;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(feature="bitcoinconsensus")] extern crate bitcoinconsensus;

extern crate rug;

#[cfg(target_pointer_width = "16")]
compile_error!("rust-bitcoin cannot be used on 16-bit architectures");

#[cfg(test)]
#[macro_use]
mod test_macros;
#[cfg(test)]
mod test_helpers;
#[macro_use]
mod internal_macros;
#[macro_use]
pub mod network;
pub mod blockdata;
pub mod util;
pub mod consensus;
// Do not remove: required in order to get hash types implementation macros to work correctly
#[allow(unused_imports)]
pub mod hash_types;

pub use crate::hash_types::*;
pub use crate::blockdata::block::Block;
pub use crate::blockdata::block::BlockHeader;
pub use crate::blockdata::script::Script;
pub use crate::blockdata::script::ColorIdentifier;
pub use crate::blockdata::transaction::Transaction;
pub use crate::blockdata::transaction::TxIn;
pub use crate::blockdata::transaction::TxOut;
pub use crate::blockdata::transaction::OutPoint;
pub use crate::blockdata::transaction::SigHashType;
pub use crate::consensus::encode::VarInt;
pub use crate::network::constants::Network;
pub use crate::util::Error;
pub use crate::util::address::Address;
pub use crate::util::address::AddressType;
pub use crate::util::amount::Amount;
pub use crate::util::amount::Denomination;
pub use crate::util::amount::SignedAmount;
pub use crate::util::key::PrivateKey;
pub use crate::util::key::PublicKey;
pub use crate::util::merkleblock::MerkleBlock;
pub use crate::util::signature::Signature;
