// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Blockdata constants
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction
//!

use std::default::Default;
use std::str::FromStr;

use hashes::hex::FromHex;
use hashes::sha256d;
use blockdata::block::{Block, BlockHeader, ExtraField};
use blockdata::opcodes;
use blockdata::script;
use blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use network::constants::Network;
use util::key::PublicKey;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    21_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(486604799)
                                          .push_scriptint(4)
                                          .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: vec![],
    });

    // Outputs
    let out_script = script::Builder::new()
        .push_slice(&Vec::<u8>::from_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 50 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    let hash: sha256d::Hash = txdata[0].ntxid().into();
    let im_merkle_root = hash.into();
    let public_key =
        PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")
            .unwrap();

    match network {
        Network::Bitcoin => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    im_merkle_root,
                    time: 1231006505,
                    extra_field: ExtraField::AggregatePublicKey(public_key),
                    proof: None,
                },
                txdata: txdata
            }
        }
        Network::Testnet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    im_merkle_root,
                    time: 1296688602,
                    extra_field: ExtraField::AggregatePublicKey(public_key),
                    proof: None,
                },
                txdata: txdata
            }
        }
        Network::Regtest => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    im_merkle_root,
                    time: 1296688602,
                    extra_field: ExtraField::AggregatePublicKey(public_key),
                    proof: None,
                },
                txdata: txdata,
            }
        }
        Network::Paradium => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    im_merkle_root,
                    time: 1562925929,
                    extra_field: ExtraField::AggregatePublicKey(public_key),
                    proof: None,
                },
                txdata: txdata,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::default::Default;
    use hex::decode as hex_decode;

    use network::constants::Network;
    use consensus::encode::serialize;
    use blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};
    use util::hash::BitcoinHash;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Default::default());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex_decode("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());

        assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex_decode("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(format!("{:x}", gen.wtxid()),
                   "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                   "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string());
        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(
            format!("{:x}", gen.header.bitcoin_hash()),
            "2b84df641d2dbae917c2f00e98a1d7a8fc6fc0988d80a1e0fc087c66228e7ee8".to_string()
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            format!("{:x}", gen.header.merkle_root),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(
            format!("{:x}", gen.header.bitcoin_hash()),
            "0abdbc494a14e90c1d89b8aad109a8266e689aa0c5478e76053524aa8976fb95".to_string()
        );
    }

    #[test]
    fn paradium_genesis_full_block() {
        let gen = genesis_block(Network::Paradium);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            format!("{:x}", gen.header.merkle_root),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1562925929);
        assert_eq!(
            format!("{:x}", gen.header.bitcoin_hash()),
            "abbaa74c35c0467802e1dfd8a20150ea7c0ac529feb245933702832d112c6b16".to_string()
        );
    }
}

