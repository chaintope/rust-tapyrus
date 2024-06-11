// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;
use core::str::FromStr;

use hashes::{sha256d, Hash};
use hex_lit::hex;
use internals::impl_array_newtype;

use crate::alloc::string::ToString;
use crate::amount::Amount;
use crate::blockdata::block::{self, Block, XField};
use crate::blockdata::locktime::absolute;
use crate::blockdata::witness::Witness;
use crate::consensus::deserialize;
use crate::crypto::key::PublicKey;
use crate::crypto::schnorr::Signature;
use crate::internal_macros::impl_bytes_newtype;
use crate::network::{NetworkId, ParseNetworkError};
use crate::opcodes::all::*;
use crate::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::{script, Txid};

#[deprecated(since = "0.31.0", note = "Use Weight::MAX_BLOCK instead")]
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

#[deprecated(since = "0.31.0", note = "Use Weight::MIN_TRANSACTION instead")]
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (tapyrus) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (tapyrus) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// Constructs and returns the coinbase (and only) transaction of the Mainnet genesis block.
fn mainnet_genesis_tx() -> Transaction {
    // https://explorer.api.tapyrus.chaintope.com/tx/3231b5798aacd8ea40f3b580e741006a71335ed9a7538768ee4a193bc525c170
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::new(Txid::all_zeros(), 0),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("314a586d6e436a646453394644366252797a4348376457716844667735486f38794c");
    let out_script = script::Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(script_bytes)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the coinbase (and only) transaction of the Testnet genesis block.
fn testnet_genesis_tx() -> Transaction {
    // https://testnet-explorer.tapyrus.dev.chaintope.com/tx/846521b8ff0b89fee8b99d089ffe403856e912c7fc34486d9dbbf03625ec188f
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::new(Txid::all_zeros(), 0),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("31415132437447336a686f37385372457a4b6533766636647863456b4a74356e7a41");
    let out_script = script::Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(script_bytes)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the Mainnet genesis block.
pub fn mainnet_genesis_block() -> Block {
    // https://explorer.api.tapyrus.chaintope.com/block/92f729508ee8b0e4f46418f81f89806a952c739df03de1e666a8e2b5c40b549b
    let txdata = vec![mainnet_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let im_merkle_root = txdata[0].malfix_txid().into();
    let merkle_root = hash.into();
    let public_key =
        PublicKey::from_str("02bb8a7fbba7da4e6a0519296e30211c33c7307ac19aba4e8f56cce2d3da36b751")
            .unwrap();
    let sig_data = hex!("fb1edbb9eac53c4a1e67c510c7fe7eefd6f5080c74df88a679cf3853e0784231979b3896b577ed3bb987d1a38fd0901d5f68f38cb0c07aea519885022428cede");
    let sig: Signature = deserialize(&sig_data).unwrap();
    Block {
        header: block::Header {
            version: block::Version::ONE,
            prev_blockhash: Hash::all_zeros(),
            merkle_root,
            im_merkle_root,
            time: 1637827301,
            xfield: XField::AggregatePublicKey(public_key),
            proof: Some(sig),
        },
        txdata,
    }
}

/// Constructs and returns the Testnet genesis block.
pub fn testnet_genesis_block() -> Block {
    // https://testnet-explorer.tapyrus.dev.chaintope.com/block/038b114875c2f78f5a2fd7d8549a905f38ea5faee6e29a3d79e547151d6bdd8a
    let txdata = vec![testnet_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let im_merkle_root = txdata[0].malfix_txid().into();
    let merkle_root = hash.into();
    let public_key =
        PublicKey::from_str("0366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4b")
            .unwrap();
    let sig_data = hex!("2b1ed9996920f57a425f6f9797557c0e73d0c9fbafdebcaa796b136e0946ffa98d928f8130b6a572f83da39530b13784eeb7007465b673aa95091619e7ee2085");
    let sig: Signature = deserialize(&sig_data).unwrap();
    Block {
        header: block::Header {
            version: block::Version::ONE,
            prev_blockhash: Hash::all_zeros(),
            merkle_root,
            im_merkle_root,
            time: 1589269151,
            xfield: XField::AggregatePublicKey(public_key),
            proof: Some(sig),
        },
        txdata,
    }
}
/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    /// `ChainHash` for mainnet network.
    pub const MAINNET: Self = Self([
        155, 84, 11, 196, 181, 226, 168, 102, 230, 225, 61, 240, 157, 115, 44, 149, 106, 128, 137,
        31, 248, 24, 100, 244, 228, 176, 232, 142, 80, 41, 247, 146,
    ]);
    /// `ChainHash` for testnet network.
    pub const TESTNET: Self = Self([
        138, 221, 107, 29, 21, 71, 229, 121, 61, 154, 226, 230, 174, 95, 234, 56, 95, 144, 154, 84,
        216, 215, 47, 90, 143, 247, 194, 117, 72, 17, 139, 3,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub fn using_genesis_block(network_id: NetworkId) -> Result<ChainHash, ParseNetworkError> {
        // https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/network_id_and_magic_bytes.md
        let magic = network_id.magic();
        match magic {
            0x00F0FF01 => Ok(Self::MAINNET),
            0x74839A75 => Ok(Self::TESTNET),
            _ => Err(ParseNetworkError("Network id is unknown.".to_string())),
        }
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::transaction;
    use crate::consensus::encode::serialize;

    #[test]
    fn mainnet_genesis_first_transaction() {
        let gen = mainnet_genesis_tx();

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0);
        assert_eq!(gen.input[0].script_sig, script::Builder::new().into_script());

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(
            serialize(&gen.output[0].script_pubkey),
            hex!(
                "2776a922314a586d6e436a646453394644366252797a4348376457716844667735486f38794c88ac"
            )
        );
        assert_eq!(gen.output[0].value, Amount::from_str("50 BTC").unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.txid().to_string(),
            "075565bbdccaefe1c8f9372414767b1a49f4463b01bd9f98c03680bc51ca5bb2"
        );
        assert_eq!(
            gen.malfix_txid().to_string(),
            "3231b5798aacd8ea40f3b580e741006a71335ed9a7538768ee4a193bc525c170"
        );
    }

    #[test]
    fn mainnet_genesis_full_block() {
        let gen = mainnet_genesis_block();

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "075565bbdccaefe1c8f9372414767b1a49f4463b01bd9f98c03680bc51ca5bb2"
        );

        assert_eq!(gen.header.time, 1637827301);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "92f729508ee8b0e4f46418f81f89806a952c739df03de1e666a8e2b5c40b549b"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = testnet_genesis_block();
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "51b341a85575219820ad1175f93a22a83f190dfcd1139a995b5ce9d01b18cc44"
        );
        assert_eq!(gen.header.time, 1589269151);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "038b114875c2f78f5a2fd7d8549a905f38ea5faee6e29a3d79e547151d6bdd8a"
        );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network_id: NetworkId) {
        use hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let magic = network_id.magic();
        let genesis_hash = match magic {
            0x00F0FF01 => mainnet_genesis_block().block_hash(),
            0x74839A75 => testnet_genesis_block().block_hash(),
            _ => panic!("Network ID is not supported"),
        };
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network_id).unwrap();
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, NetworkId::from(1);
        testnet_chain_hash_genesis_block, NetworkId::from(1939510133);
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(NetworkId::from(1)).unwrap().to_string();
        let want = "9b540bc4b5e2a866e6e13df09d732c956a80891ff81864f4e4b0e88e5029f792";
        assert_eq!(got, want);
    }
}
