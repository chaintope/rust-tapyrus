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

//! Bitcoin Block
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use std::io;
use std::str::FromStr;

use hashes::{Hash, HashEngine};
use hashes::hex::FromHex;
use hash_types::{Wtxid, BlockHash, BlockSigHash, TxMerkleNode, WitnessMerkleNode, WitnessCommitment, XFieldHash};
use consensus::{serialize, encode, Decodable, Encodable};
use consensus::encode::Error;
use consensus::encode::serialize_hex;
use blockdata::constants::WITNESS_SCALE_FACTOR;
use blockdata::transaction::Transaction;
use util::hash::bitcoin_merkle_root;
use util::key::PublicKey;
use util::signature::Signature;
use VarInt;


/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockHeader {
    /// The protocol version. Should always be 1.
    pub version: i32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: TxMerkleNode,
    /// MerkleRoot based on fixing malleability transaction hash
    pub im_merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// Extra field. This field can host any type of data defined in Tapyrus protocol.
    pub xfield: XField,
    /// Collection holds a signature for block hash which is consisted of block header without Proof.
    pub proof: Option<Signature>,
}

struct BlockHeaderWithoutProof {
    version: i32,
    prev_blockhash: BlockHash,
    merkle_root: TxMerkleNode,
    im_merkle_root: TxMerkleNode,
    time: u32,
    xfield: XField,
}

impl BlockHeader {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Return the Aggregate public key in this BlockHeader
    pub fn aggregated_public_key(&self) -> Option<PublicKey> {
        match self.xfield {
            XField::AggregatePublicKey(pk) => Some(pk),
            _ => None,
        }
    }

    /// Return the max block size in this BlockHeader
    pub fn max_block_size(&self) -> Option<u32> {
        match self.xfield {
            XField::MaxBlockSize(max_block_size) => Some(max_block_size),
            _ => None,
        }
    }

    /// Computes a signature hash for this block.
    /// Tapyrus signer needs to sign this hash. The signature will be added to
    /// the block header as the proof field and submitted to the tapyrus node.
    pub fn signature_hash(&self) -> BlockSigHash {
        let block = BlockHeaderWithoutProof::from(&self);
        BlockSigHash::hash(&serialize(&block))
    }

    /// Return block header size
    pub fn get_size(&self) -> usize {
        let proof_size: usize = self.proof.map(|_| 65).unwrap_or(1);
        4 + 32 + 32 + 32 + 4 + self.xfield.get_size() + proof_size
    }
}

impl BlockHeaderWithoutProof {
    fn from(header: &BlockHeader) -> Self {
        Self {
            version: header.version,
            prev_blockhash: header.prev_blockhash,
            merkle_root: header.merkle_root,
            im_merkle_root: header.im_merkle_root,
            time: header.time,
            xfield: header.xfield.clone(),
        }
    }
}

/// An extra field that allows the block header to hold arbitrary data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XField {
    /// xfield isn't used.
    None,
    /// Aggregate public key used to verify block proof.
    AggregatePublicKey(PublicKey),
    /// Max block size to change the block size limit.
    MaxBlockSize(u32),
    /// Unknown type
    Unknown(u8, Vec<u8>),
}

impl XField {
    /// Return xfieldType.
    pub fn field_type(&self) -> u8 {
        match self {
            XField::None => 0u8,
            XField::AggregatePublicKey(_) => 1u8,
            XField::MaxBlockSize(_) => 2u8,
            XField::Unknown(x_type, _) => *x_type,
        }
    }

    /// Return size of XField
    pub fn get_size(&self) -> usize {
        match self {
            XField::None => 1,
            XField::AggregatePublicKey(_) => 35,
            XField::MaxBlockSize(_) => 5,
            XField::Unknown(_, _) => 0,
        }
    }

    /// Return hash of serialized XField for signing
    pub fn signature_hash(&self) ->Result<XFieldHash, Error>  {
        match self {
            XField::None => Err(Error::XFieldNone),
            XField::AggregatePublicKey(_) => Ok(XFieldHash::hash(&serialize(self))),
            XField::MaxBlockSize(_) => Ok(XFieldHash::hash(&serialize(self))),
            XField::Unknown(i, _) => Err(Error::UnknownXField(*i)),
        }
    }
}

impl FromStr for XField {
    type Err = encode::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> = Vec::from_hex(&s[..]).map_err(|_| encode::Error::ParseFailed("invalid hex string"))?;
        XField::consensus_decode(&bytes[..])
    }
}

impl std::fmt::Display for XField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serialize_hex(self))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for XField {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self)
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for XField {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<XField, D::Error> {
        struct XFieldVisitor;

        impl<'de> ::serde::de::Visitor<'de> for XFieldVisitor {
            type Value = XField;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("hex string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                if let Ok(s) = ::std::str::from_utf8(v) {
                    XField::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                XField::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(XFieldVisitor)
    }
}

impl Decodable for XField {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let x_type: u8 = Decodable::consensus_decode(&mut d)?;
        match x_type {
            0 => Ok(XField::None),
            1 => {
                let bytes: Vec<u8> = Decodable::consensus_decode(&mut d)?;
                let pk = PublicKey::from_slice(&bytes)
                    .map_err(|_| encode::Error::ParseFailed("aggregate public key"))?;
                Ok(XField::AggregatePublicKey(pk))
            },
            2 => {
                let maxblocksize: u32 = Decodable::consensus_decode(&mut d)?;
                Ok(XField::MaxBlockSize(maxblocksize))
            },
            _ => {
                let data: Vec<u8> = Decodable::consensus_decode(&mut d)?;
                Ok(XField::Unknown(x_type, data))
            },
        }
    }
}

impl Encodable for XField {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        self.field_type().consensus_encode(&mut s)?;
        match self {
            XField::None => Ok(1),
            XField::AggregatePublicKey(pk) => {
                let len = pk.to_bytes().consensus_encode(&mut s)?;
                Ok(1 + len)
            },
            XField::MaxBlockSize(maxblocksize) => {
                let len = maxblocksize.consensus_encode(&mut s)?;
                Ok(1 + len)
            },
            XField::Unknown(_type, data) => {
                let len = data.consensus_encode(&mut s)?;
                Ok(1 + len)
            }
        }
    }
}

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>
}

impl Block {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// check if merkle root of header matches merkle root of the transaction list
    pub fn check_merkle_root (&self) -> bool {
        self.header.merkle_root == self.merkle_root() &&
            self.header.im_merkle_root == self.immutable_merkle_root()
    }

    /// check if witness commitment in coinbase is matching the transaction list
    pub fn check_witness_commitment(&self) -> bool {

        // witness commitment is optional if there are no transactions using SegWit in the block
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }
        if !self.txdata.is_empty() {
            let coinbase = &self.txdata[0];
            if coinbase.is_coin_base() {
                // commitment is in the last output that starts with below magic
                if let Some(pos) = coinbase.output.iter()
                    .rposition(|o| {
                        o.script_pubkey.len () >= 38 &&
                        o.script_pubkey[0..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed] }) {
                    let commitment = WitnessCommitment::from_slice(&coinbase.output[pos].script_pubkey.as_bytes()[6..38]).unwrap();
                    // witness reserved value is in coinbase input witness
                    if coinbase.input[0].witness.len() == 1 && coinbase.input[0].witness[0].len() == 32 {
                        let witness_root = self.witness_root();
                        return commitment == Self::compute_witness_commitment(&witness_root, coinbase.input[0].witness[0].as_slice())
                    }
                }
            }
        }
        false
    }

    /// Calculate the transaction merkle root.
    pub fn merkle_root(&self) -> TxMerkleNode {
        let hashes = self.txdata.iter().map(|obj| obj.txid().as_hash());
        bitcoin_merkle_root(hashes).into()
    }

    /// Calculate the immutable transaction merkle root.
    fn immutable_merkle_root(&self) -> TxMerkleNode {
        let hashes = self.txdata.iter().map(|obj| obj.malfix_txid().as_hash());
        bitcoin_merkle_root(hashes).into()
    }

    /// compute witness commitment for the transaction list
    pub fn compute_witness_commitment (witness_root: &WitnessMerkleNode, witness_reserved_value: &[u8]) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).unwrap();
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Merkle root of transactions hashed for witness
    pub fn witness_root(&self) -> WitnessMerkleNode {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)|
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::default().as_hash()
            } else {
                t.wtxid().as_hash()
            }
        );
        bitcoin_merkle_root(hashes).into()
    }

    /// Get the size of the block
    pub fn get_size(&self) -> usize {
        // The size of the header + the size of the varint with the tx count + the txs themselves
        let base_size = self.header.get_size() + VarInt(self.txdata.len() as u64).len();
        let txs_size: usize = self.txdata.iter().map(Transaction::get_size).sum();
        base_size + txs_size
    }

    /// Get the weight of the block
    pub fn get_weight(&self) -> usize {
        let base_weight = WITNESS_SCALE_FACTOR * (self.header.get_size() + VarInt(self.txdata.len() as u64).len());
        let txs_weight: usize = self.txdata.iter().map(Transaction::get_weight).sum();
        base_weight + txs_weight
    }
}

impl_consensus_encoding!(
    BlockHeader,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    xfield,
    proof
);
impl_consensus_encoding!(Block, header, txdata);
impl_consensus_encoding!(
    BlockHeaderWithoutProof,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    xfield
);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use blockdata::block::{Block, XField};
    use consensus::encode::{deserialize, serialize, Error};
    use util::key::PublicKey;
    use hash_types::{BlockSigHash, XFieldHash};
    use hashes::hex::FromHex;

    #[test]
    fn block_test() {
        let some_block = Vec::from_hex("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e490121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af40f1453cd332262d74edf65f96688724b80a15c852fd50151e4aabc41a0d9560d2cd38f0746c3d9c9e18b236f20e37d0ae1bda457ea029db8a55b20f38143517d00201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();
        let cutoff_block = Vec::from_hex("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e490121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").unwrap();

        let prevhash =
            Vec::from_hex("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000").unwrap();
        let merkle =
            Vec::from_hex("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c").unwrap();
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let sig = deserialize(&Vec::from_hex("f1453cd332262d74edf65f96688724b80a15c852fd50151e4aabc41a0d9560d2cd38f0746c3d9c9e18b236f20e37d0ae1bda457ea029db8a55b20f38143517d0").unwrap()).unwrap();
        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, 1);
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.merkle_root());
        assert_eq!(
            real_decode.header.im_merkle_root,
            real_decode.immutable_merkle_root()
        );
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.aggregated_public_key().unwrap(), pk);
        assert_eq!(real_decode.header.proof.unwrap(), sig);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.get_size(), some_block.len());
        assert_eq!(real_decode.get_weight(), some_block.len() * 4);

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    #[test]
    fn no_aggkey_and_no_proof_block_test() {
        let some_block = Vec::from_hex("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e4900000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();
        let decode: Result<Block, _> = deserialize(&some_block);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert!(real_decode.header.aggregated_public_key().is_none());
        assert_eq!(real_decode.header.xfield, XField::None);
        assert!(real_decode.header.proof.is_none());
    }

    #[test]
    fn xfield_none_test() {
        let bytes = Vec::from_hex("00").unwrap();
        let decode: XField = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&decode), bytes);

        assert_eq!(decode, XField::None);

        let xfield = XField::from_str("00");
        assert_eq!(xfield.unwrap(), XField::None);
    }

    #[test]
    fn xfield_aggregate_public_key_test() {
        let bytes = Vec::from_hex("0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let decode: XField = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&decode), bytes);

        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        assert_eq!(decode, XField::AggregatePublicKey(pk));

        let xfield = XField::from_str("0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af");
        assert_eq!(xfield.unwrap(), XField::AggregatePublicKey(pk));
    }

    #[test]
    fn xfield_max_block_size_test() {
        let bytes = Vec::from_hex("0200010000").unwrap();
        let decode: XField = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&decode), bytes);

        let maxblocksize:u32 = 0x100;
        assert_eq!(decode, XField::MaxBlockSize(maxblocksize));
        let xfield = XField::from_str("0200010000");
        assert_eq!(xfield.unwrap(), XField::MaxBlockSize(maxblocksize));

        // max u32
        let max_size_bytes = Vec::from_hex("FFFFFFFF").unwrap();
        let decoded_max:u32 = deserialize(&max_size_bytes).unwrap();
        assert_eq!(XField::MaxBlockSize(u32::MAX).get_size(), 5);
        assert_eq!(serialize(&decoded_max), max_size_bytes);

        // zero
        let zero_size_bytes = Vec::from_hex("00000000").unwrap();
        let decoded_zero:u32 = deserialize(&zero_size_bytes).unwrap();
        assert_eq!(XField::MaxBlockSize(0).get_size(), 5);
        assert_eq!(serialize(&decoded_zero), zero_size_bytes);

        // negative
        let x:i32 = -1;
        let hex_x = Vec::from_hex(&format!("{:08x}", x)).unwrap();
        let decoded_x:u32 = deserialize(&hex_x).unwrap();
        assert!(XField::from_str(&format!("{:08x}", decoded_x)).is_err());
        assert!(XField::from_str(&format!("{:08x}", x)).is_err());

        assert!(XField::from_str("pq").is_err());
        assert!(XField::from_str("020001").is_err());
    }

    #[test]
    #[should_panic]
    fn xfield_max_block_size_panic_test() {

        //larger than u32::MAX
        let overflow_value:u64 = (u32::MAX as u64) + 1;
        let overflow_bytes = Vec::from_hex(&format!("{:016x}", overflow_value)).unwrap();
        assert!(deserialize::<u32>(&overflow_bytes).is_err());
        assert!(XField::from_str(&format!("{:016x}", overflow_value)).is_err());
    }

    #[test]
    fn xfield_unsupported_type_test() {
        let bytes = Vec::from_hex("ff0101").unwrap();
        let decode: XField = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&decode), bytes);

        assert_eq!(decode, XField::Unknown(0xff, vec![0x01]));

        let xfield = XField::from_str("ff0101");
        assert_eq!(xfield.unwrap(), XField::Unknown(0xff, vec![0x01]));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn xfield_serialize_test() {
        let xfield = Vec::from_hex("00").unwrap();
        let decode: XField = deserialize(&xfield).unwrap();
        serde_round_trip!(decode);

        let xfield = Vec::from_hex("0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af").unwrap();
        let decode: XField = deserialize(&xfield).unwrap();
        serde_round_trip!(decode);

        let xfield = Vec::from_hex("02000000ff").unwrap();
        let decode: XField = deserialize(&xfield).unwrap();
        serde_round_trip!(decode);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let segwit_block = Vec::from_hex("000000202aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d7490600000000000010bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67eda3486f183ebe5fcbd343331abaec9fec7eb3ec2a087e543f3a92385e78bdc5b5503bd5700000f010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a3983704012000000000000000000000000000000000000000000000000000000000000000000000000001000000017e4f81175332a733e26d4ba4e29f53f67b7a5d7c2adebb276e447ca71d130b55000000006b483045022100cac809cd1a3d9ad5d5e31a84e2e1d8ec5542841e4d14c6b52e8b38cbe1ff1728022064470b7fb0c2efeccb2e84bfa36ec5f9e434c84b1101c00f7ee32f726371b7410121020e62280798b6b8c37f068df0915b0865b63fabc401c2457cbc3ef96887dd3647ffffffff02ca2f780c000000001976a914c6b5545b3592cb477d709896fa705592c9b6113a88ac663b2a06000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac0000000001000000011e99f5a785e677e017d36b50aa4fd10010ffd039f38f42f447ca8895250e121f01000000d90047304402200d3d296ad641a281dd5c0d68b9ab0d1ad5f7052bec148c1fb81fb1ba69181ec502201a372bb16fb8e054ee9bef41e300d292153830f841a4db0ab7f7407f6581b9bc01473044022002584f313ae990236b6bebb82fbbb006a2b02a448dd5c93434428991eae960d60220491d67d2660c4dde19025cf86e5164a559e2c79c3b98b40e146fab974acd24690147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9140ffdcf96700455074292a821c74922e8652993998788997bc60000000017a9148ce5408cfeaddb7ccb2545ded41ef478109454848700000000010000000113100b09e6a78d63ec4850654ab0f68806de29710b09172eddfef730652b155501000000da00473044022015389408e3446a3f36a05060e0e4a3c8b92ff3901ba2511aa944ec91a537a1cb022045a33b6ec47605b1718ed2e753263e54918edbf6126508ff039621fb928d28a001483045022100bb952fde81f216f7063575c0bb2bedc050ce08c96d9b437ea922f5eb98c882da02201b7cbf3a2f94ea4c5eb7f0df3af2ebcafa8705af7f410ab5d3d4bac13d6bc6120147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914d3db9a20312c3ab896a316eb108dbd01e47e17d687e0ba7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000016e3cca1599cde54878e2f27f434df69df0afd1f313cb6e38c08d3ffb57f97a6c01000000da0048304502210095623b70ec3194fa4037a1c1106c2580caedc390e25e5b330bbeb3111e8184bc02205ae973c4a4454be2a3a03beb66297143c1044a3c4743742c5cdd1d516a1ad3040147304402202f3d6d89996f5b42773dd6ebaf367f1af1f3a95c7c7b487ec040131c40f4a4a30220524ffbb0b563f37b3eb1341228f792e8f84111b7c4a9f49cdd998e052ee42efa0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9141ade6b95896dde8ec4dee9e59af8849d3797348e8728af7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000011d9dc3a5df9b5b2eeb2bd11a2db243be9e8cc23e2f180bf317d32a499904c15501000000db00483045022100ebbd1c9a8ce626edbb1a7881df81e872ef8c6424feda36faa8a5745157400c6a02206eb463bc8acd5ea06a289e86115e1daae0c2cf10d9cbbd199e1311170d5543ef01483045022100809411a917dc8cf4f3a777f0388fdea6de06243ef7691e500c60abd1c7f19ae602205255d2b1191d8adedb77b814ccb66471eb8486cb4ff8727824254ee5589f176b0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914759a49c772347be81c49517f9e1e6def6a88d4dd87800b85c60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704f0000006a47304402201be0d485f6a3ce871be80064c593c5327b3fd7e450f05ab7fae38385bc40cfbe02206e2a6c9970b5d1d10207892376733757486634fce4f352e772149c486857612101210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704e0000006b483045022100ccc8c0ac90bdb0402842aec91830c765cdead7a728552a6a34de7d13a6dab28e02206c96f8640cf3444054e9632b197be30598a09c3d5defcd95750bdb922a60d64801210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000011b436669c06cbf3442e21a2fe3edc20cd3cf13c358c53234bc4d88bfd8c4bd2a000000006a47304402204a63410ee13db52c7609ab08e25b7fe3c608cc21cc1755ad13460685eb55193202204cd1ea80c06a81571119be0b8cccd96ef7cdd90f62c1fe2d538622feb08e22ba0121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d64523365345261445653324d436a736e536171734a5753324465655446624238354541794a4d5843784c7934000000000100000001be4a95ed36316cada5118b1982e4cb4a07f93e7a4153e227466f1cb0776de995000000006b483045022100a22d5251deea0470806bab817013d675a63cd52218d6e477ab0c9d601d018b7f022042121b46afcdcd0c66f189398212b66085e88c6973ae560f1810c13e55e2bee40121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d57484d57504e5248515872504c7338554c586b4d483746745356413675366b5a6b4a4e3851796e4e583751340000000001000000016c061a65b49edec21acdbc22f97dc853aa872302aeef13fabf0bf6807de1b8bd010000006b483045022100dd80381f2d158b4dad7f98d2d97317c533fb36e737542473feb05fa74d0b73bb02207097d4331196069167e525b61d132532292fd75cc039a5839c04c2545d427e2b0121035e9a597df8b417bef66811882a2844604fc591c427f642628f0fef46be19a4c9feffffff0280a4bf07000000001976a914573b9106e16ee0b5c143dc40f0724f77dd0e282088ac9533b22c000000001976a9149c4da607efb1d759d33da71778bc6cafa56acb5988acd31b0e0001000000017dae20994b69b28534e5b22f3d7c50f9d7541348cbf6f43fcc654263ebaf8f68000000006b483045022100a85300eb94b24b044877d0b0d61e08e16dbc82ec7d69c723a8a45519f95c35b002203d78376e6bee31b455c097557af7fe4d6b620bc74269e9a75e2aad2b545abddb012103b0d08aba2a5ac6cf2788fda941c386040e35e49d3a57d2aefb16c0438fb98acbfeffffff022222305f000000001976a914cfda30dd836b596db6a9c230c45ae2179107f04888ac80a4bf07000000001976a91442dfcf5823aacb185844e663873c35fb98bfd21b88acd31b0e000100000002ad3e85e4af30678a330f8941ed7a9ca17cd0236368d238cac4e9ff09c466fed1020000006b483045022100d1196c48a0392e09592f1b96b4aec32ab0cecb6fd17b1d0c85ab3250a2fe45d9022059217c82f684fcdecdbe660a2077ea956dfbbb964d2648bc1e8ae0f0fe565449012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff34f0a71c1c2cd610522e9c18c67931cded5e9647d4419c49b99715e2a0795f3d020000006a4730440220316e81d8242abf3c5f885d200feca12c3adb63cf2cd4dc74602f7b8b0cba50340220210d525758df77ccdca6908311c1895275e07bbb29b45963a19252acde55873f012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff0510270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788ac10270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788aca0860100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac70110100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac0000000000000000026a000000000001000000018e33fecc2ddbd86c5ea919f7bd5a5acf8a09f3e0cdaaaf4f08c5ef095161ef1100000000fdfe0000483045022100d2489b225d39b7d8b6767a6928c8029a2a1297c08fdf00d683ba0c1987e7d7000220176cb66c8a243806bb7421f658325a69a51c82c0c3314e37f2400f33626390210148304502210096cfa57662a545830d0e29610becd41ea031e256339913718ce18dbb1a27bdb00220482911c851d15adcd37097dff99a9ff1f97d953bcebc528835118f447412553e014c695221028d9889862b29430278c084b5c4090b7b807b31e047bcd212ebc2c4e43fc0e3c52103160949a7c8c81f2c25d7763f57eb1cb407d867c5b7c290331bd2dc4b1182c6d32103fbef3b60914bda9173765902013a251ec89450c75d0b5a96a143db1dabf98d9553aeffffffff0220e8891c0100000017a914d996715e081c50f8f6b1b4e7fb6ca214f9924fdf87809698000000000017a9145611d812263f32960228cb5f85329bce4770a218870000000001000000017720507dcbe6c69f652b0c0ce19406f482372d1a8abc05d45fb7acf97fb80eec00000000fdfe00004830450221009821d8e117de44b1202c829c0f5063997acf007cf9b561c6fb8d1212cddb6c40022010ff5067b0d9d4eca2da0ceb876e9a16f1a2142da866d3042a7bae8968813e8001483045022100dea759d14a8a1c5da5f3dcc5509871aaa2c1e3be03752c1b858d80fa4227163702205183d70cc28dcb6df9b037714c8b6442ef84e0ddce07711a30c731e9f0925090014c695221028d70ea66fe7a7def282df7b2b498007e5072933e42c18f63ce85975dcbcf1a8821037e8f842b1e47e21d88002c5aab2559212a4c2c9dbe5ef5347f2a29afd0510ec1210251259cb9fd4f6206488408286e4475c9c9fe887e57a3e32ae4da222778a2aedf53aeffffffff023380cb020000000017a9143b5a7e85b22656a34d43187ac8dd09acd7109d2487809698000000000017a914b9b4b555f594a34deec3ad61d5c5f3738b17ee158700000000").unwrap();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash =
            Vec::from_hex("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000").unwrap();
        let merkle =
            Vec::from_hex("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e").unwrap();

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, 0x20000000); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.merkle_root());
        assert_eq!(
            real_decode.header.im_merkle_root,
            real_decode.immutable_merkle_root()
        );
        assert_eq!(real_decode.header.time, 1472004949);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.get_size(), segwit_block.len());
        assert_eq!(real_decode.get_weight(), 17272);

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = Vec::from_hex("ffffff7f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, 2147483647);

        let block2 = Vec::from_hex("0000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, -2147483648);
    }

    #[test]
    fn signature_hash_test() {
        let block = Vec::from_hex("010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000").unwrap();
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        assert_eq!(decode.unwrap().header.signature_hash(), BlockSigHash::from_hex("3d856f50e0718f72bab6516c1ab020ce3390ebc97490b6d2bad4054dc7a40a93").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_aggpubkey() {
        let xfield = XField::AggregatePublicKey(PublicKey::from_str("02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806").unwrap());
        assert_eq!(serialize(&xfield), Vec::<u8>::from_hex("012102459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806").unwrap());
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_hex("5eb6038f90ec3b530ebed8789afd4f3f49af83fa4b00f34238c93ce0327ff9ad").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_maxblocksize() {
        let xfield = XField::MaxBlockSize(200000);
        assert_eq!(serialize(&xfield), Vec::<u8>::from_hex("02400d0300").unwrap());
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_hex("b2a51fb82acc2125508f323fa9567340c32257997dfd4af4e70788031d5b1915").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_aggpubkey1() {
        let xfield = XField::AggregatePublicKey(PublicKey::from_str("0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50").unwrap());
        assert_eq!(serialize(&xfield), Vec::<u8>::from_hex("01210376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50").unwrap());
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_hex("e70d5478d63e19ab2d9aa059340785b810f82cc288e83752e726a0f9817fcc88").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_maxblocksize1() {
        let xfield = XField::MaxBlockSize(400000);
        assert_eq!(serialize(&xfield), Vec::<u8>::from_hex("02801a0600").unwrap());
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_hex("7b5a43d2dae273d564ec0db616efe75a31725707fc3865124e3477684f5faec0").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_none() {
        let xfield = XField::None;
        let result = xfield.signature_hash();

        assert!(matches!(result, Err(Error::XFieldNone)));
    }

    #[test]
    fn xfield_signature_hash_test_unknown() {
        let xfield = XField::Unknown{0:3, 1:Vec::<u8>::from_hex("012345").unwrap()};
        let result = xfield.signature_hash();
        
        assert!(matches!(result, Err(Error::UnknownXField(3))));
    }
}
