// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;

use hashes::{Hash, HashEngine};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::Transaction;
use crate::consensus::{encode, Decodable, Encodable};
pub use crate::hash_types::BlockHash;
use crate::hash_types::{TxMerkleNode, WitnessCommitment, WitnessMerkleNode, Wtxid};
use crate::internal_macros::impl_consensus_encoding;
use crate::pow::{CompactTarget, Target, Work};
use crate::prelude::*;
use crate::{io, merkle_tree, VarInt};

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
}

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time);

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits)
    pub const SIZE: usize = 4 + 32 + 32 + 4 + 4 + 4; // 80

    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target { Target::ZERO }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 { self.target().difficulty() }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 { self.target().difficulty_float() }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let target = self.target();
        if target != required_target {
            return Err(ValidationError::BadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work { self.target().to_work() }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .finish()
    }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn from_consensus(v: i32) -> Self { Version(v) }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 { self.0 }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version { Self::NO_SOFT_FORK_SIGNALLING }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash { self.header.block_hash() }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base block size.
    ///
    /// > Base size is the block size in bytes with the original transaction serialization without
    /// > any witness-related data, as seen by a non-upgraded node.
    fn base_size(&self) -> usize {
        let mut size = Header::SIZE;

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = Header::SIZE;

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    /// Returns the stripped size of the block.
    #[deprecated(since = "0.31.0", note = "use Block::base_size() instead")]
    pub fn strippedsize(&self) -> usize { self.base_size() }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> { self.txdata.first() }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash { header.block_hash() }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash { header.block_hash() }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash { block.block_hash() }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash { block.block_hash() }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;

        match *self {
            BadProofOfWork => f.write_str("block target correct but not attained"),
            BadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ValidationError::*;

        match *self {
            BadProofOfWork | BadTarget => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }

    #[test]
    fn block_test() {
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e490201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e490201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = Work::from(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 1);
        assert_eq!(real_decode.header.difficulty_float(), 1.0);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let segwit_block = hex!("000000202aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d7490600000000000010bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e5503bd570f010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a3983704012000000000000000000000000000000000000000000000000000000000000000000000000001000000017e4f81175332a733e26d4ba4e29f53f67b7a5d7c2adebb276e447ca71d130b55000000006b483045022100cac809cd1a3d9ad5d5e31a84e2e1d8ec5542841e4d14c6b52e8b38cbe1ff1728022064470b7fb0c2efeccb2e84bfa36ec5f9e434c84b1101c00f7ee32f726371b7410121020e62280798b6b8c37f068df0915b0865b63fabc401c2457cbc3ef96887dd3647ffffffff02ca2f780c000000001976a914c6b5545b3592cb477d709896fa705592c9b6113a88ac663b2a06000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac0000000001000000011e99f5a785e677e017d36b50aa4fd10010ffd039f38f42f447ca8895250e121f01000000d90047304402200d3d296ad641a281dd5c0d68b9ab0d1ad5f7052bec148c1fb81fb1ba69181ec502201a372bb16fb8e054ee9bef41e300d292153830f841a4db0ab7f7407f6581b9bc01473044022002584f313ae990236b6bebb82fbbb006a2b02a448dd5c93434428991eae960d60220491d67d2660c4dde19025cf86e5164a559e2c79c3b98b40e146fab974acd24690147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9140ffdcf96700455074292a821c74922e8652993998788997bc60000000017a9148ce5408cfeaddb7ccb2545ded41ef478109454848700000000010000000113100b09e6a78d63ec4850654ab0f68806de29710b09172eddfef730652b155501000000da00473044022015389408e3446a3f36a05060e0e4a3c8b92ff3901ba2511aa944ec91a537a1cb022045a33b6ec47605b1718ed2e753263e54918edbf6126508ff039621fb928d28a001483045022100bb952fde81f216f7063575c0bb2bedc050ce08c96d9b437ea922f5eb98c882da02201b7cbf3a2f94ea4c5eb7f0df3af2ebcafa8705af7f410ab5d3d4bac13d6bc6120147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914d3db9a20312c3ab896a316eb108dbd01e47e17d687e0ba7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000016e3cca1599cde54878e2f27f434df69df0afd1f313cb6e38c08d3ffb57f97a6c01000000da0048304502210095623b70ec3194fa4037a1c1106c2580caedc390e25e5b330bbeb3111e8184bc02205ae973c4a4454be2a3a03beb66297143c1044a3c4743742c5cdd1d516a1ad3040147304402202f3d6d89996f5b42773dd6ebaf367f1af1f3a95c7c7b487ec040131c40f4a4a30220524ffbb0b563f37b3eb1341228f792e8f84111b7c4a9f49cdd998e052ee42efa0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9141ade6b95896dde8ec4dee9e59af8849d3797348e8728af7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000011d9dc3a5df9b5b2eeb2bd11a2db243be9e8cc23e2f180bf317d32a499904c15501000000db00483045022100ebbd1c9a8ce626edbb1a7881df81e872ef8c6424feda36faa8a5745157400c6a02206eb463bc8acd5ea06a289e86115e1daae0c2cf10d9cbbd199e1311170d5543ef01483045022100809411a917dc8cf4f3a777f0388fdea6de06243ef7691e500c60abd1c7f19ae602205255d2b1191d8adedb77b814ccb66471eb8486cb4ff8727824254ee5589f176b0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914759a49c772347be81c49517f9e1e6def6a88d4dd87800b85c60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704f0000006a47304402201be0d485f6a3ce871be80064c593c5327b3fd7e450f05ab7fae38385bc40cfbe02206e2a6c9970b5d1d10207892376733757486634fce4f352e772149c486857612101210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704e0000006b483045022100ccc8c0ac90bdb0402842aec91830c765cdead7a728552a6a34de7d13a6dab28e02206c96f8640cf3444054e9632b197be30598a09c3d5defcd95750bdb922a60d64801210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000011b436669c06cbf3442e21a2fe3edc20cd3cf13c358c53234bc4d88bfd8c4bd2a000000006a47304402204a63410ee13db52c7609ab08e25b7fe3c608cc21cc1755ad13460685eb55193202204cd1ea80c06a81571119be0b8cccd96ef7cdd90f62c1fe2d538622feb08e22ba0121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d64523365345261445653324d436a736e536171734a5753324465655446624238354541794a4d5843784c7934000000000100000001be4a95ed36316cada5118b1982e4cb4a07f93e7a4153e227466f1cb0776de995000000006b483045022100a22d5251deea0470806bab817013d675a63cd52218d6e477ab0c9d601d018b7f022042121b46afcdcd0c66f189398212b66085e88c6973ae560f1810c13e55e2bee40121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d57484d57504e5248515872504c7338554c586b4d483746745356413675366b5a6b4a4e3851796e4e583751340000000001000000016c061a65b49edec21acdbc22f97dc853aa872302aeef13fabf0bf6807de1b8bd010000006b483045022100dd80381f2d158b4dad7f98d2d97317c533fb36e737542473feb05fa74d0b73bb02207097d4331196069167e525b61d132532292fd75cc039a5839c04c2545d427e2b0121035e9a597df8b417bef66811882a2844604fc591c427f642628f0fef46be19a4c9feffffff0280a4bf07000000001976a914573b9106e16ee0b5c143dc40f0724f77dd0e282088ac9533b22c000000001976a9149c4da607efb1d759d33da71778bc6cafa56acb5988acd31b0e0001000000017dae20994b69b28534e5b22f3d7c50f9d7541348cbf6f43fcc654263ebaf8f68000000006b483045022100a85300eb94b24b044877d0b0d61e08e16dbc82ec7d69c723a8a45519f95c35b002203d78376e6bee31b455c097557af7fe4d6b620bc74269e9a75e2aad2b545abddb012103b0d08aba2a5ac6cf2788fda941c386040e35e49d3a57d2aefb16c0438fb98acbfeffffff022222305f000000001976a914cfda30dd836b596db6a9c230c45ae2179107f04888ac80a4bf07000000001976a91442dfcf5823aacb185844e663873c35fb98bfd21b88acd31b0e000100000002ad3e85e4af30678a330f8941ed7a9ca17cd0236368d238cac4e9ff09c466fed1020000006b483045022100d1196c48a0392e09592f1b96b4aec32ab0cecb6fd17b1d0c85ab3250a2fe45d9022059217c82f684fcdecdbe660a2077ea956dfbbb964d2648bc1e8ae0f0fe565449012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff34f0a71c1c2cd610522e9c18c67931cded5e9647d4419c49b99715e2a0795f3d020000006a4730440220316e81d8242abf3c5f885d200feca12c3adb63cf2cd4dc74602f7b8b0cba50340220210d525758df77ccdca6908311c1895275e07bbb29b45963a19252acde55873f012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff0510270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788ac10270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788aca0860100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac70110100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac0000000000000000026a000000000001000000018e33fecc2ddbd86c5ea919f7bd5a5acf8a09f3e0cdaaaf4f08c5ef095161ef1100000000fdfe0000483045022100d2489b225d39b7d8b6767a6928c8029a2a1297c08fdf00d683ba0c1987e7d7000220176cb66c8a243806bb7421f658325a69a51c82c0c3314e37f2400f33626390210148304502210096cfa57662a545830d0e29610becd41ea031e256339913718ce18dbb1a27bdb00220482911c851d15adcd37097dff99a9ff1f97d953bcebc528835118f447412553e014c695221028d9889862b29430278c084b5c4090b7b807b31e047bcd212ebc2c4e43fc0e3c52103160949a7c8c81f2c25d7763f57eb1cb407d867c5b7c290331bd2dc4b1182c6d32103fbef3b60914bda9173765902013a251ec89450c75d0b5a96a143db1dabf98d9553aeffffffff0220e8891c0100000017a914d996715e081c50f8f6b1b4e7fb6ca214f9924fdf87809698000000000017a9145611d812263f32960228cb5f85329bce4770a218870000000001000000017720507dcbe6c69f652b0c0ce19406f482372d1a8abc05d45fb7acf97fb80eec00000000fdfe00004830450221009821d8e117de44b1202c829c0f5063997acf007cf9b561c6fb8d1212cddb6c40022010ff5067b0d9d4eca2da0ceb876e9a16f1a2142da866d3042a7bae8968813e8001483045022100dea759d14a8a1c5da5f3dcc5509871aaa2c1e3be03752c1b858d80fa4227163702205183d70cc28dcb6df9b037714c8b6442ef84e0ddce07711a30c731e9f0925090014c695221028d70ea66fe7a7def282df7b2b498007e5072933e42c18f63ce85975dcbcf1a8821037e8f842b1e47e21d88002c5aab2559212a4c2c9dbe5ef5347f2a29afd0510ec1210251259cb9fd4f6206488408286e4475c9c9fe887e57a3e32ae4da222778a2aedf53aeffffffff023380cb020000000017a9143b5a7e85b22656a34d43187ac8dd09acd7109d2487809698000000000017a914b9b4b555f594a34deec3ad61d5c5f3738b17ee158700000000");

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(real_decode.base_size(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};
    use crate::EmptyWrite;

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
