// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;
use core::str::FromStr;

use hashes::hex::FromHex;
use hashes::{Hash, HashEngine};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::Transaction;
use crate::consensus::encode::{serialize_hex, Error};
use crate::consensus::{encode, serialize, Decodable, Encodable};
use crate::crypto::key::PublicKey;
use crate::crypto::schnorr::Signature;
pub use crate::hash_types::BlockHash;
use crate::hash_types::{BlockSigHash, TxMerkleNode, WitnessCommitment, WitnessMerkleNode, Wtxid, XFieldHash};
use crate::internal_macros::impl_consensus_encoding;
use crate::prelude::*;
use crate::{crypto, io, merkle_tree, VarInt};

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
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// MerkleRoot based on fixing malleability transaction hash
    pub im_merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// Extra field. This field can host any type of data defined in Tapyrus protocol.
    pub xfield: XField,
    /// Collection holds a signature for block hash which is consisted of block header without Proof.
    pub proof: Option<Signature>,
}

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, im_merkle_root, time)
    pub const SIZE: usize = 4 + 32 + 32 + 32 + 4; // 104

    /// Returns the block hash.
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

    /// Computes a signature hash for this block.
    /// Tapyrus signer needs to sign this hash. The signature will be added to
    /// the block header as the proof field and submitted to the tapyrus node.
    pub fn signature_hash(&self) -> BlockSigHash {
        let block = HeaderWithoutProof::from(self);
        BlockSigHash::hash(&serialize(&block))
    }

    /// Return the max block size in this BlockHeader
    pub fn max_block_size(&self) -> Option<u32> {
        match self.xfield {
            XField::MaxBlockSize(size) => Some(size),
            _ => None,
        }
    }
}

impl_consensus_encoding!(
    Header,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    xfield,
    proof
);

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("im_merkle_root", &self.im_merkle_root)
            .field("time", &self.time)
            .field("xfield", &self.xfield)
            .field("proof", &self.proof)
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

struct HeaderWithoutProof {
    version: Version,
    prev_blockhash: BlockHash,
    merkle_root: TxMerkleNode,
    im_merkle_root: TxMerkleNode,
    time: u32,
    xfield: XField,
}

impl HeaderWithoutProof {
    fn from(header: &Header) -> Self {
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

impl_consensus_encoding!(
    HeaderWithoutProof,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    xfield
);

/// An extra field that allows the block header to hold arbitrary data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
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
    /// Return field size
    pub fn size(&self) -> usize {
        match self {
            XField::None => 1,
            XField::AggregatePublicKey(_) => 35, // 1 + 1 + 33
            XField::MaxBlockSize(_) => 5, // 1 + 4
            XField::Unknown(_, data) => 1 + VarInt::from(data.len()).size() + data.len(),
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
        let bytes: Vec<u8> =
            Vec::from_hex(s).map_err(|_| encode::Error::ParseFailed("invalid hex string"))?;
        XField::consensus_decode(&mut &bytes[..])
    }
}

impl core::fmt::Display for XField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("hex string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                if let Ok(s) = ::core::str::from_utf8(v) {
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
    fn consensus_decode<D: io::Read + ?Sized>(mut d: &mut D) -> Result<Self, encode::Error> {
        let x_type: u8 = Decodable::consensus_decode(&mut d)?;
        match x_type {
            0 => Ok(XField::None),
            1 => {
                let bytes: Vec<u8> = Decodable::consensus_decode(&mut d)?;
                let pk = PublicKey::from_slice(&bytes)
                    .map_err(|_| encode::Error::ParseFailed("aggregate public key"))?;
                Ok(XField::AggregatePublicKey(pk))
            }
            2 => {
                let size: u32 = Decodable::consensus_decode(&mut d)?;
                Ok(XField::MaxBlockSize(size))
            }
            _ => {
                let data: Vec<u8> = Decodable::consensus_decode(&mut d)?;
                Ok(XField::Unknown(x_type, data))
            }
        }
    }
}

impl Encodable for XField {
    #[inline]
    fn consensus_encode<S: io::Write + ?Sized>(&self, mut s: &mut S) -> Result<usize, io::Error> {
        self.field_type().consensus_encode(&mut s)?;
        match self {
            XField::None => Ok(1),
            XField::AggregatePublicKey(pk) => {
                let len = pk.to_bytes().consensus_encode(&mut s)?;
                Ok(1 + len)
            }
            XField::MaxBlockSize(size) => {
                let len = size.consensus_encode(&mut s)?;
                Ok(1 + len)
            }
            XField::Unknown(_type, data) => {
                let len = data.consensus_encode(&mut s)?;
                Ok(1 + len)
            }
        }
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

    /// Computes the merkle root of transactions using immutable hash
    pub fn immutable_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.malfix_txid());
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
        size += self.header.xfield.size();
        size += 1; // length of proof field
        if self.header.proof.is_some() {
            size += 2 * crypto::schnorr::SECP256K1_SCALAR_SIZE;
        }
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
        size += self.header.xfield.size();
        size += 1; // length of proof field
        if self.header.proof.is_some() {
            size += 2 * crypto::schnorr::SECP256K1_SCALAR_SIZE;
        }
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
    use core::str::FromStr;

    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize, Error};
    use crate::crypto::key::PublicKey;
    use crate::hash_types::BlockSigHash;

    #[test]
    #[ignore]
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
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e490121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af40f1453cd332262d74edf65f96688724b80a15c852fd50151e4aabc41a0d9560d2cd38f0746c3d9c9e18b236f20e37d0ae1bda457ea029db8a55b20f38143517d00201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e490121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.im_merkle_root, real_decode.immutable_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.aggregated_public_key().unwrap(), pk);
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
        let bytes =
            Vec::from_hex("0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")
                .unwrap();
        let decode: XField = deserialize(&bytes).unwrap();
        assert_eq!(serialize(&decode), bytes);

        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        assert_eq!(decode, XField::AggregatePublicKey(pk));

        let xfield = XField::from_str(
            "0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        );
        assert_eq!(xfield.unwrap(), XField::AggregatePublicKey(pk));
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

        let xfield =
            Vec::from_hex("0121032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")
                .unwrap();
        let decode: XField = deserialize(&xfield).unwrap();
        serde_round_trip!(decode);

        let xfield = Vec::from_hex("02000000ff").unwrap();
        let decode: XField = deserialize(&xfield).unwrap();
        serde_round_trip!(decode);
    }

    #[test]
    fn signature_hash_test() {
        let block = hex!("010000000000000000000000000000000000000000000000000000000000000000000000c1457ff3e5c527e69858108edf0ff1f49eea9c58d8d37300a164b3b4f8c8c7cef1a2e72770d547feae29f2dd40123a97c580d44fd4493de072416d53331997617b96f05d00403a4c09253c7b583e5260074380c9b99b895f938e37799d326ded984fb707e91fa4df2e0524a4ccf5fe224945b4fb94784b411a760eb730d95402d3383dd7ffdc01010000000100000000000000000000000000000000000000000000000000000000000000000000000022210366262690cbdf648132ce0c088962c6361112582364ede120f3780ab73438fc4bffffffff0100f2052a010000002776a9226d70757956774d32596a454d755a4b72687463526b614a787062715447417346484688ac00000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        assert_eq!(
            decode.unwrap().header.signature_hash(),
            BlockSigHash::from_str(
                "3d856f50e0718f72bab6516c1ab020ce3390ebc97490b6d2bad4054dc7a40a93"
            )
            .unwrap()
        );
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        let block2 = hex!("0000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
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
        assert_eq!(XField::MaxBlockSize(u32::MAX).size(), 5);
        assert_eq!(serialize(&decoded_max), max_size_bytes);

        // zero
        let zero_size_bytes = Vec::from_hex("00000000").unwrap();
        let decoded_zero:u32 = deserialize(&zero_size_bytes).unwrap();
        assert_eq!(XField::MaxBlockSize(0).size(), 5);
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
        // larger than u32::MAX
        let overflow_value:u64 = (u32::MAX as u64) + 1;
        let overflow_bytes = hex!(&format!("{:016x}", overflow_value));
        assert!(deserialize::<u32>(&overflow_bytes).is_err());
        assert!(XField::from_str(&format!("{:016x}", overflow_value)).is_err());
    }

    #[test]
    fn xfield_signature_hash_test_aggpubkey() {
        let xfield = XField::AggregatePublicKey(PublicKey::from_str("02459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806").unwrap());
        assert_eq!(serialize(&xfield), hex!("012102459adb8a8f052be94874aef7d4c3d3ddb71fcdaa869b1d515a92d63cb29c2806"));
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_str("5eb6038f90ec3b530ebed8789afd4f3f49af83fa4b00f34238c93ce0327ff9ad").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_maxblocksize() {
        let xfield = XField::MaxBlockSize(200000);
        assert_eq!(serialize(&xfield), hex!("02400d0300"));
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_str("b2a51fb82acc2125508f323fa9567340c32257997dfd4af4e70788031d5b1915").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_aggpubkey1() {
        let xfield = XField::AggregatePublicKey(PublicKey::from_str("0376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50").unwrap());
        assert_eq!(serialize(&xfield), hex!("01210376c3265e7d81839c1b2312b95697d47cc5b3ab3369a92a5af52ef1c945792f50"));
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_str("e70d5478d63e19ab2d9aa059340785b810f82cc288e83752e726a0f9817fcc88").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_maxblocksize1() {
        let xfield = XField::MaxBlockSize(400000);
        assert_eq!(serialize(&xfield), hex!("02801a0600"));
        assert_eq!(xfield.signature_hash().unwrap(), XFieldHash::from_str("7b5a43d2dae273d564ec0db616efe75a31725707fc3865124e3477684f5faec0").unwrap());
    }

    #[test]
    fn xfield_signature_hash_test_none() {
        let xfield = XField::None;
        let result = xfield.signature_hash();

        assert!(matches!(result, Err(Error::XFieldNone)));
    }

    #[test]
    fn xfield_signature_hash_test_unknown() {
        let xfield = XField::Unknown(3, hex!("012345"));
        let result = xfield.signature_hash();

        assert!(matches!(result, Err(Error::UnknownXField(3))));
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};
    use crate::EmptyWrite;

    #[bench]
    #[ignore]
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
    #[ignore]
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
    #[ignore]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    #[ignore]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
