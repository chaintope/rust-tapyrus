//! The colored Identifier is a special identifier that is used to identify a colored coin.
//!
//! > When OP_COLOR opcode appears in a script, the top element of the stack is popped which
//! > interpreted as a COLOR identifier. The script will fail if there are no elements left
//! > in the stack, or if the COLOR identifier does not matched the rules described below.
//! > If the COLOR identifier matches to the rule, the coin of the UTXO represents the amount
//! > of the coin for the COLOR identifier. Script which does not include OP_COLOR represents
//! > to the amount of the default token TPC (tapyrus).
//!
//! [Colored Coin]: <https://github.com/chaintope/tapyrus-core/blob/master/doc/tapyrus/colored_coin.md>

use core::convert::TryFrom;
use core::fmt;

use hashes::{Hash, sha256};
use crate::consensus::{Decodable, Encodable, encode, serialize};
use crate::blockdata::script::Script;
use crate::blockdata::transaction::OutPoint;
use crate::consensus::encode::serialize_hex;
use crate::script::PushBytesBuf;
use crate::io;

/// ColorIdentifier
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ColorIdentifier {
    /// Token type
    pub token_type: TokenTypes,
    /// Payload
    payload: ColorIdentifierPayload,
}

impl ColorIdentifier {
    /// initialize ColorIdentifier with type Reissuable
    pub fn reissuable(script_pubkey: &Script) -> Self {
        let mut enc = ColorIdentifierPayload::engine();
        script_pubkey.consensus_encode(&mut enc).unwrap();
        ColorIdentifier {
            token_type: TokenTypes::Reissuable,
            payload: ColorIdentifierPayload::from_engine(enc),
        }
    }

    /// initialize ColorIdentifier with type Non Reissuable
    pub fn non_reissuable(out_point: OutPoint) -> Self {
        let mut enc = ColorIdentifierPayload::engine();
        out_point.consensus_encode(&mut enc).unwrap();
        ColorIdentifier {
            token_type: TokenTypes::NonReissuable,
            payload: ColorIdentifierPayload::from_engine(enc),
        }
    }

    /// initialize ColorIdentifier with type Nft
    pub fn nft(out_point: OutPoint) -> Self {
        let mut enc = ColorIdentifierPayload::engine();
        out_point.consensus_encode(&mut enc).unwrap();
        ColorIdentifier {
            token_type: TokenTypes::Nft,
            payload: ColorIdentifierPayload::from_engine(enc),
        }
    }

    /// Check if the color identifier is colored
    pub fn is_colored(&self) -> bool {
        self.token_type != TokenTypes::None
    }

    /// Check if the color identifier is TPC
    pub fn is_default(&self) -> bool {
        self.token_type == TokenTypes::None
    }
}

impl Default for ColorIdentifier {
    fn default() -> Self {
        ColorIdentifier {
            token_type: TokenTypes::None,
            payload: ColorIdentifierPayload::all_zeros(),
        }
    }
}

impl Encodable for ColorIdentifier {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.token_type.consensus_encode(w)?;
        len += self.payload.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for ColorIdentifier {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let token_type = TokenTypes::consensus_decode(r)?;
        let payload = ColorIdentifierPayload::consensus_decode(r)?;
        Ok(ColorIdentifier {
            token_type,
            payload,
        })
    }
}

impl fmt::Display for ColorIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", serialize_hex(self))
    }
}

impl From<ColorIdentifier> for PushBytesBuf {
    fn from(color_id: ColorIdentifier) -> Self {
        PushBytesBuf::try_from(serialize(&color_id)).unwrap()
    }
}

hashes::hash_newtype! {
    /// A color identifier payload hash
    pub struct ColorIdentifierPayload(sha256::Hash);
}

crate::hash_types::impl_hashencode!(ColorIdentifierPayload);

/// Token types
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum TokenTypes {
    /// TPC
    None = 0x00,
    /// Reissuable
    Reissuable = 0xc1,
    /// Non reissuable
    NonReissuable = 0xc2,
    /// Non fungible token
    Nft = 0xc3,
}

impl TokenTypes {
    /// return true if token type is supported
    pub fn is_valid(token_type: &u8) -> bool {
        [
            TokenTypes::None,
            TokenTypes::Reissuable,
            TokenTypes::NonReissuable,
            TokenTypes::Nft
        ].iter().any(|e| *e as u8 == *token_type)
    }
}

impl Encodable for TokenTypes {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (*self as u8).consensus_encode(w)
    }
}

impl Decodable for TokenTypes {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let token_type = u8::consensus_decode(r)?;
        match token_type {
            0x00 => Ok(TokenTypes::None),
            0xc1 => Ok(TokenTypes::Reissuable),
            0xc2 => Ok(TokenTypes::NonReissuable),
            0xc3 => Ok(TokenTypes::Nft),
            _ => Err(encode::Error::ParseFailed("Unknown token type")),
        }
    }
}

/// Error occured with colored coin
#[derive(Debug)]
pub enum ColoredCoinError {
    /// original script is not based p2pkh and p2sh
    UnsupportedScriptType,
}
