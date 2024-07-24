// SPDX-License-Identifier: CC0-1.0

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
//!

#![allow(deprecated)] // Remove once we remove XpubIdentifier.

use core::convert::TryInto;
use core::default::Default;
use core::ops::Index;
use core::str::FromStr;
use core::{fmt, slice};

use hashes::{hash160, hash_newtype, sha512, Hash, HashEngine, Hmac, HmacEngine};
use internals::{impl_array_newtype, write_err};
use secp256k1::{self, Secp256k1, XOnlyPublicKey};
#[cfg(feature = "serde")]
use serde;

use crate::base58;
use crate::crypto::key::{self, Keypair, PrivateKey, PublicKey};
use crate::internal_macros::impl_bytes_newtype;
use crate::io::Write;
use crate::network::Network;
use crate::prelude::*;

/// Version bytes for extended public keys on the Tapyrus network.
const VERSION_BYTES_PROD_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Version bytes for extended private keys on the Tapyrus network.
const VERSION_BYTES_PROD_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Version bytes for extended public keys on any of the dev networks.
const VERSION_BYTES_DEV_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Version bytes for extended private keys on any of the dev networks.
const VERSION_BYTES_DEV_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// The old name for xpub, extended public key.
#[deprecated(since = "0.31.0", note = "use xpub instead")]
pub type ExtendendPubKey = Xpub;

/// The old name for xpriv, extended public key.
#[deprecated(since = "0.31.0", note = "use xpriv instead")]
pub type ExtendendPrivKey = Xpriv;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_bytes_newtype!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..].try_into().expect("half of hmac is guaranteed to be 32 bytes")
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_bytes_newtype!(Fingerprint, 4);

hash_newtype! {
    /// XpubIdentifier as defined in BIP-32.
    #[deprecated(since = "0.0.0-NEXT-RELEASE", note = "use XKeyIdentifier instead")]
    pub struct XpubIdentifier(hash160::Hash);

    /// Extended key identifier as defined in BIP-32.
    pub struct XKeyIdentifier(hash160::Hash);
}

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Xpriv {
    /// The network this key is to be used on
    pub network: Network,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: secp256k1::SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(Xpriv, "a BIP-32 extended private key");

#[cfg(not(feature = "std"))]
impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[SecretKey]")
            .finish()
    }
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub {
    /// The network this key is to be used on
    pub network: Network,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(Xpub, "a BIP-32 extended public key");

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool { !self.is_hardened() }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Hardened { .. } => true,
            ChildNumber::Normal { .. } => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal { index: idx } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened { index: idx } => ChildNumber::from_hardened_idx(idx + 1),
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened { index: number ^ (1 << 31) }
        } else {
            ChildNumber::Normal { index: number }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | (1 << 31),
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened { index } => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_str(if alt { "h" } else { "'" })
            }
            ChildNumber::Normal { index } => fmt::Display::fmt(&index, f),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildNumber::from_hardened_idx(
                inp[0..inp.len() - 1].parse().map_err(|_| Error::InvalidChildNumberFormat)?,
            )?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        })
    }
}

impl AsRef<[ChildNumber]> for ChildNumber {
    fn as_ref(&self) -> &[ChildNumber] { slice::from_ref(self) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Convers a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(DerivationPath, "a BIP-32 derivation path");

impl<I> Index<I> for DerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl Default for DerivationPath {
    fn default() -> DerivationPath { DerivationPath::master() }
}

impl<T> IntoDerivationPath for T
where
    T: Into<DerivationPath>,
{
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { Ok(self.into()) }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl<'a> IntoDerivationPath for &'a str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self { DerivationPath(numbers) }
}

impl From<DerivationPath> for Vec<ChildNumber> {
    fn from(path: DerivationPath) -> Self { path.0 }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self { DerivationPath(numbers.to_vec()) }
}

impl core::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> core::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] { &self.0 }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        let mut parts = path.split('/');
        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(Error::InvalidDerivationPathFormat);
        }

        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_from],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator { base: path, next_child: Some(start) }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Returns length of the derivation path
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns derivation path for a master key (i.e. empty derivation path)
    pub fn master() -> DerivationPath { DerivationPath(vec![]) }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    pub fn is_master(&self) -> bool { self.0.is_empty() }

    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Normal { index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Hardened { index: 0 })
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use tapyrus::bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/42").unwrap();
    ///
    /// let deriv_1 = base.extend(DerivationPath::from_str("m/0/1").unwrap());
    /// let deriv_2 = base.extend(&[
    ///     ChildNumber::from_normal_idx(0).unwrap(),
    ///     ChildNumber::from_normal_idx(1).unwrap()
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    pub fn extend<T: AsRef<[ChildNumber]>>(&self, path: T) -> DerivationPath {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }

    /// Returns the derivation path as a vector of u32 integers.
    /// Unhardened elements are copied as is.
    /// 0x80000000 is added to the hardened elements.
    ///
    /// ```
    /// use tapyrus::bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap();
    /// const HARDENED: u32 = 0x80000000;
    /// assert_eq!(path.to_u32_vec(), vec![84 + HARDENED, HARDENED, HARDENED, 0, 1]);
    /// ```
    pub fn to_u32_vec(&self) -> Vec<u32> { self.into_iter().map(|&el| el.into()).collect() }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for cn in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(cn, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self, f) }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Secp256k1(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Hexadecimal decoding error
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            CannotDeriveFromHardenedKey =>
                f.write_str("cannot derive hardened key from public key"),
            Secp256k1(ref e) => write_err!(f, "secp256k1 error"; e),
            InvalidChildNumber(ref n) =>
                write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n),
            InvalidChildNumberFormat => f.write_str("invalid child number format"),
            InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            UnknownVersion(ref bytes) => write!(f, "unknown version magic bytes: {:?}", bytes),
            WrongExtendedKeyLength(ref len) =>
                write!(f, "encoded extended key data has wrong length {}", len),
            Base58(ref e) => write_err!(f, "base58 encoding error"; e),
            Hex(ref e) => write_err!(f, "Hexadecimal decoding error"; e),
            InvalidPublicKeyHexLength(got) =>
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            Base58(ref e) => Some(e),
            Hex(ref e) => Some(e),
            CannotDeriveFromHardenedKey
            | InvalidChildNumber(_)
            | InvalidChildNumberFormat
            | InvalidDerivationPathFormat
            | UnknownVersion(_)
            | WrongExtendedKeyLength(_)
            | InvalidPublicKeyHexLength(_) => None,
        }
    }
}

impl From<key::Error> for Error {
    fn from(err: key::Error) -> Self {
        match err {
            key::Error::Base58(e) => Error::Base58(e),
            key::Error::Secp256k1(e) => Error::Secp256k1(e),
            key::Error::InvalidKeyPrefix(_) => Error::Secp256k1(secp256k1::Error::InvalidPublicKey),
            key::Error::Hex(e) => Error::Hex(e),
            key::Error::InvalidHexLength(got) => Error::InvalidPublicKeyHexLength(got),
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self { Error::Base58(err) }
}

impl Xpriv {
    /// Construct a new master key from a seed value
    pub fn new_master(network: Network, seed: &[u8]) -> Result<Xpriv, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Tapyrus seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(Xpriv {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Constructs ECDSA compressed private key matching internal secret key representation.
    pub fn to_priv(self) -> PrivateKey {
        PrivateKey { compressed: true, network: self.network, inner: self.private_key }
    }

    /// Constructs BIP340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair<C: secp256k1::Signing>(self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_seckey_slice(secp, &self.private_key[..])
            .expect("BIP32 internal private key representation is broken")
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<Xpriv, Error> {
        let mut sk: Xpriv = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Xpriv, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }

        hmac_engine.input(&u32::from(i).to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Ok(Xpriv {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Decoding extended private key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpriv, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_PROD_PRIVATE) {
            Network::Prod
        } else if data.starts_with(&VERSION_BYTES_DEV_PRIVATE) {
            Network::Dev
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpriv {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        })
    }

    /// Extended private key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            Network::Prod => VERSION_BYTES_PROD_PRIVATE,
            Network::Dev => VERSION_BYTES_DEV_PRIVATE,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XKeyIdentifier {
        Xpub::from_priv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl Xpub {
    /// Derives a public key from a private key
    pub fn from_priv<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &Xpriv) -> Xpub {
        Xpub {
            network: sk.network,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
        }
    }

    /// Constructs ECDSA compressed public key matching internal public key representation.
    pub fn to_pub(self) -> PublicKey { PublicKey { compressed: true, inner: self.public_key } }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_pub(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<ChildNumber>`, such as `DerivationPath`, for instance.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<Xpub, Error> {
        let mut pk: Xpub = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(
        &self,
        i: ChildNumber,
    ) -> Result<(secp256k1::SecretKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened { .. } => Err(Error::CannotDeriveFromHardenedKey),
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.serialize()[..]);
                hmac_engine.input(&n.to_be_bytes());

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from_hmac(hmac_result);
                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Xpub, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into())?;

        Ok(Xpub {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpub, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_PROD_PUBLIC) {
            Network::Prod
        } else if data.starts_with(&VERSION_BYTES_DEV_PUBLIC) {
            Network::Dev
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpub {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            Network::Prod => VERSION_BYTES_PROD_PUBLIC,
            Network::Dev => VERSION_BYTES_DEV_PUBLIC,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XKeyIdentifier {
        let mut engine = XKeyIdentifier::engine();
        engine.write_all(&self.public_key.serialize()).expect("engines don't error");
        XKeyIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier()[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl fmt::Display for Xpriv {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpriv {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpriv, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()).into());
        }

        Xpriv::decode(&data)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpub {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpub, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(base58::Error::InvalidLength(data.len()).into());
        }

        Xpub::decode(&data)
    }
}

impl From<Xpub> for XKeyIdentifier {
    fn from(key: Xpub) -> XKeyIdentifier { key.identifier() }
}

impl From<&Xpub> for XKeyIdentifier {
    fn from(key: &Xpub) -> XKeyIdentifier { key.identifier() }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;
    use secp256k1::{self, Secp256k1};

    use super::ChildNumber::{Hardened, Normal};
    use super::*;
    use crate::network::Network::{self, Prod};

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(DerivationPath::from_str("42"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("n/0'/0"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("4/m/5"), Err(Error::InvalidDerivationPathFormat));
        assert_eq!(DerivationPath::from_str("m//3/0'"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(DerivationPath::from_str("m/0h/0x"), Err(Error::InvalidChildNumberFormat));
        assert_eq!(
            DerivationPath::from_str("m/2147483648"),
            Err(Error::InvalidChildNumber(2147483648))
        );

        assert_eq!(DerivationPath::master(), DerivationPath::from_str("m").unwrap());
        assert_eq!(DerivationPath::master(), DerivationPath::default());
        assert_eq!(DerivationPath::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened_idx(0).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap()
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1/2'"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2h/2"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1/2'/2/1000000000"),
            Ok(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(2).unwrap(),
                ChildNumber::from_normal_idx(2).unwrap(),
                ChildNumber::from_normal_idx(1000000000).unwrap(),
            ]
            .into())
        );
        let s = "m/0'/50/3'/5/545456";
        assert_eq!(DerivationPath::from_str(s), s.into_derivation_path());
        assert_eq!(DerivationPath::from_str(s), s.to_string().into_derivation_path());
    }

    #[test]
    fn test_derivation_path_conversion_index() {
        let path = DerivationPath::from_str("m/0h/1/2'").unwrap();
        let numbers: Vec<ChildNumber> = path.clone().into();
        let path2: DerivationPath = numbers.into();
        assert_eq!(path, path2);
        assert_eq!(
            &path[..2],
            &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()]
        );
        let indexed: DerivationPath = path[..2].into();
        assert_eq!(indexed, DerivationPath::from_str("m/0h/1").unwrap());
        assert_eq!(indexed.child(ChildNumber::from_hardened_idx(2).unwrap()), path);
    }

    fn test_path<C: secp256k1::Signing + secp256k1::Verification>(
        secp: &Secp256k1<C>,
        network: Network,
        seed: &[u8],
        path: DerivationPath,
        expected_sk: &str,
        expected_pk: &str,
    ) {
        let mut sk = Xpriv::new_master(network, seed).unwrap();
        let mut pk = Xpub::from_priv(secp, &sk);

        // Check derivation convenience method for Xpriv
        assert_eq!(&sk.derive_priv(secp, &path).unwrap().to_string()[..], expected_sk);

        // Check derivation convenience method for Xpub, should error
        // appropriately if any ChildNumber is hardened
        if path.0.iter().any(|cnum| cnum.is_hardened()) {
            assert_eq!(pk.derive_pub(secp, &path), Err(Error::CannotDeriveFromHardenedKey));
        } else {
            assert_eq!(&pk.derive_pub(secp, &path).unwrap().to_string()[..], expected_pk);
        }

        // Derive keys, checking hardened and non-hardened derivation one-by-one
        for &num in path.0.iter() {
            sk = sk.ckd_priv(secp, num).unwrap();
            match num {
                Normal { .. } => {
                    let pk2 = pk.ckd_pub(secp, num).unwrap();
                    pk = Xpub::from_priv(secp, &sk);
                    assert_eq!(pk, pk2);
                }
                Hardened { .. } => {
                    assert_eq!(pk.ckd_pub(secp, num), Err(Error::CannotDeriveFromHardenedKey));
                    pk = Xpub::from_priv(secp, &sk);
                }
            }
        }

        // Check result against expected base58
        assert_eq!(&sk.to_string()[..], expected_sk);
        assert_eq!(&pk.to_string()[..], expected_pk);
        // Check decoded base58 against result
        let decoded_sk = Xpriv::from_str(expected_sk);
        let decoded_pk = Xpub::from_str(expected_pk);
        assert_eq!(Ok(sk), decoded_sk);
        assert_eq!(Ok(pk), decoded_pk);
    }

    #[test]
    fn test_increment() {
        let idx = 9345497; // randomly generated, I promise
        let cn = ChildNumber::from_normal_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_normal_idx(idx + 1).unwrap()));
        let cn = ChildNumber::from_hardened_idx(idx).unwrap();
        assert_eq!(cn.increment().ok(), Some(ChildNumber::from_hardened_idx(idx + 1).unwrap()));

        let max = (1 << 31) - 1;
        let cn = ChildNumber::from_normal_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));
        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        assert_eq!(cn.increment().err(), Some(Error::InvalidChildNumber(1 << 31)));

        let cn = ChildNumber::from_normal_idx(350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/350".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/351".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.normal_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1".parse().unwrap()));

        let path = DerivationPath::from_str("m/42'/350'").unwrap();
        let mut iter = path.hardened_children();
        assert_eq!(iter.next(), Some("m/42'/350'/0'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/350'/1'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(42350).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert_eq!(iter.next(), Some("m/42'/42350'".parse().unwrap()));
        assert_eq!(iter.next(), Some("m/42'/42351'".parse().unwrap()));

        let cn = ChildNumber::from_hardened_idx(max).unwrap();
        let path = DerivationPath::from_str("m/42'").unwrap();
        let mut iter = path.children_from(cn);
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_vector_1() {
        let secp = Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        // m
        test_path(&secp, Prod, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K2xjLUb6KPjDjExyBLXq6K9u1gGQVMLyvewCLXdivoY7w3iRxAk1eX7k51Dxy71QdfRSQMmiMUGUi5iKfsKh2wfZVEGcqXEe",
                  "xpub661MyMwAqRbcFSooacdKksATnzofjzYwgNpcUep6ugWuXjXV5B3BMLSQu1eaiuxJ5zdoKt6ZcnpMi8mz2XHDHg8qSNWZpNnKABKxGetVSeG");

        // m/0h
        test_path(&secp, Prod, &seed, "m/0h".parse().unwrap(),
                  "xprv9uFM9iJccmW8MWthq313xGRzCStfizbMbuoFc7e3bherrNG4n7pxxeZnbt5xL3C4apsWhDp5xHqJVYTXaEZym1QxYutBNzsbA3KNN3brxYg",
                  "xpub68EhZDqWT94RZzyAw4Y4KQNikUjA8TKCy8irQW3fA3BqjAbDKf9DWStGTAq9yngbomLc1kWLcTsif1Q3K81CAtajweZiJgzYoBf3ok5siog");

        // m/0h/1
        test_path(&secp, Prod, &seed, "m/0h/1".parse().unwrap(),
                   "xprv9xby4JDYU1wVTmtDez13fFZYwujZNjCnuog6uMJDok16SnZnKaCxZNcqC4yGX7y7EzkCCtp8zdowyapkCAmZ48Qcw5SdPcAmYC4GyAaq17w",
                   "xpub6BbKTokSJPVngFxgm1Y42PWHVwa3nBveH2bhhjhqN5Y5Katvs7XD7AwK3LAx9RQfdHjLNXYgMx9pav9de2VDZ3ovqZfhYsqhXdN1D8ZknGV");

        // m/0h/1/2h
        test_path(&secp, Prod, &seed, "m/0h/1/2h".parse().unwrap(),
                  "xprv9yHeFHDADn4TthzzG64pa8fN4oJ1hXaErdbTwenLijZZepW8KRvFrXHUyXxV9YZefWYLnwLcRDBufF2ZcdNBeKagGtEYmC3deGVrKJfUN7h",
                  "xpub6CGzenk449cm7C5TN7bpwGc6cq8W6zJ6DrX4k3BxH56YXcqGryEWQKbxpoGaV5SiD6JpEvE7vCrkQxHmyWka33JpLJuCjbR1XGBQrK7kCJR");

        // m/0h/1/2h/2
        test_path(&secp, Prod, &seed, "m/0h/1/2h/2".parse().unwrap(),
                  "xprvA1sfG8WVX65Z2fnP4nbcKqhU4u8X2ZhDnafhLapjgar7kVFNJkHB9m46iRjyMRniTSU6Ftop4oQBarK2VaptXCHwBxN2JyeE3HZCdWj3naS",
                  "xpub6Es1fe3PMTdrF9rrAp8cgyeCcvy1S2R59obJ8yEMEvP6dHaWrHbRhZNaZhD1U3BK91axZiTZFTV9Tizr1X5D4yemBn59HqpGjqc4ijMrN2Y");

        // m/0h/1/2h/2/1000000000
        test_path(&secp, Prod, &seed, "m/0h/1/2h/2/1000000000".parse().unwrap(),
                  "xprvA39ZwpCsVGrRgnS4n7Ub6s4RPYMqsD64zPpdmm6pD6SNjEc2LTHha47jbqYxBSKNL4cuyMCxk1b44oiApcAd8uH89UYb4Hj7RmUQBJH3bmu",
                  "xpub6G8vMKjmKeQiuGWXt91bU119waCLGfovMckEa9WRmRyMc2wAszbx7rSDT6tmshb7WRQsuEbYPCdGsUrCKDxAdoPv59neBYeAaEMGQPeAgNy");
    }

    #[test]
    fn test_vector_2() {
        let secp = Secp256k1::new();
        let seed = hex!("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

        // m
        test_path(&secp, Prod, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K3EAWtaFfWyKZ4wZYY8EritwZ7t8Q1CjU2sAF2A6STEAcvE18D4NErHh4zdGYysW7GYbykLp5cnFeFUzgNQaevEX56YV4MfL",
                  "xpub661MyMwAqRbcFiEyzbnft7GHcyQ2waxi67s9vGY1ZYGSufVPZhQh12V6mTVtGMVZVNZ6pUA1sJjkPQzcSp3Yy1KrbKbYB2j2prTCLQ5q5xU");

        // m/0
        test_path(&secp, Prod, &seed, "m/0".parse().unwrap(),
                  "xprv9uNreJ4cFzMXpxuys3mL2oWZvBdDqLzRJcjKEaryur7g89ZJPidyoA2FHN65ugspw18VBNYhEcqwQKez6RPPvfvVp4jnZpv8zpEDEPmUas8",
                  "xpub68ND3obW6Muq3SzSy5JLPwTJUDTiEoiGfqev2yGbUBeezwtSwFxELxLj8e9T4N92dNmfcdheGw29NPGe4i3rYeAecJxMmMgKoV6JfDCwDYu");

        // m/0/2147483647h
        test_path(&secp, Prod, &seed, "m/0/2147483647h".parse().unwrap(),
                  "xprv9xAAhXL9iBW14jQBobrkXTJAuKgbtrbjKukd8miYZL6npywgwi8MqzENDt2zMfQhcduM5zLq1Efs3oNTQZJ2RTsbKrnyusrdxyewDk5cQtt",
                  "xpub6B9X72s3YZ4JHDUeudPktbEuTMX6JKKah8gDwA8A7fdmhnGqVFScPnYr5CXoV7gbJyQSKU9pZhqjnA4gUHpGba1T2gBphsQi76NJBtePzrE");

        // m/0/2147483647h/1
        test_path(&secp, Prod, &seed, "m/0/2147483647h/1".parse().unwrap(),
                  "xprv9xsheafKD5fYcGJWkNFdsX8St5XF13E9j8h5CVeKEgkpYrRvL6zQdm5Ex7gVC32CLFoVU3zKeGrrvLqJF1ZouBirmMWvK24eFTy9xN3vAch",
                  "xpub6Bs446CD3TDqpkNyrPneEf5BS7MjQVx16Mcfzt3vo2HoRem4seJfBZPioQ2JE3KjLYBxxu3ezCbCg5nv1JJeBNKPXgPBZQLBQxcHC9bdg8a");

        // m/0/2147483647h/1/2147483646h
        test_path(&secp, Prod, &seed, "m/0/2147483647h/1/2147483646h".parse().unwrap(),
                  "xprvA16mAad8fZ2LQvPiCyMbaonMQGfQCbEQXUkpUqJ34D6hjUsHa4tEFiubS9n9QKtMEwHS2zupnC6ENGyNWDcTQAGDhDYb9fqkE7KedNoN8jq",
                  "xpub6E67a6A2VvaddQUBJztbwwj5xJVtc3xFthgRHDhecYdgcHCS7cCUoXE5HRhPgSDx4H1Y6qLbT5PtTjxomcvadXe2seaj4uzQG5kRs1o2Unb");

        // m/0/2147483647h/1/2147483646h/2
        test_path(&secp, Prod, &seed, "m/0/2147483647h/1/2147483646h/2".parse().unwrap(),
                  "xprvA3miAHhnL1mo7oKJ9SgmQdUHfEmsbiPUyUorxoiuJXnQTp4kKiYAF6aDxLKpFTQ6mzsACWa7oC7p44S9h8dkCiHWcQjQL1vNyJWGn4BrCpP",
                  "xpub6Gm4ZoEgAPL6LHPmFUDmmmR2DGcN1B7LLhjTmC8WrsKPLcPtsFrQntthobzSvu7t8uiBD1GkK6jek6Life3QvWygRYkAegjuFNTK1v1F858");
    }

    #[test]
    fn test_vector_3() {
        let secp = Secp256k1::new();
        let seed = hex!("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

        // m
        test_path(&secp, Prod, &seed, "m".parse().unwrap(),
                  "xprv9s21ZrQH143K3xbnDaEaYrFEsVkzYXtcHdiwwmug5RfE15ZETjXpBeWVBrJA6HFJWMLNK4U7U9MiWVyA1Q3uRoKdKhhKdozE6YALH8r5dEr",
                  "xpub661MyMwAqRbcGSgFKbmauzByRXbUwzcTereYkAKHdmCCsstP1Gr4jSpy38Gw3DRGTi47zaaZCux4tEU334RNcp32NL6Y6KwDAsjW7EWAvK8");

        // m/0h
        test_path(&secp, Prod, &seed, "m/0h".parse().unwrap(),
                  "xprv9uYKM3GKt1gSYCGcR6FABVUHVMZ1jqFPmHUAV6bctpKtDj99E2eZWNz6ZvJsvxeur9pBRpLdLpjaguLLXJ9gg6dMm41qb13jB3onoHdTD34",
                  "xpub68XfkYoDiPEjkgM5X7nAYdR23PPW9HyF8WPmHV1ET9rs6XUHmZxp4BJaRBQALEUkmwWJmBF6L1ZzyPjWDRtNVidyqH9cJDyVgdWKeJoHDzE");
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_decode_childnumber() {
        serde_round_trip!(ChildNumber::from_normal_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_normal_idx((1 << 31) - 1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(0).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx(1).unwrap());
        serde_round_trip!(ChildNumber::from_hardened_idx((1 << 31) - 1).unwrap());
    }

    #[test]
    #[cfg(feature = "serde")]
    pub fn encode_fingerprint_chaincode() {
        use serde_json;
        let fp = Fingerprint::from([1u8, 2, 3, 42]);
        #[rustfmt::skip]
        let cc = ChainCode::from(
            [1u8,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]
        );

        serde_round_trip!(fp);
        serde_round_trip!(cc);

        assert_eq!("\"0102032a\"", serde_json::to_string(&fp).unwrap());
        assert_eq!(
            "\"0102030405060708090001020304050607080900010203040506070809000102\"",
            serde_json::to_string(&cc).unwrap()
        );
        assert_eq!("0102032a", fp.to_string());
        assert_eq!(
            "0102030405060708090001020304050607080900010203040506070809000102",
            cc.to_string()
        );
    }

    #[test]
    fn fmt_child_number() {
        assert_eq!("000005h", &format!("{:#06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5h", &format!("{:#}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("000005'", &format!("{:06}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("5'", &format!("{}", ChildNumber::from_hardened_idx(5).unwrap()));
        assert_eq!("42", &format!("{}", ChildNumber::from_normal_idx(42).unwrap()));
        assert_eq!("000042", &format!("{:06}", ChildNumber::from_normal_idx(42).unwrap()));
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_zeros() {
        /* this is how we generate key:
        let mut sk = secp256k1::key::ONE_KEY;

        let zeros = [0u8; 32];
        unsafe {
            sk.as_mut_ptr().copy_from(zeros.as_ptr(), 32);
        }

        let xpriv = Xpriv {
            network: Network::Prod,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: sk,
            chain_code: ChainCode::from([0u8; 32])
        };

        println!("{}", xpriv);
         */

        // Xpriv having secret key set to all zeros
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx";
        Xpriv::from_str(xpriv_str).unwrap();
    }

    #[test]
    #[should_panic(expected = "Secp256k1(InvalidSecretKey)")]
    fn schnorr_broken_privkey_ffs() {
        // Xpriv having secret key set to all 0xFF's
        let xpriv_str = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW";
        Xpriv::from_str(xpriv_str).unwrap();
    }
}
