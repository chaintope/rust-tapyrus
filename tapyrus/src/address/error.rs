use core::fmt;

use internals::write_err;

use crate::address::{Address, NetworkUnchecked};
use crate::prelude::String;
use crate::{base58, Network};

/// Address error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// Address's network differs from required one.
    NetworkValidation {
        /// Network that was required.
        required: Network,
        /// Network on which the address was found to be valid.
        found: Network,
        /// The address itself
        address: Address<NetworkUnchecked>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            UncompressedPubkey =>
                write!(f, "an uncompressed pubkey was used where it is not allowed"),
            ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
            UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
            NetworkValidation { required, found, ref address } => {
                write!(f, "address ")?;
                address.fmt_internal(f)?; // Using fmt_internal in order to remove the "Address<NetworkUnchecked>(..)" wrapper
                write!(
                    f,
                    " belongs to network {} which is different from required {}",
                    found, required
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            UncompressedPubkey
            | ExcessiveScriptSize
            | UnrecognizedScript
            | NetworkValidation { .. } => None,
        }
    }
}

/// Address type is either invalid or not supported in rust-tapyrus.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownAddressTypeError(pub String);

impl fmt::Display for UnknownAddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "failed to parse {} as address type", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownAddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Address parsing error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Base58 error.
    Base58(base58::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Base58(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for ParseError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}
