// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Signature for block proof
//!
//! Implementation for Schnorr signature which is used as block proof.
//!

use std::error;
use std::fmt;

use util::key::PublicKey;
use secp256k1::SecretKey;
use hashes::{sha256, HashEngine, Hash};

pub const GENERATOR: [u8; 33] = [
    0x02,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
];

/// The size of scalar value on secp256k1 curve
pub const SECP256K1_SCALAR_SIZE: usize = 32;

/// Schnorr signature struct
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Signature {
    /// R.x
    pub r_x: [u8; SECP256K1_SCALAR_SIZE],
    /// sigma
    pub sigma: [u8; SECP256K1_SCALAR_SIZE],
}

impl Signature {
    /// Verify signature
    pub fn verify(&self, message: &[u8], pk: &PublicKey) -> Result<(), Error> {
        let ctx = secp256k1::Secp256k1::verification_only();

        // TODO: check pk is not infinity.

        // Extract s
        let s = secp256k1::SecretKey::from_slice(&self.sigma[..])?;

        // Compute e
        let mut e = Signature::compute_e(&self.r_x[..], &pk.key, message)?;

        // Compute R = sG - eP
        let r = {
            e.negate_assign();
            let minus_ep = {
                let mut result = pk.key.clone();
                result.mul_assign(&ctx, &e[..])?;
                result
            };

            let sg = {
                let mut result = secp256k1::PublicKey::from_slice(&GENERATOR[..]).unwrap();
                result.mul_assign(&ctx, &s[..])?;
                result
            };

            sg.combine(&minus_ep)?
        };

        // TODO: check R is not infinity.

        // Check that R.x is what we expect
        if &r.serialize()[1..33] != self.r_x {
            return Err(Error::InvalidSignature);
        }

        // TODO: Check that jacobi(R.y) is 1

        Ok(())
    }

    pub fn compute_e(r_x: &[u8], pk: &secp256k1::PublicKey, message: &[u8]) -> Result<SecretKey, secp256k1::Error> {
        let mut engine = sha256::Hash::engine();
        engine.input(r_x);
        engine.input(&pk.serialize()[..]);
        engine.input(message);
        let hash = sha256::Hash::from_engine(engine);

        Ok(SecretKey::from_slice(&hash[..])?)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            sigma: [0u8; SECP256K1_SCALAR_SIZE],
            r_x: [0u8; SECP256K1_SCALAR_SIZE],
        }
    }
}

impl_consensus_encoding!(Signature, r_x, sigma);
serde_struct_impl!(Signature, r_x, sigma);

/// Signature error
#[derive(Debug)]
pub enum Error {
    /// Invalid Signature Error
    InvalidSignature,
    /// secp256k1 error
    Secp256k1Error(secp256k1::Error),
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1Error(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp256k1Error(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidSignature => {
                f.write_str(error::Error::description(self))
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Secp256k1Error(ref e) => e.description(),
            Error::InvalidSignature => "Invalid signature",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Secp256k1Error(ref e) => Some(e),
            Error::InvalidSignature => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::decode as hex_decode;

    use consensus::encode::{deserialize, serialize};
    use util::signature::Signature;
    use util::key::PublicKey;
    use hashes::core::str::FromStr;

    #[test]
    fn signature_test() {
        let sig_data =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let sigma =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77").unwrap();
        let r_x =
            hex_decode("aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let decode: Result<Signature, _> = deserialize(&sig_data);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap();
        assert_eq!(&real_decode.sigma[..], sigma.as_slice());
        assert_eq!(&real_decode.r_x[..], r_x.as_slice());
        assert_eq!(serialize(&real_decode), sig_data);
    }

    #[test]
    fn test_verify() {
        let signature =
            hex_decode("8ecf8e95c1b31f9cf765912f77876d7782df71a50612b25930311d8746f5f61b9b22b5ee08ac148e8fe143b37a45976937a2d38eacf600343323f91614917dd5").unwrap();
        let signature: Signature = deserialize(&signature).unwrap();

        let message =
            hex_decode("b77bba2a538d76d23ec211516afeb6db31c3266c6867e00c5c584f01c78da5ca").unwrap();



        let pubkey = PublicKey::from_str("0313a906d2bbb008c3738b7cafcac215b578f66b5a2faabba26d85dc86b2bee854").unwrap();

        assert!(signature.verify(&message[..], &pubkey).is_ok());

    }
}
