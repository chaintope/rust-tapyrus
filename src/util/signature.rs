// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Signature for block proof
//!
//! Implementation for Schnorr signature which is used as block proof.
//!

/// The size of scalar value on secp256k1 curve
pub const SECP256K1_SCALAR_SIZE: usize = 32;

/// Schnorr signature struct
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Signature {
    /// sigma
    sigma: [u8; SECP256K1_SCALAR_SIZE],
    /// R.x
    r_x: [u8; SECP256K1_SCALAR_SIZE],
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            sigma: [0u8; SECP256K1_SCALAR_SIZE],
            r_x: [0u8; SECP256K1_SCALAR_SIZE],
        }
    }
}

impl_consensus_encoding!(Signature, sigma, r_x);
serde_struct_impl!(Signature, sigma, r_x);

#[cfg(test)]
mod tests {
    use hex::decode as hex_decode;

    use consensus::encode::{deserialize, serialize};
    use util::signature::Signature;

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
}
