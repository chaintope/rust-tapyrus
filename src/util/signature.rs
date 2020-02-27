// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Signature for block proof
//!
//! Implementation for Schnorr signature which is used as block proof.
//!

use std::error;
use std::fmt;
use std::borrow::Borrow;

use secp256k1::SecretKey;
use hashes::{sha256, HashEngine, Hash};

use util::key::{PublicKey, PrivateKey};
use util::prime::jacobi;
use util::rfc6979::nonce_rfc6979;

/// The size of scalar value on secp256k1 curve
pub const SECP256K1_SCALAR_SIZE: usize = 32;

/// "SCHNORR + SHA256"
pub const ALGO16: [u8; 16] = [
    83, 67, 72, 78, 79, 82, 82, 32, 43, 32, 83, 72, 65, 50, 53, 54
];

/// Schnorr signature struct
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Signature {
    /// R.x
    pub r_x: [u8; SECP256K1_SCALAR_SIZE],
    /// sigma
    pub sigma: [u8; SECP256K1_SCALAR_SIZE],
}

impl Signature {
    /// signing to message
    pub fn sign(privkey: &PrivateKey, message: &[u8; 32]) -> Result<Self, Error> {
        Self::sign_inner(privkey.key.borrow(), message)
    }

    fn sign_inner(sk: &SecretKey, message: &[u8; 32]) -> Result<Self, Error> {
        let ctx = secp256k1::Secp256k1::signing_only();

        let pk = secp256k1::PublicKey::from_secret_key(&ctx, sk);

        // Generate k
        let mut k = Self::generate_k(sk, message);

        // Compute R = k * G
        let r = secp256k1::PublicKey::from_secret_key(&ctx, &k);

        // Negate k if value of jacobi(R.y) is not 1
        if jacobi(&r.serialize_uncompressed()[33..]) != 1 {
            k.negate_assign();
        }

        // Compute e = sha256(R.x, pk, message)
        let e = Self::compute_e(&r.serialize()[1..33], &pk, message)?;

        // Compute s = k + ep
        let sigma = {
            let mut result = e.clone();
            result.mul_assign(&sk[..])?;
            result.add_assign(&k[..])?;
            result
        };

        let mut r_x = [0u8; 32];
        r_x.clone_from_slice(&r.serialize()[1..33]);

        Ok(Signature { r_x, sigma: to_bytes(&sigma) })
    }

    /// Verify signature
    pub fn verify(&self, message: &[u8; 32], pk: &PublicKey) -> Result<(), Error> {
        self.verify_inner(message, pk.key.borrow())
    }

    fn verify_inner(&self, message: &[u8; 32], pk: &secp256k1::PublicKey) -> Result<(), Error> {
        let ctx = secp256k1::Secp256k1::verification_only();

        // Extract s
        let s = secp256k1::SecretKey::from_slice(&self.sigma[..])?;

        // Compute e
        let mut e = Self::compute_e(&self.r_x[..], pk, message)?;

        // Compute R = sG - eP
        let r = {
            e.negate_assign();
            let minus_ep = {
                let mut result = pk.clone();
                result.mul_assign(&ctx, &e[..])?;
                result
            };

            let sg = {
                let mut result = PublicKey::generator().key;
                result.mul_assign(&ctx, &s[..])?;
                result
            };

            sg.combine(&minus_ep)?
        };

        // Check that R.x is what we expect
        if &r.serialize()[1..33] != self.r_x {
            return Err(Error::InvalidSignature);
        }

        // Check that jacobi(R.y) is 1
        if jacobi(&r.serialize_uncompressed()[33..]) != 1 {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    /// Compute e
    fn compute_e(r_x: &[u8], pk: &secp256k1::PublicKey, message: &[u8; 32]) -> Result<SecretKey, secp256k1::Error> {
        let mut engine = sha256::Hash::engine();
        engine.input(r_x);
        engine.input(&pk.serialize()[..]);
        engine.input(message);
        let hash = sha256::Hash::from_engine(engine);

        Ok(SecretKey::from_slice(&hash[..])?)
    }

    fn generate_k(sk: &SecretKey, message: &[u8; 32]) -> SecretKey {
        let mut count: u32 = 0;

        loop {
            let nonce = nonce_rfc6979(
                message,
                sk,
                &ALGO16,
                None,
                count
            );
            count += 1;

            if let Ok(k) = SecretKey::from_slice(&nonce[..]) {
                return k;
            }
        }
    }
}

fn to_bytes(sk: &secp256k1::SecretKey) -> [u8; 32] {
    let mut r = [0u8; 32];
    r.clone_from_slice(&sk[..]);
    r
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

    use hashes::Hash;
    use consensus::encode::{deserialize, serialize};
    use util::signature::Signature;
    use util::key::PrivateKey;
    use test_helpers::*;

    #[test]
    fn test_p2p_sign_and_verify() {
        for n in 0..16 {
            let msg = {
                let m = format!("Very secret message {}: 11", n);
                let hash = hashes::sha256::Hash::hash(m.as_bytes());
                hash.into_inner()
            };

            let key = PrivateKey::from_wif("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj").unwrap();

            let sign = Signature::sign(&key, &msg).unwrap();

            let ctx = secp256k1::Secp256k1::signing_only();
            assert!(sign.verify(&msg, &key.public_key(&ctx)).is_ok());
        }
    }

    /// these test vectors from here https://github.com/chaintope/tapyrus-schnorr-signature-test-vectors
    #[test]
    fn test_signing_and_verification() {
        let default_message = decode_message("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
        let default_pk = decode_pk("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");

        // test vector 0
        let sk = decode_sk("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = pk_from(&sk);
        let message = decode_message("0000000000000000000000000000000000000000000000000000000000000000");
        let sign = Signature::sign_inner(&sk, &message).unwrap();

        assert_eq!("06705D6B7FD5A7A34EA47B6A8D0CE8372A83D2129A65458E2BEF6F45892E7D5DBB13B346C6937CB76D25EFB18979B6523C72B56DD13B8F9D2F180893D20ECF45",
                   hex::encode_upper(&serialize(&sign)));
        assert!(sign.verify_inner(&message, &pk).is_ok());

        // test vector 1
        let sk = decode_sk("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        let pk = pk_from(&sk);
        let message = decode_message("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
        let sign = Signature::sign_inner(&sk, &message).unwrap();

        assert_eq!("28C528B8E405F81CE9B396755849E24A316A12A0B7BC77CEBCB8C01DAD63AB53C79B5363B04C1046F021F5E28A20D2506C38B1598F3BE79235C5421AC98400B9",
                   hex::encode_upper(&serialize(&sign)));
        assert!(sign.verify_inner(&message, &pk).is_ok());

        // test vector 2
        let sk = decode_sk("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
        let pk = pk_from(&sk);
        let message = decode_message("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C");
        let sign = Signature::sign_inner(&sk, &message).unwrap();

        assert_eq!("028CD7B45D8C265C9EA76A3633F09E48A3594558EBA0E2A10186ED1BFA1C8E0702B1EE67112B6CE4F5DD1CDFB4709B7628D71C6C74E8EA65B793A5267CA667F7",
                   hex::encode_upper(&serialize(&sign)));
        assert!(sign.verify_inner(&message, &pk).is_ok());

        // test vector 3, test fails if msg is reduced modulo p or n
        let sk = decode_sk("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710");
        let pk = pk_from(&sk);
        let message = decode_message("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        let sign = Signature::sign_inner(&sk, &message).unwrap();

        assert_eq!("E56D33673C16E2FCB1C8ABFE1065D1058109C1B051BBC0E7450DC6DE9A3C78B5ADCAFC135086D9DED95E3794E3B24F81E01ED232C9F0C59161E1930939FB05D7",
                   hex::encode_upper(&serialize(&sign)));
        assert!(sign.verify_inner(&message, &pk).is_ok());

        // test vector 4
        let pk = decode_pk("03D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9");
        let message = decode_message("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703");
        let sign = decode_signature("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63BAFC1D697AADBEB208CB8249CC7D9725A0FF8DA59AE04F68349A1EA06D072266");
        assert!(sign.verify_inner(&message, &pk).is_ok());

        // test vector 5, public key not on the curve
        let pk = hex::decode("02EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34").unwrap();
        assert!(secp256k1::PublicKey::from_slice(&pk[..]).is_err());

        // test vector 6, has_square_y(R) is false
        let sign = decode_signature("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F91DB49FABFB32B7EAD6D52CF16E38918D26F5C08E3B42D34EF90C29523D5BCA92");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 7, negated message
        let sign = decode_signature("9A44BCAB38B9EAB28608F673740BC3353BC8C188E949A02E0EFE09B9B1927406FD7546CAAFC5B703FD0A452E4FF3C257E49344885727CBE0F20491D561CD0852");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 8, negated s value
        let sign = decode_signature("28C528B8E405F81CE9B396755849E24A316A12A0B7BC77CEBCB8C01DAD63AB533864AC9C4FB3EFB90FDE0A1D75DF2DAE4E762B8D200CB8A98A0D1C7206B24088");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 9, sG - eP is infinite. Test fails in single verification if has_square_y(inf) is defined as true and x(inf) as 0
        let sign = decode_signature("00000000000000000000000000000000000000000000000000000000000000009E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 10, sG - eP is infinite. Test fails in single verification if has_square_y(inf) is defined as true and x(inf) as 1
        let sign = decode_signature("0000000000000000000000000000000000000000000000000000000000000000DDE56901145852D60EE498A24C6B6B74370CBBE91F671E945956829EB8B62F90");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 11, sig[0:32] is not an X coordinate on the curve
        let sign = decode_signature("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DC79B5363B04C1046F021F5E28A20D2506C38B1598F3BE79235C5421AC98400B9");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 12, sig[0:32] is equal to field size
        let sign = decode_signature("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FC79B5363B04C1046F021F5E28A20D2506C38B1598F3BE79235C5421AC98400B9");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 13, sig[32:64] is equal to curve order
        let sign = decode_signature("28C528B8E405F81CE9B396755849E24A316A12A0B7BC77CEBCB8C01DAD63AB53FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        assert!(sign.verify_inner(&default_message, &default_pk).is_err());

        // test vector 14, public key is not a valid X coordinate because it exceeds the field size
        let pk = hex::decode("02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30").unwrap();
        assert!(secp256k1::PublicKey::from_slice(&pk[..]).is_err());
    }

    #[test]
    fn test_decode() {
        let sig_data =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let r_x =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77").unwrap();
        let sigma =
            hex_decode("aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let decode: Result<Signature, _> = deserialize(&sig_data);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap();
        assert_eq!(&real_decode.sigma[..], sigma.as_slice());
        assert_eq!(&real_decode.r_x[..], r_x.as_slice());
        assert_eq!(serialize(&real_decode), sig_data);
    }
}
