// Copyright (c) 2020 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! RFC6879
//!

use hashes::{HmacEngine, HashEngine, Hmac, Hash};
use hashes::sha256::Hash as SHA256;
use secp256k1::SecretKey;

/// Generate nonce
pub fn nonce_rfc6979(
    message: &[u8; 32],
    key: &SecretKey,
    algo16: &[u8; 16],
    data: Option<&[u8; 32]>,
    counter: u32,
) -> [u8; 32]
{
    let mut keydata: Vec<u8> = Vec::new();

    keydata.extend(&key[..]);
    keydata.extend(message);
    if let Some(d) = data {
        keydata.extend(d);
    }
    keydata.extend(algo16);
    let mut rng = RFC6879::new(&keydata[..]);
    let mut ret: [u8; 32] = [0u8; 32];
    for _ in 0..=counter {
        ret = rng.generate();
    }

    ret
}

struct RFC6879 {
    v: [u8; 32],
    k: [u8; 32],
    retry: bool,
}

impl RFC6879 {
    pub fn new(keydata: &[u8]) -> Self {
        let mut rng = Self {
            v: [1u8; 32], // RFC6979 3.2.b.
            k: [0u8; 32], // RFC6979 3.2.c.
            retry: false,
        };

        let zero = [0u8; 1];
        let one = [1u8; 1];

        // RFC6979 3.2.d.
        let mut hmac = HmacEngine::<SHA256>::new(&rng.k[..]);
        hmac.input(&rng.v[..]);
        hmac.input(&zero[..]);
        hmac.input(&keydata[..]);
        rng.k = Hmac::from_engine(hmac).into_inner();
        let mut hmac = HmacEngine::<SHA256>::new(&rng.k[..]);
        hmac.input(&rng.v[..]);
        rng.v = Hmac::from_engine(hmac).into_inner();

        // RFC6979 2.3.f.
        let mut hmac = HmacEngine::<SHA256>::new(&rng.k[..]);
        hmac.input(&rng.v[..]);
        hmac.input(&one[..]);
        hmac.input(&keydata[..]);
        rng.k = Hmac::from_engine(hmac).into_inner();
        let mut hmac = HmacEngine::<SHA256>::new(&rng.k[..]);
        hmac.input(&rng.v[..]);
        rng.v = Hmac::from_engine(hmac).into_inner();

        rng
    }

    pub fn generate(&mut self) -> [u8; 32] {
        // RVC6979 3.2.h.
        let zero = [0u8; 1];
        if self.retry {
            let mut hmac = HmacEngine::<SHA256>::new(&self.k[..]);
            hmac.input(&self.v[..]);
            hmac.input(&zero[..]);
            self.k = Hmac::from_engine(hmac).into_inner();
            let mut hmac = HmacEngine::<SHA256>::new(&self.k[..]);
            hmac.input(&self.v[..]);
            self.v = Hmac::from_engine(hmac).into_inner();
        }

        let mut hmac = HmacEngine::<SHA256>::new(&self.k[..]);
        hmac.input(&self.v[..]);
        self.v = Hmac::from_engine(hmac).into_inner();

        self.retry = true;

        self.v.clone()
    }
}

#[cfg(test)]
mod tests {
    use test_helpers::{decode_message, decode_sk};
    use util::rfc7969::nonce_rfc6979;

    #[test]
    fn test() {
        let message = decode_message("0000000000000000000000000000000000000000000000000000000000000000");
        let sk = decode_sk("0000000000000000000000000000000000000000000000000000000000000001");

        // "SCHNORR + SHA256"
        static ALGO16: [u8; 16] = [
            83, 67, 72, 78, 79, 82, 82, 32, 43, 32, 83, 72, 65, 50, 53, 54
        ];

        assert_eq!("e9766e06045ef351d82f09d5d8707fd9a3f1f10cd5c596ce34b88b1aa19c7aea",
                   hex::encode(nonce_rfc6979(&message, &sk, &ALGO16, None, 0)));
    }
}