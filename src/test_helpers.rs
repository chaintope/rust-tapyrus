// Copyright (c) 2020 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Internal helper functions for unit tests
//!
//!

use secp256k1::SecretKey;
use crate::util::signature::Signature;
use crate::consensus::deserialize;

pub fn decode_sk(sk_hex: &str) -> SecretKey {
    let sk = hex::decode(sk_hex).unwrap();
    SecretKey::from_slice(&sk[..]).unwrap()
}

pub fn decode_message(message_hex: &str) -> [u8; 32] {
    let vec = hex::decode(message_hex).unwrap();
    let mut r = [0u8; 32];
    r.clone_from_slice(&vec[..]);
    r
}

pub fn decode_pk(pk_hex: &str) -> secp256k1::PublicKey {
    let pk = hex::decode(pk_hex).unwrap();
    secp256k1::PublicKey::from_slice(&pk[..]).unwrap()
}

pub fn pk_from(sk: &SecretKey) -> secp256k1::PublicKey {
    let secp = secp256k1::Secp256k1::signing_only();
    secp256k1::PublicKey::from_secret_key(&secp, sk)
}

pub fn decode_signature(sig_hex: &str) -> Signature {
    let sig = hex::decode(sig_hex).unwrap();
    deserialize(&sig[..]).unwrap()
}