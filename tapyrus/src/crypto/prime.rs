// Copyright (c) 2024 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Utility for prime number
//!
//!

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, FromPrimitive, Zero};

/// Prime number for secp256k1 field element.
pub const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// Calculate jacobi symbol
pub fn jacobi(a: &[u8]) -> i8 {
    
    let a = BigUint::from_bytes_be(a);
    let p = BigUint::from_bytes_be(&P[..]);
    jacobi_inner(&a, &p)
}

fn jacobi_inner(a: &BigUint, n: &BigUint) -> i8 {
    let three: BigUint = BigUint::from_u64(3).unwrap();
    let five: BigUint = BigUint::from_u64(5).unwrap();
    let seven: BigUint = BigUint::from_u64(7).unwrap();

    assert!(*n >= three);
    let a = a % n;
    if a.is_zero() {
        return 0;
    }

    if a.is_one() {
        return 1;
    }
    let mut a: BigUint = a.clone();
    let mut e = 0;
    while a.is_even() {
        a >>= 1;
        e += 1;
    }

    let n_mod_8 = n % 8u32;
    let mut s: i8 = if e % 2 == 0 || n_mod_8 == BigUint::one() || n_mod_8 == seven {
        1
    } else if n_mod_8 == three || n_mod_8 == five {
        -1
    } else {
        0
    };

    if n % 4u32 == three && &a % 4u32 == three {
        s = -s
    }

    if a.is_one() {
        s
    } else {
        let n_mod_a = n % &a;
        s * jacobi_inner(&n_mod_a, &a)
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;

    #[test]
    fn test_jacobi() {
        assert_eq!(1, jacobi_inner(&BigUint::from_u64(1).unwrap(), &BigUint::from_u64(3).unwrap()));
        assert_eq!(-1, jacobi_inner(&BigUint::from_u64(2).unwrap(), &BigUint::from_u64(3).unwrap()));
        assert_eq!(0, jacobi_inner(&BigUint::from_u64(3).unwrap(), &BigUint::from_u64(3).unwrap()));

        let a = <[u8; 32]>::from_hex(
            "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
        )
        .unwrap();

        assert_eq!(-1, jacobi(&a[..]));
    }
}
