// Copyright (c) 2020 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Utility for prime number
//!
//!

use rug::Integer;
use rug::integer::Order;

/// Prime number for secp256k1 field element.
pub const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
];

/// Calculate jacobi symbol
pub fn jacobi(a: &[u8]) -> i8 {
    let a = Integer::from_digits(a, Order::MsfBe);
    let p = Integer::from_digits(&P[..], Order::MsfBe);
    jacobi_inner(&a, &p)
}

fn jacobi_inner(a: &Integer, n: &Integer) -> i8 {
    assert!(*n >= Integer::from(3));
    let a = Integer::from(a % n);
    if a == Integer::from(0) {
        return 0;
    }
    if a == Integer::from(1) {
        return 1;
    }

    let mut a1: Integer = a.clone();
    let mut e = 0;
    while a1.is_even() {
        a1 = a1.div_exact_u(2);
        e += 1;
    }
    let mut s: i8 = if e & 1 == 0
        || n.mod_u(8) == 1
        || n.mod_u(8) == 7
    {
        1
    } else if n.mod_u(8) == 3
        || n.mod_u(8) == 5
    {
        -1
    } else {
        0
    };
    if n.mod_u(4) == 3 && a1.mod_u(4) == 3
    {
        s = -s
    }

    if a1 == Integer::from(1) {
        s
    } else {
        s * jacobi_inner(&(n % a1.clone()), &a1.clone())
    }
}

#[cfg(test)]
mod tests {
    use util::prime::{jacobi, jacobi_inner};
    use rug::Integer;

    #[test]
    fn test_jacobi() {
        assert_eq!(1, jacobi_inner(&Integer::from(1), &Integer::from(3)));
        assert_eq!(-1, jacobi_inner(&Integer::from(2), &Integer::from(3)));
        assert_eq!(0, jacobi_inner(&Integer::from(3), &Integer::from(3)));

        let a = hex::decode("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672").unwrap();
        assert_eq!(-1, jacobi(&a[..]));
    }
}