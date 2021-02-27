// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Amounts
//!
//! This module mainly introduces the [Amount] and [SignedAmount] types.
//! We refer to the documentation on the types for more information.
//!

use std::default;
use std::error;
use std::fmt::{self, Write};
use std::ops;
use std::str::FromStr;
use std::cmp::Ordering;

/// A set of denominations in which amounts can be expressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Denomination {
    /// TPC
    TPC,
    /// mTPC
    MilliTPC,
    /// uTPC
    MicroTPC,
    /// tapyrus
    Tapyrus,
    /// mtap
    MilliTapyrus,
}

impl Denomination {
    /// The number of decimal places more than a tapyrus.
    fn precision(self) -> i32 {
        match self {
            Denomination::TPC => -8,
            Denomination::MilliTPC => -5,
            Denomination::MicroTPC => -2,
            Denomination::Tapyrus => 0,
            Denomination::MilliTapyrus => 3,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Denomination::TPC => "TPC",
            Denomination::MilliTPC => "mTPC",
            Denomination::MicroTPC => "uTPC",
            Denomination::Tapyrus => "tapyrus",
            Denomination::MilliTapyrus => "mtap",
        })
    }
}

impl FromStr for Denomination {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TPC" => Ok(Denomination::TPC),
            "mTPC" => Ok(Denomination::MilliTPC),
            "uTPC" => Ok(Denomination::MicroTPC),
            "tapyrus" => Ok(Denomination::Tapyrus),
            "tap" => Ok(Denomination::Tapyrus),
            "mtap" => Ok(Denomination::MilliTapyrus),
            d => Err(ParseAmountError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during amount parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAmountError {
    /// Amount is negative.
    Negative,
    /// Amount is too big to fit inside the type.
    TooBig,
    /// Amount has higher precision than supported by the type.
    TooPrecise,
    /// Invalid number format.
    InvalidFormat,
    /// Input string was too large.
    InputTooLarge,
    /// Invalid character in input.
    InvalidCharacter(char),
    /// The denomination was unknown.
    UnknownDenomination(String),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseAmountError::Negative => f.write_str("amount is negative"),
            ParseAmountError::TooBig => f.write_str("amount is too big"),
            ParseAmountError::TooPrecise => f.write_str("amount has a too high precision"),
            ParseAmountError::InvalidFormat => f.write_str("invalid number format"),
            ParseAmountError::InputTooLarge => f.write_str("input string was too large"),
            ParseAmountError::InvalidCharacter(c) => write!(f, "invalid character in input: {}", c),
            ParseAmountError::UnknownDenomination(ref d) => write!(f, "unknown denomination: {}",d),
        }
    }
}

#[allow(deprecated)]
impl error::Error for ParseAmountError {
    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}


fn is_too_precise(s: &str, precision: usize) -> bool {
    s.contains('.') || precision >= s.len() || s.chars().rev().take(precision).any(|d| d != '0')
}

/// Parse decimal string in the given denomination into a tapyrus value and a
/// bool indicator for a negative amount.
fn parse_signed_to_tapyrus(
    mut s: &str,
    denom: Denomination,
) -> Result<(bool, u64), ParseAmountError> {
    if s.is_empty() {
        return Err(ParseAmountError::InvalidFormat);
    }
    if s.len() > 50 {
        return Err(ParseAmountError::InputTooLarge);
    }

    let is_negative = s.starts_with('-');
    if is_negative {
        if s.len() == 1 {
            return Err(ParseAmountError::InvalidFormat);
        }
        s = &s[1..];
    }

    let max_decimals = {
        // The difference in precision between native (tapyrus)
        // and desired denomination.
        let precision_diff = -denom.precision();
        if precision_diff < 0 {
            // If precision diff is negative, this means we are parsing
            // into a less precise amount. That is not allowed unless
            // there are no decimals and the last digits are zeroes as
            // many as the difference in precision.
            let last_n = precision_diff.abs() as usize;
            if is_too_precise(s, last_n) {
                return Err(ParseAmountError::TooPrecise);
            }
            s = &s[0..s.len() - last_n];
            0
        } else {
            precision_diff
        }
    };

    let mut decimals = None;
    let mut value: u64 = 0; // as tapyruses
    for c in s.chars() {
        match c {
            '0'...'9' => {
                // Do `value = 10 * value + digit`, catching overflows.
                match 10_u64.checked_mul(value) {
                    None => return Err(ParseAmountError::TooBig),
                    Some(val) => match val.checked_add((c as u8 - b'0') as u64) {
                        None => return Err(ParseAmountError::TooBig),
                        Some(val) => value = val,
                    },
                }
                // Increment the decimal digit counter if past decimal.
                decimals = match decimals {
                    None => None,
                    Some(d) if d < max_decimals => Some(d + 1),
                    _ => return Err(ParseAmountError::TooPrecise),
                };
            }
            '.' => match decimals {
                None => decimals = Some(0),
                // Double decimal dot.
                _ => return Err(ParseAmountError::InvalidFormat),
            },
            c => return Err(ParseAmountError::InvalidCharacter(c)),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_u64.checked_mul(value) {
            Some(v) => v,
            None => return Err(ParseAmountError::TooBig),
        };
    }

    Ok((is_negative, value))
}

/// Format the given tapyrus amount in the given denomination.
///
/// Does not include the denomination.
fn fmt_tapyrus_in(
    tapyrus: u64,
    negative: bool,
    f: &mut fmt::Write,
    denom: Denomination,
) -> fmt::Result {
    if negative {
        f.write_str("-")?;
    }

    let precision = denom.precision();
    match precision.cmp(&0) {
        Ordering::Greater => {
            // add zeroes in the end
            let width = precision as usize;
            write!(f, "{}{:0width$}", tapyrus, 0, width = width)?;
        }
        Ordering::Less => {
            // need to inject a comma in the number
            let nb_decimals = precision.abs() as usize;
            let real = format!("{:0width$}", tapyrus, width = nb_decimals);
            if real.len() == nb_decimals {
                write!(f, "0.{}", &real[real.len() - nb_decimals..])?;
            } else {
                write!(
                    f,
                    "{}.{}",
                    &real[0..(real.len() - nb_decimals)],
                    &real[real.len() - nb_decimals..]
                )?;
            }
        }
        Ordering::Equal => write!(f, "{}", tapyrus)?,
    }
    Ok(())
}

/// Amount
///
/// The [Amount] type can be used to express TPC amounts that supports
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [std::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [std::ops] that [Amount]
/// implements will panic when overflow or underflow occurs.  Also note that
/// since the internal representation of amounts is unsigned, subtracting below
/// zero is considered an underflow and will cause a panic if you're not using
/// the checked arithmetic methods.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one tapyrus.
    pub const ONE_TAP: Amount = Amount(1);
    /// Exactly one TPC.
    pub const ONE_TPC: Amount = Amount(100_000_000);

    /// Create an [Amount] with tapyrus precision and the given number of tapyrus.
    pub fn from_tap(tapyrus: u64) -> Amount {
        Amount(tapyrus)
    }

    /// Get the number of tapyrus in this [Amount].
    pub fn as_tap(self) -> u64 {
        self.0
    }

    /// The maximum value of an [Amount].
    pub fn max_value() -> Amount {
        Amount(u64::max_value())
    }

    /// The minimum value of an [Amount].
    pub fn min_value() -> Amount {
        Amount(u64::min_value())
    }

    /// Convert from a value expressing tpcs to an [Amount].
    pub fn from_tpc(tpc: f64) -> Result<Amount, ParseAmountError> {
        Amount::from_float_in(tpc, Denomination::TPC)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        let (negative, tapyrus) = parse_signed_to_tapyrus(s, denom)?;
        if negative {
            return Err(ParseAmountError::Negative);
        }
        if tapyrus > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(Amount::from_tap(tapyrus))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParseAmountError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(Amount::from_str_in(amt_str, denom_str.parse()?)?)
    }

    /// Express this [Amount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [Amount] as a floating-point value in TPC.
    ///
    /// Equivalent to `to_float_in(Denomination::TPC)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_tpc(self) -> f64 {
        self.to_float_in(Denomination::TPC)
    }

    /// Convert this [Amount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if value < 0.0 {
            return Err(ParseAmountError::Negative);
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_tapyrus_in(self.as_tap(), false, f, denom)
    }

    /// Get a string number of this [Amount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [Amount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Amount> {
        self.0.checked_mul(rhs).map(Amount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<Amount> {
        self.0.checked_div(rhs).map(Amount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<Amount> {
        self.0.checked_rem(rhs).map(Amount)
    }

    /// Convert to a signed amount.
    pub fn to_signed(self) -> Result<SignedAmount, ParseAmountError> {
        if self.as_tap() > SignedAmount::max_value().as_tap() as u64 {
            Err(ParseAmountError::TooBig)
        } else {
            Ok(SignedAmount::from_tap(self.as_tap() as i64))
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self {
        Amount::ZERO
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({} tapyrus)", self.as_tap())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using TPC denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::TPC)?;
        write!(f, " {}", Denomination::TPC)
    }
}

impl ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Self::Output {
        self.checked_add(rhs).expect("Amount addition error")
    }
}

impl ops::AddAssign for Amount {
    fn add_assign(&mut self, other: Amount) {
        *self = *self + other
    }
}

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs).expect("Amount subtraction error")
    }
}

impl ops::SubAssign for Amount {
    fn sub_assign(&mut self, other: Amount) {
        *self = *self - other
    }
}

impl ops::Rem<u64> for Amount {
    type Output = Amount;

    fn rem(self, modulus: u64) -> Self {
        self.checked_rem(modulus).expect("Amount remainder error")
    }
}

impl ops::RemAssign<u64> for Amount {
    fn rem_assign(&mut self, modulus: u64) {
        *self = *self % modulus
    }
}

impl ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        self.checked_mul(rhs).expect("Amount multiplication error")
    }
}

impl ops::MulAssign<u64> for Amount {
    fn mul_assign(&mut self, rhs: u64) {
        *self = *self * rhs
    }
}

impl ops::Div<u64> for Amount {
    type Output = Amount;

    fn div(self, rhs: u64) -> Self::Output {
        self.checked_div(rhs).expect("Amount division error")
    }
}

impl ops::DivAssign<u64> for Amount {
    fn div_assign(&mut self, rhs: u64) {
        *self = *self / rhs
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_str_with_denomination(s)
    }
}

/// SignedAmount
///
/// The [SignedAmount] type can be used to express TPC amounts that supports
/// arithmetic and conversion to various denominations.
///
///
/// Warning!
///
/// This type implements several arithmetic operations from [std::ops].
/// To prevent errors due to overflow or underflow when using these operations,
/// it is advised to instead use the checked arithmetic methods whose names
/// start with `checked_`.  The operations from [std::ops] that [Amount]
/// implements will panic when overflow or underflow occurs.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedAmount(i64);

impl SignedAmount {
    /// The zero amount.
    pub const ZERO: SignedAmount = SignedAmount(0);
    /// Exactly one tapyrus.
    pub const ONE_TAP: SignedAmount = SignedAmount(1);
    /// Exactly one TPC.
    pub const ONE_TPC: SignedAmount = SignedAmount(100_000_000);

    /// Create an [SignedAmount] with tapyrus precision and the given number of tapyruses.
    pub fn from_tap(tapyrus: i64) -> SignedAmount {
        SignedAmount(tapyrus)
    }

    /// Get the number of tapyrus in this [SignedAmount].
    pub fn as_tap(self) -> i64 {
        self.0
    }

    /// The maximum value of an [SignedAmount].
    pub fn max_value() -> SignedAmount {
        SignedAmount(i64::max_value())
    }

    /// The minimum value of an [SignedAmount].
    pub fn min_value() -> SignedAmount {
        SignedAmount(i64::min_value())
    }

    /// Convert from a value expressing tpcs to an [SignedAmount].
    pub fn from_tpc(tpc: f64) -> Result<SignedAmount, ParseAmountError> {
        SignedAmount::from_float_in(tpc, Denomination::TPC)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value
    /// with denomination, use [FromStr].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, ParseAmountError> {
        let (negative, tapyrus) = parse_signed_to_tapyrus(s, denom)?;
        if tapyrus > i64::max_value() as u64 {
            return Err(ParseAmountError::TooBig);
        }
        Ok(match negative {
            true => SignedAmount(-(tapyrus as i64)),
            false => SignedAmount(tapyrus as i64),
        })
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// [to_string_with_denomination] or with [fmt::Display].
    /// If you want to parse only the amount without the denomination,
    /// use [from_str_in].
    pub fn from_str_with_denomination(s: &str) -> Result<SignedAmount, ParseAmountError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(SignedAmount::from_str_in(amt_str, denom_str.parse()?)?)
    }

    /// Express this [SignedAmount] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [SignedAmount] as a floating-point value in TPC.
    ///
    /// Equivalent to `to_float_in(Denomination::TPC)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_tpc(self) -> f64 {
        self.to_float_in(Denomination::TPC)
    }

    /// Convert this [SignedAmount] in floating-point notation with a given
    /// denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(
        value: f64,
        denom: Denomination,
    ) -> Result<SignedAmount, ParseAmountError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        SignedAmount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [SignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut fmt::Write, denom: Denomination) -> fmt::Result {
        let taps = self.as_tap().checked_abs().map(|a: i64| a as u64).unwrap_or_else(|| {
            // We could also hard code this into `9223372036854775808`
            u64::max_value() - self.as_tap() as u64 +1
        });
        fmt_tapyrus_in(taps, self.is_negative(), f, denom)
    }

    /// Get a string number of this [SignedAmount] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [SignedAmount] in the given denomination,
    /// suffixed with the abbreviation for the denomination.
    pub fn to_string_with_denomination(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Get the absolute value of this [SignedAmount].
    pub fn abs(self) -> SignedAmount {
        SignedAmount(self.0.abs())
    }

    /// Returns a number representing sign of this [SignedAmount].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    pub fn signum(self) -> i64 {
        self.0.signum()
    }

    /// Returns `true` if this [SignedAmount] is positive and `false` if
    /// this [SignedAmount] is zero or negative.
    pub fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if this [SignedAmount] is negative and `false` if
    /// this [SignedAmount] is zero or positive.
    pub fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    /// Get the absolute value of this [SignedAmount].
    /// Returns [None] if overflow occurred. (`self == min_value()`)
    pub fn checked_abs(self) -> Option<SignedAmount> {
        self.0.checked_abs().map(SignedAmount)
    }

    /// Checked addition.
    /// Returns [None] if overflow occurred.
    pub fn checked_add(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_add(rhs.0).map(SignedAmount)
    }

    /// Checked subtraction.
    /// Returns [None] if overflow occurred.
    pub fn checked_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_sub(rhs.0).map(SignedAmount)
    }

    /// Checked multiplication.
    /// Returns [None] if overflow occurred.
    pub fn checked_mul(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_mul(rhs).map(SignedAmount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [None] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_div(rhs).map(SignedAmount)
    }

    /// Checked remainder.
    /// Returns [None] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_rem(rhs).map(SignedAmount)
    }

    /// Subtraction that doesn't allow negative [SignedAmount]s.
    /// Returns [None] if either [self], [rhs] or the result is strictly negative.
    pub fn positive_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        if self.is_negative() || rhs.is_negative() || rhs > self {
            None
        } else {
            self.checked_sub(rhs)
        }
    }

    /// Convert to an unsigned amount.
    pub fn to_unsigned(self) -> Result<Amount, ParseAmountError> {
        if self.is_negative() {
            Err(ParseAmountError::Negative)
        } else {
            Ok(Amount::from_tap(self.as_tap() as u64))
        }
    }
}

impl default::Default for SignedAmount {
    fn default() -> Self {
        SignedAmount::ZERO
    }
}

impl fmt::Debug for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedAmount({} tapyrus)", self.as_tap())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using TPC denominated string.
impl fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::TPC)?;
        write!(f, " {}", Denomination::TPC)
    }
}

impl ops::Add for SignedAmount {
    type Output = SignedAmount;

    fn add(self, rhs: SignedAmount) -> Self::Output {
        self.checked_add(rhs).expect("SignedAmount addition error")
    }
}

impl ops::AddAssign for SignedAmount {
    fn add_assign(&mut self, other: SignedAmount) {
        *self = *self + other
    }
}

impl ops::Sub for SignedAmount {
    type Output = SignedAmount;

    fn sub(self, rhs: SignedAmount) -> Self::Output {
        self.checked_sub(rhs)
            .expect("SignedAmount subtraction error")
    }
}

impl ops::SubAssign for SignedAmount {
    fn sub_assign(&mut self, other: SignedAmount) {
        *self = *self - other
    }
}

impl ops::Rem<i64> for SignedAmount {
    type Output = SignedAmount;

    fn rem(self, modulus: i64) -> Self {
        self.checked_rem(modulus)
            .expect("SignedAmount remainder error")
    }
}

impl ops::RemAssign<i64> for SignedAmount {
    fn rem_assign(&mut self, modulus: i64) {
        *self = *self % modulus
    }
}

impl ops::Mul<i64> for SignedAmount {
    type Output = SignedAmount;

    fn mul(self, rhs: i64) -> Self::Output {
        self.checked_mul(rhs)
            .expect("SignedAmount multiplication error")
    }
}

impl ops::MulAssign<i64> for SignedAmount {
    fn mul_assign(&mut self, rhs: i64) {
        *self = *self * rhs
    }
}

impl ops::Div<i64> for SignedAmount {
    type Output = SignedAmount;

    fn div(self, rhs: i64) -> Self::Output {
        self.checked_div(rhs).expect("SignedAmount division error")
    }
}

impl ops::DivAssign<i64> for SignedAmount {
    fn div_assign(&mut self, rhs: i64) {
        *self = *self / rhs
    }
}

impl FromStr for SignedAmount {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedAmount::from_str_with_denomination(s)
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    // methods are implementation of a standardized serde-specific signature
    #![allow(missing_docs)]

    //! This module adds serde serialization and deserialization support for Amounts.
    //! Since there is not a default way to serialize and deserialize Amounts, multiple
    //! ways are supported and it's up to the user to decide which serialiation to use.
    //! The provided modules can be used as follows:
    //!
    //! ```rust,ignore
    //! use serde::{Serialize, Deserialize};
    //! use tapyrus::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! pub struct HasAmount {
    //!     #[serde(with = "tapyrus::util::amount::serde::as_tpc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use util::amount::{Amount, Denomination, SignedAmount};

    /// This trait is used only to avoid code duplication and naming collisions
    /// of the different serde serialization crates.
    pub trait SerdeAmount: Copy + Sized {
        fn ser_tap<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_tap<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
        fn ser_tpc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        fn des_tpc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
    }

    impl SerdeAmount for Amount {
        fn ser_tap<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            u64::serialize(&self.as_tap(), s)
        }
        fn des_tap<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(Amount::from_tap(u64::deserialize(d)?))
        }
        fn ser_tpc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::TPC), s)
        }
        fn des_tpc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Ok(Amount::from_tpc(f64::deserialize(d)?).map_err(D::Error::custom)?)
        }
    }

    impl SerdeAmount for SignedAmount {
        fn ser_tap<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&self.as_tap(), s)
        }
        fn des_tap<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(SignedAmount::from_tap(i64::deserialize(d)?))
        }
        fn ser_tpc<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&self.to_float_in(Denomination::TPC), s)
        }
        fn des_tpc<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde::de::Error;
            Ok(SignedAmount::from_tpc(f64::deserialize(d)?).map_err(D::Error::custom)?)
        }
    }

    pub mod as_tap {
        //! Serialize and deserialize [Amount] as real numbers denominated in tapyrus.
        //! Use with `#[serde(with = "amount::serde::as_tap")]`.

        use serde::{Deserializer, Serializer};
        use util::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_tap(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_tap(d)
        }

        pub mod opt {
            //! Serialize and deserialize [Optoin<Amount>] as real numbers denominated in tapyrus.
            //! Use with `#[serde(default, with = "amount::serde::as_tap::opt")]`.

            use serde::{Deserializer, Serializer};
            use util::amount::serde::SerdeAmount;

            pub fn serialize<A: SerdeAmount, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_tap(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                Ok(Some(A::des_tap(d)?))
            }
        }
    }

    pub mod as_tpc {
        //! Serialize and deserialize [Amount] as JSON numbers denominated in TPC.
        //! Use with `#[serde(with = "amount::serde::as_tpc")]`.

        use serde::{Deserializer, Serializer};
        use util::amount::serde::SerdeAmount;

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_tpc(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_tpc(d)
        }

        pub mod opt {
            //! Serialize and deserialize [Option<Amount>] as JSON numbers denominated in TPC.
            //! Use with `#[serde(default, with = "amount::serde::as_tpc::opt")]`.

            use serde::{Deserializer, Serializer};
            use util::amount::serde::SerdeAmount;

            pub fn serialize<A: SerdeAmount, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_tpc(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                Ok(Some(A::des_tpc(d)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    #[test]
    fn add_sub_mul_div() {
        let tap = Amount::from_tap;
        let stap = SignedAmount::from_tap;

        assert_eq!(tap(15) + tap(15), tap(30));
        assert_eq!(tap(15) - tap(15), tap(0));
        assert_eq!(tap(14) * 3, tap(42));
        assert_eq!(tap(14) / 2, tap(7));
        assert_eq!(tap(14) % 3, tap(2));
        assert_eq!(stap(15) - stap(20), stap(-5));
        assert_eq!(stap(-14) * 3, stap(-42));
        assert_eq!(stap(-14) / 2, stap(-7));
        assert_eq!(stap(-14) % 3, stap(-2));

        let mut b = stap(-5);
        b += stap(13);
        assert_eq!(b, stap(8));
        b -= stap(3);
        assert_eq!(b, stap(5));
        b *= 6;
        assert_eq!(b, stap(30));
        b /= 3;
        assert_eq!(b, stap(10));
        b %= 3;
        assert_eq!(b, stap(1));

        // panic on overflow
        let result = panic::catch_unwind(|| Amount::max_value() + Amount::from_tap(1));
        assert!(result.is_err());
        let result = panic::catch_unwind(|| Amount::from_tap(8446744073709551615) * 3);
        assert!(result.is_err());
    }

    #[test]
    fn checked_arithmetic() {
        let tap = Amount::from_tap;
        let stap = SignedAmount::from_tap;

        assert_eq!(tap(42).checked_add(tap(1)), Some(tap(43)));
        assert_eq!(SignedAmount::max_value().checked_add(stap(1)), None);
        assert_eq!(SignedAmount::min_value().checked_sub(stap(1)), None);
        assert_eq!(Amount::max_value().checked_add(tap(1)), None);
        assert_eq!(Amount::min_value().checked_sub(tap(1)), None);

        assert_eq!(tap(5).checked_sub(tap(3)), Some(tap(2)));
        assert_eq!(tap(5).checked_sub(tap(6)), None);
        assert_eq!(stap(5).checked_sub(stap(6)), Some(stap(-1)));
        assert_eq!(tap(5).checked_rem(2), Some(tap(1)));

        assert_eq!(tap(5).checked_div(2), Some(tap(2))); // integer division
        assert_eq!(stap(-6).checked_div(2), Some(stap(-3)));

        assert_eq!(stap(-5).positive_sub(stap(3)), None);
        assert_eq!(stap(5).positive_sub(stap(-3)), None);
        assert_eq!(stap(3).positive_sub(stap(5)), None);
        assert_eq!(stap(3).positive_sub(stap(3)), Some(stap(0)));
        assert_eq!(stap(5).positive_sub(stap(3)), Some(stap(2)));
    }

    #[test]
    fn floating_point() {
        use super::Denomination as D;
        let f = Amount::from_float_in;
        let sf = SignedAmount::from_float_in;
        let tap = Amount::from_tap;
        let stap = SignedAmount::from_tap;

        assert_eq!(f(11.22, D::TPC), Ok(tap(1122000000)));
        assert_eq!(sf(-11.22, D::MilliTPC), Ok(stap(-1122000)));
        assert_eq!(sf(-1000.0, D::MilliTapyrus), Ok(stap(-1)));
        assert_eq!(f(0.0001234, D::TPC), Ok(tap(12340)));
        assert_eq!(sf(-0.00012345, D::TPC), Ok(stap(-12345)));

        assert_eq!(f(-100.0, D::MilliTapyrus), Err(ParseAmountError::Negative));
        assert_eq!(f(11.22, D::Tapyrus), Err(ParseAmountError::TooPrecise));
        assert_eq!(
            sf(-100.0, D::MilliTapyrus),
            Err(ParseAmountError::TooPrecise)
        );
        assert_eq!(
            sf(-100.0, D::MilliTapyrus),
            Err(ParseAmountError::TooPrecise)
        );
        assert_eq!(
            f(42.123456781, D::TPC),
            Err(ParseAmountError::TooPrecise)
        );
        assert_eq!(
            sf(-184467440738.0, D::TPC),
            Err(ParseAmountError::TooBig)
        );
        assert_eq!(
            f(18446744073709551617.0, D::Tapyrus),
            Err(ParseAmountError::TooBig)
        );
        assert_eq!(
            f(
                SignedAmount::max_value().to_float_in(D::Tapyrus) + 1.0,
                D::Tapyrus
            ),
            Err(ParseAmountError::TooBig)
        );
        assert_eq!(
            f(
                Amount::max_value().to_float_in(D::Tapyrus) + 1.0,
                D::Tapyrus
            ),
            Err(ParseAmountError::TooBig)
        );

        let tpc = move |f| SignedAmount::from_tpc(f).unwrap();
        assert_eq!(tpc(2.5).to_float_in(D::TPC), 2.5);
        assert_eq!(tpc(-2.5).to_float_in(D::MilliTPC), -2500.0);
        assert_eq!(tpc(2.5).to_float_in(D::Tapyrus), 250000000.0);
        assert_eq!(tpc(-2.5).to_float_in(D::MilliTapyrus), -250000000000.0);

        let tpc = move |f| Amount::from_tpc(f).unwrap();
        assert_eq!(&tpc(0.0012).to_float_in(D::TPC).to_string(), "0.0012")
    }

    #[test]
    fn parsing() {
        use super::ParseAmountError as E;
        let tpc = Denomination::TPC;
        let tap = Denomination::Tapyrus;
        let p = Amount::from_str_in;
        let sp = SignedAmount::from_str_in;

        assert_eq!(p("x", tpc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", tpc), Err(E::InvalidFormat));
        assert_eq!(sp("-", tpc), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", tpc), Err(E::InvalidCharacter('x')));
        assert_eq!(p("0.0 ", tpc), Err(ParseAmountError::InvalidCharacter(' ')));
        assert_eq!(p("0.000.000", tpc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amount::max_value());
        assert_eq!(p(&more_than_max, tpc), Err(E::TooBig));
        assert_eq!(p("0.000000042", tpc), Err(E::TooPrecise));

        assert_eq!(p("1", tpc), Ok(Amount::from_tap(1_000_000_00)));
        assert_eq!(sp("-.5", tpc), Ok(SignedAmount::from_tap(-500_000_00)));
        assert_eq!(p("1.1", tpc), Ok(Amount::from_tap(1_100_000_00)));
        assert_eq!(p("100", tap), Ok(Amount::from_tap(100)));
        assert_eq!(p("55", tap), Ok(Amount::from_tap(55)));
        assert_eq!(p("5500000000000000000", tap), Ok(Amount::from_tap(5_500_000_000_000_000_000)));
        // Should this even pass?
        assert_eq!(p("5500000000000000000.", tap), Ok(Amount::from_tap(5_500_000_000_000_000_000)));
        assert_eq!(
            p("12345678901.12345678", tpc),
            Ok(Amount::from_tap(12_345_678_901__123_456_78))
        );

        // make sure tapyrus > i64::max_value() is checked.
        let amount = Amount::from_tap(i64::max_value() as u64);
        assert_eq!(Amount::from_str_in(&amount.to_string_in(tap), tap), Ok(amount));
        assert_eq!(Amount::from_str_in(&(amount+Amount(1)).to_string_in(tap), tap), Err(E::TooBig));

        assert_eq!(p("12.000", Denomination::MilliTapyrus), Err(E::TooPrecise));
        // exactly 50 chars.
        assert_eq!(p("100000000000000.0000000000000000000000000000000000", Denomination::TPC), Err(E::TooBig));
        // more than 50 chars.
        assert_eq!(p("100000000000000.00000000000000000000000000000000000", Denomination::TPC), Err(E::InputTooLarge));
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(Amount::ONE_TPC.to_string_in(D::TPC), "1.00000000");
        assert_eq!(Amount::ONE_TPC.to_string_in(D::Tapyrus), "100000000");
        assert_eq!(Amount::ONE_TAP.to_string_in(D::TPC), "0.00000001");
        assert_eq!(
            SignedAmount::from_tap(-42).to_string_in(D::TPC),
            "-0.00000042"
        );

        assert_eq!(
            Amount::ONE_TPC.to_string_with_denomination(D::TPC),
            "1.00000000 TPC"
        );
        assert_eq!(
            Amount::ONE_TAP.to_string_with_denomination(D::MilliTapyrus),
            "1000 mtap"
        );
        assert_eq!(
            SignedAmount::ONE_TPC.to_string_with_denomination(D::Tapyrus),
            "100000000 tapyrus"
        );
        assert_eq!(
            Amount::ONE_TAP.to_string_with_denomination(D::TPC),
            "0.00000001 TPC"
        );
        assert_eq!(
            SignedAmount::from_tap(-42).to_string_with_denomination(D::TPC),
            "-0.00000042 TPC"
        );
    }

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::ParseAmountError as E;
        let sa = SignedAmount::from_tap;
        let ua = Amount::from_tap;

        assert_eq!(Amount::max_value().to_signed(),  Err(E::TooBig));
        assert_eq!(ua(i64::max_value() as u64).to_signed(),  Ok(sa(i64::max_value())));
        assert_eq!(ua(0).to_signed(),  Ok(sa(0)));
        assert_eq!(ua(1).to_signed(), Ok( sa(1)));
        assert_eq!(ua(1).to_signed(),  Ok(sa(1)));
        assert_eq!(ua(i64::max_value() as u64 + 1).to_signed(),  Err(E::TooBig));

        assert_eq!(sa(-1).to_unsigned(), Err(E::Negative));
        assert_eq!(sa(i64::max_value()).to_unsigned(), Ok(ua(i64::max_value() as u64)));

        assert_eq!(sa(0).to_unsigned().unwrap().to_signed(), Ok(sa(0)));
        assert_eq!(sa(1).to_unsigned().unwrap().to_signed(), Ok(sa(1)));
        assert_eq!(sa(i64::max_value()).to_unsigned().unwrap().to_signed(), Ok(sa(i64::max_value())));
    }

    #[test]
    fn from_str() {
        use super::ParseAmountError as E;
        let p = Amount::from_str;
        let sp = SignedAmount::from_str;

        assert_eq!(p("x TPC"), Err(E::InvalidCharacter('x')));
        assert_eq!(p("5 TPC TPC"), Err(E::InvalidFormat));
        assert_eq!(p("5 5 TPC"), Err(E::InvalidFormat));

        assert_eq!(p("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(p("-1 TPC"), Err(E::Negative));
        assert_eq!(p("-0.0 TPC"), Err(E::Negative));
        assert_eq!(p("0.123456789 TPC"), Err(E::TooPrecise));
        assert_eq!(sp("-0.1 tapyrus"), Err(E::TooPrecise));
        assert_eq!(p("0.123456 mTPC"), Err(E::TooPrecise));
        assert_eq!(sp("-200000000000 TPC"), Err(E::TooBig));
        assert_eq!(p("18446744073709551616 tapyrus"), Err(E::TooBig));

        assert_eq!(sp("0 mtap"), Err(E::TooPrecise));
        assert_eq!(sp("-0 mtap"), Err(E::TooPrecise));
        assert_eq!(sp("000 mtap"), Err(E::TooPrecise));
        assert_eq!(sp("-000 mtap"), Err(E::TooPrecise));
        assert_eq!(p("0 mtap"), Err(E::TooPrecise));
        assert_eq!(p("-0 mtap"), Err(E::TooPrecise));
        assert_eq!(p("000 mtap"), Err(E::TooPrecise));
        assert_eq!(p("-000 mtap"), Err(E::TooPrecise));

        assert_eq!(p("0.00253583 TPC"), Ok(Amount::from_tap(253583)));
        assert_eq!(sp("-5 tapyrus"), Ok(SignedAmount::from_tap(-5)));
        assert_eq!(p("0.10000000 TPC"), Ok(Amount::from_tap(100_000_00)));
    }

    #[test]
    fn to_from_string_in() {
        use super::Denomination as D;
        let ua_str = Amount::from_str_in;
        let ua_tap = Amount::from_tap;
        let sa_str = SignedAmount::from_str_in;
        let sa_tap = SignedAmount::from_tap;

        assert_eq!("0.00253583", Amount::from_tap(253583).to_string_in(D::TPC));
        assert_eq!("-5", SignedAmount::from_tap(-5).to_string_in(D::Tapyrus));
        assert_eq!("0.10000000", Amount::from_tap(100_000_00).to_string_in(D::TPC));

        assert_eq!(ua_str(&ua_tap(0).to_string_in(D::Tapyrus), D::Tapyrus), Ok(ua_tap(0)));
        assert_eq!(ua_str(&ua_tap(500).to_string_in(D::TPC), D::TPC), Ok(ua_tap(500)));
        assert_eq!(ua_str(&ua_tap(1).to_string_in(D::MicroTPC), D::MicroTPC), Ok(ua_tap(1)));
        assert_eq!(ua_str(&ua_tap(1_000_000_000_000).to_string_in(D::MilliTPC), D::MilliTPC), Ok(ua_tap(1_000_000_000_000)));
        assert_eq!(ua_str(&ua_tap(u64::max_value()).to_string_in(D::MilliTPC), D::MilliTPC),  Err(ParseAmountError::TooBig));

        assert_eq!(sa_str(&sa_tap(-1).to_string_in(D::MicroTPC), D::MicroTPC), Ok(sa_tap(-1)));

        assert_eq!(sa_str(&sa_tap(i64::max_value()).to_string_in(D::Tapyrus), D::MicroTPC), Err(ParseAmountError::TooBig));
        // Test an overflow bug in `abs()`
        assert_eq!(sa_str(&sa_tap(i64::min_value()).to_string_in(D::Tapyrus), D::MicroTPC), Err(ParseAmountError::TooBig));

    }

    #[test]
    fn to_string_with_denomination_from_str_roundtrip() {
        use super::Denomination as D;

        let amt = Amount::from_tap(42);
        let denom = Amount::to_string_with_denomination;
        assert_eq!(Amount::from_str(&denom(amt, D::TPC)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MilliTPC)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MicroTPC)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Tapyrus)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::MilliTapyrus)), Ok(amt));

        assert_eq!(Amount::from_str("42 tapyrus TPC"), Err(ParseAmountError::InvalidFormat));
        assert_eq!(SignedAmount::from_str("-42 tapyrus TPC"), Err(ParseAmountError::InvalidFormat));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_tap() {

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_tap")]
            pub amt: Amount,
            #[serde(with = "::util::amount::serde::as_tap")]
            pub samt: SignedAmount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_tap(123456789),
                samt: SignedAmount::from_tap(-123456789),
            },
            &[
                serde_test::Token::Struct { name: "T", len: 2 },
                serde_test::Token::Str("amt"),
                serde_test::Token::U64(123456789),
                serde_test::Token::Str("samt"),
                serde_test::Token::I64(-123456789),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_tpc() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_tpc")]
            pub amt: Amount,
            #[serde(with = "::util::amount::serde::as_tpc")]
            pub samt: SignedAmount,
        }

        let orig = T {
            amt: Amount::from_tap(21_000_000__000_000_01),
            samt: SignedAmount::from_tap(-21_000_000__000_000_01),
        };

        let json = "{\"amt\": 21000000.00000001, \
                    \"samt\": -21000000.00000001}";
        let t: T = serde_json::from_str(&json).unwrap();
        assert_eq!(t, orig);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(t, serde_json::from_value(value).unwrap());

        // errors
        let t: Result<T, serde_json::Error> =
            serde_json::from_str("{\"amt\": 1000000.000000001, \"samt\": 1}");
        assert!(t
            .unwrap_err()
            .to_string()
            .contains(&ParseAmountError::TooPrecise.to_string()));
        let t: Result<T, serde_json::Error> = serde_json::from_str("{\"amt\": -1, \"samt\": 1}");
        assert!(t
            .unwrap_err()
            .to_string()
            .contains(&ParseAmountError::Negative.to_string()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_tpc_opt() {
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_tpc::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "::util::amount::serde::as_tpc::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_tap(2__500_000_00)),
            samt: Some(SignedAmount::from_tap(-2__500_000_00)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

        let t: T = serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value =
            serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }
}
