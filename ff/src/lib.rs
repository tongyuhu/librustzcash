#![allow(unused_imports)]

extern crate byteorder;
extern crate rand;
extern crate subtle;

#[cfg(feature = "derive")]
#[macro_use]
extern crate ff_derive;

#[cfg(feature = "derive")]
pub use ff_derive::*;

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{ConditionallySelectable, CtOption};

/// This trait represents an element of a field.
pub trait Field:
    Sized
    + Eq
    + Copy
    + Clone
    + Default
    + Send
    + Sync
    + fmt::Debug
    + fmt::Display
    + 'static
    + rand::Rand
    + ConditionallySelectable
    + FieldOps
    + for<'r> FieldOps<&'r Self>
    + FieldAssignOps
    + for<'r> FieldAssignOps<&'r Self>
{
    /// Returns the zero element of the field, the additive identity.
    fn zero() -> Self;

    /// Returns the one element of the field, the multiplicative identity.
    fn one() -> Self;

    /// Returns true iff this element is zero.
    fn is_zero(&self) -> bool;

    /// Squares this element.
    #[must_use]
    fn square(&self) -> Self;

    /// Doubles this element.
    #[must_use]
    fn double(&self) -> Self;

    /// Computes the multiplicative inverse of this element,
    /// failing if the element is zero.
    fn invert(&self) -> CtOption<Self>;

    /// Exponentiates this element by a power of the base prime modulus via
    /// the Frobenius automorphism.
    fn frobenius_map(&mut self, power: usize);

    /// Exponentiates `self` by `exp`, where `exp` is a little-endian order
    /// integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the
    /// exponent is fixed, this operation is effectively constant time.
    fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::one();
        for e in exp.as_ref().iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }

        res
    }
}

/// The trait for types implementing basic field operations.
///
/// This is automatically implemented for types which implement the operators.
pub trait FieldOps<Rhs = Self, Output = Self>:
    Neg<Output = Output>
    + Add<Rhs, Output = Output>
    + Sub<Rhs, Output = Output>
    + Mul<Rhs, Output = Output>
{
}

impl<T, Rhs, Output> FieldOps<Rhs, Output> for T where
    T: Neg<Output = Output>
        + Add<Rhs, Output = Output>
        + Sub<Rhs, Output = Output>
        + Mul<Rhs, Output = Output>
{
}

/// The trait for types implementing field assignment operators (like `+=`).
///
/// This is automatically implemented for types which implement the operators.
pub trait FieldAssignOps<Rhs = Self>: AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> {}

impl<T, Rhs> FieldAssignOps<Rhs> for T where T: AddAssign<Rhs> + SubAssign<Rhs> + MulAssign<Rhs> {}

/// The trait for references which implement field operations, taking the
/// second operand either by value or by reference.
///
/// This is automatically implemented for types which implement the operators.
pub trait RefField<Base>: FieldOps<Base, Base> + for<'r> FieldOps<&'r Base, Base> {}
impl<T, Base> RefField<Base> for T where T: FieldOps<Base, Base> + for<'r> FieldOps<&'r Base, Base> {}

/// This trait represents an element of a field that has a square root operation described for it.
pub trait SqrtField: Field {
    /// Returns the square root of the field element, if it is
    /// quadratic residue.
    fn sqrt(&self) -> CtOption<Self>;
}

/// This represents an element of a prime field.
pub trait PrimeField: Field// + Read + Write
    // + AsRef<[u64]>
    // + AsMut<[u64]>
    + From<u64> {
    /// The prime field can be converted back and forth into this binary
    /// representation.
    type Repr: AsRef<[u8]> + From<Self> + for<'r> From<&'r Self>;

    /// Attempts to convert a little-endian byte representation of a field element into an
    /// element of this prime field, failing if the input is not canonical (is not smaller
    /// than the field's modulus).
    fn from_bytes(&Self::Repr) -> CtOption<Self>;

    /// Converts an element of the prime field into a byte representation in little-endian
    /// byte order.
    fn to_bytes(&self) -> Self::Repr;

    /// Returns the field characteristic; the modulus.
    fn char() -> Self::Repr;

    /// How many bits are needed to represent an element of this field.
    const NUM_BITS: u32;

    /// How many bits of information can be reliably stored in the field element.
    const CAPACITY: u32;

    /// Returns the multiplicative generator of `char()` - 1 order. This element
    /// must also be quadratic nonresidue.
    fn multiplicative_generator() -> Self;

    /// 2^s * t = `char()` - 1 with t odd.
    const S: u32;

    /// Returns the 2^s root of unity computed by exponentiating the `multiplicative_generator()`
    /// by t.
    fn root_of_unity() -> Self;
}

/// An "engine" is a collection of types (fields, elliptic curve groups, etc.)
/// with well-defined relationships. Specific relationships (for example, a
/// pairing-friendly curve) can be defined in a subtrait.
pub trait ScalarEngine: Sized + 'static + Clone {
    /// This is the scalar field of the engine's groups.
    type Fr: PrimeField + SqrtField;
}

#[derive(Debug)]
pub struct BitIterator<E> {
    t: E,
    n: usize,
}

impl<E: AsRef<[u64]>> BitIterator<E> {
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 64;

        BitIterator { t, n }
    }
}

impl<E: AsRef<[u64]>> Iterator for BitIterator<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 64;
            let bit = self.n - (64 * part);

            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}

#[test]
fn test_bit_iterator() {
    let mut a = BitIterator::new([0xa953d79b83f6ab59, 0x6dea2059e200bd39]);
    let expected = "01101101111010100010000001011001111000100000000010111101001110011010100101010011110101111001101110000011111101101010101101011001";

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());

    let expected = "1010010101111110101010000101101011101000011101110101001000011001100100100011011010001011011011010001011011101100110100111011010010110001000011110100110001100110011101101000101100011100100100100100001010011101010111110011101011000011101000111011011101011001";

    let mut a = BitIterator::new([
        0x429d5f3ac3a3b759,
        0xb10f4c66768b1c92,
        0x92368b6d16ecd3b4,
        0xa57ea85ae8775219,
    ]);

    for e in expected.chars() {
        assert!(a.next().unwrap() == (e == '1'));
    }

    assert!(a.next().is_none());
}

pub use self::arith_impl::*;

mod arith_impl {
    /// Calculate a - b - borrow, returning the result and modifying
    /// the borrow value.
    #[inline(always)]
    pub fn sbb(a: u64, b: u64, borrow: &mut u64) -> u64 {
        let tmp = (1u128 << 64) + u128::from(a) - u128::from(b) - u128::from(*borrow);

        *borrow = if tmp >> 64 == 0 { 1 } else { 0 };

        tmp as u64
    }

    /// Calculate a + b + carry, returning the sum and modifying the
    /// carry value.
    #[inline(always)]
    pub fn adc(a: u64, b: u64, carry: &mut u64) -> u64 {
        let tmp = u128::from(a) + u128::from(b) + u128::from(*carry);

        *carry = (tmp >> 64) as u64;

        tmp as u64
    }

    /// Calculate a + (b * c) + carry, returning the least significant digit
    /// and setting carry to the most significant digit.
    #[inline(always)]
    pub fn mac_with_carry(a: u64, b: u64, c: u64, carry: &mut u64) -> u64 {
        let tmp = (u128::from(a)) + u128::from(b) * u128::from(c) + u128::from(*carry);

        *carry = (tmp >> 64) as u64;

        tmp as u64
    }
}
