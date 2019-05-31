extern crate byteorder;
extern crate ff;
extern crate rand;
extern crate subtle;

use ff::{PrimeField, ScalarEngine, SqrtField};
use std::fmt;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConstantTimeEq, CtOption};

pub mod tests;

// mod wnaf;
// pub use self::wnaf::Wnaf;

/// Projective representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
pub trait CurveProjective:
    PartialEq
    + Eq
    + Sized
    + Copy
    + Clone
    + Send
    + Sync
    + fmt::Debug
    + fmt::Display
    + rand::Rand
    + 'static
    + ConstantTimeEq
    + CurveAddOps
    + for<'r> CurveAddOps<&'r Self>
    + CurveAddAssignOps
    + for<'r> CurveAddAssignOps<&'r Self>
{
    type Engine: ScalarEngine<Fr = Self::Scalar>;
    type Scalar: PrimeField + SqrtField;
    type Base: SqrtField;
    type Affine: CurveAffine<Projective = Self, Scalar = Self::Scalar>;

    /// Returns the additive identity.
    fn zero() -> Self;

    // /// Returns a fixed generator of unknown exponent.
    // fn one() -> Self;

    /// Determines if this point is the point at infinity.
    fn is_zero(&self) -> bool;

    /// Determines if this point is prime order, or in other words that
    /// the smallest scalar multiplied by this point that produces the
    /// identity is `r`.
    fn is_prime_order(&self) -> Choice;

    // /// Normalizes a slice of projective elements so that
    // /// conversion to affine is cheap.
    // fn batch_normalization(v: &mut [Self]);

    // /// Checks if the point is already "normalized" so that
    // /// cheap affine conversion is possible.
    // fn is_normalized(&self) -> bool;

    /// Doubles this element.
    fn double(&self) -> Self;

    /// Adds an affine element to this element.
    fn add_assign_mixed(&mut self, other: &Self::Affine);

    /// Performs scalar multiplication of this element.
    fn mul_assign(&mut self, other: Self::Scalar);

    /// Converts this element into its affine representation.
    fn into_affine(&self) -> Self::Affine;

    // /// Recommends a wNAF window table size given a scalar. Always returns a number
    // /// between 2 and 22, inclusive.
    // fn recommended_wnaf_for_scalar(scalar: Self::Scalar) -> usize;

    // /// Recommends a wNAF window size given the number of scalars you intend to multiply
    // /// a base by. Always returns a number between 2 and 22, inclusive.
    // fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

/// Affine representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
pub trait CurveAffine:
    Copy
    + Clone
    + Sized
    + Send
    + Sync
    + fmt::Debug
    + fmt::Display
    + PartialEq
    + Eq
    + 'static
    + ConstantTimeEq
    + Neg<Output = Self>
{
    type Engine: ScalarEngine<Fr = Self::Scalar>;
    type Scalar: PrimeField + SqrtField;
    type Base: SqrtField;
    type Projective: CurveProjective<Affine = Self, Scalar = Self::Scalar>;
    // type Uncompressed: EncodedPoint<Affine = Self>;
    type Compressed: EncodedPoint<Affine = Self>;

    /// Returns the additive identity.
    fn zero() -> Self;

    // /// Returns a fixed generator of unknown exponent.
    // fn one() -> Self;

    /// Determines if this point represents the point at infinity; the
    /// additive identity.
    fn is_zero(&self) -> bool;

    /// Returns the `u`-coordinate of this point.
    fn get_u(&self) -> Self::Base;

    /// Returns the `v`-coordinate of this point.
    fn get_v(&self) -> Self::Base;

    /// Performs scalar multiplication of this element with mixed addition.
    fn mul(&self, other: Self::Scalar) -> Self::Projective;

    /// Converts this element into its affine representation.
    fn into_projective(&self) -> Self::Projective;

    /// Converts this element into its compressed encoding, so long as it's not
    /// the point at infinity.
    fn into_compressed(&self) -> Self::Compressed {
        <Self::Compressed as EncodedPoint>::from_affine(*self)
    }

    // /// Converts this element into its uncompressed encoding, so long as it's not
    // /// the point at infinity.
    // fn into_uncompressed(&self) -> Self::Uncompressed {
    //     <Self::Uncompressed as EncodedPoint>::from_affine(*self)
    // }
}

/// The trait for types implementing additive curve operations.
///
/// This is automatically implemented for types which implement the operators.
pub trait CurveAddOps<Rhs = Self, Output = Self>:
    Neg<Output = Output> + Add<Rhs, Output = Output> + Sub<Rhs, Output = Output>
{
}

impl<T, Rhs, Output> CurveAddOps<Rhs, Output> for T where
    T: Neg<Output = Output> + Add<Rhs, Output = Output> + Sub<Rhs, Output = Output>
{
}

/// The trait for types implementing additive curve assignment operators
/// (like `+=`).
///
/// This is automatically implemented for types which implement the operators.
pub trait CurveAddAssignOps<Rhs = Self>: AddAssign<Rhs> + SubAssign<Rhs> {}

impl<T, Rhs> CurveAddAssignOps<Rhs> for T where T: AddAssign<Rhs> + SubAssign<Rhs> {}

/// The trait for references which implement additive curve operations, taking
/// the second operand either by value or by reference.
///
/// This is automatically implemented for types which implement the operators.
pub trait RefCurve<Base>: CurveAddOps<Base, Base> + for<'r> CurveAddOps<&'r Base, Base> {}
impl<T, Base> RefCurve<Base> for T where
    T: CurveAddOps<Base, Base> + for<'r> CurveAddOps<&'r Base, Base>
{
}

/// An encoded elliptic curve point, which should essentially wrap a `[u8; N]`.
pub trait EncodedPoint:
    Sized + Send + Sync + AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + 'static
{
    type Affine: CurveAffine;

    /// Creates an empty representation.
    fn empty() -> Self;

    /// Returns the number of bytes consumed by this representation.
    fn size() -> usize;

    /// Converts an `EncodedPoint` into a `CurveAffine` element,
    /// if the encoding represents a valid element.
    fn into_affine(&self) -> CtOption<Self::Affine>;

    // /// Converts an `EncodedPoint` into a `CurveAffine` element,
    // /// without guaranteeing that the encoding represents a valid
    // /// element. This is useful when the caller knows the encoding is
    // /// valid already.
    // ///
    // /// If the encoding is invalid, this can break API invariants,
    // /// so caution is strongly encouraged.
    // fn into_affine_unchecked(&self) -> CtOption<Self::Affine>;

    /// Creates an `EncodedPoint` from an affine point, as long as the
    /// point is not the point at infinity.
    fn from_affine(affine: Self::Affine) -> Self;
}
