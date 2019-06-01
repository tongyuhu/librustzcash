use group::{CurveAffine, CurveProjective, EncodedPoint};
use std::ops::{Add, Neg};
use subtle::ConstantTimeEq;

use super::{montgomery, JubjubEngine, PrimeOrder, Unknown};

use rand::{Rand, Rng};

use std::marker::PhantomData;

use std::io::{self, Read, Write};

// Represents the affine point (X/Z, Y/Z) via the extended
// twisted Edwards coordinates.
//
// See "Twisted Edwards Curves Revisited"
//     Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
#[derive(Debug)]
pub struct Point<E: JubjubEngine, Subgroup> {
    pub(super) inner: E::ExtendedPoint,
    _marker: PhantomData<Subgroup>,
}

fn convert_subgroup<E: JubjubEngine, S1, S2>(from: &Point<E, S1>) -> Point<E, S2> {
    Point {
        inner: from.inner,
        _marker: PhantomData,
    }
}

impl<E: JubjubEngine> From<&Point<E, Unknown>> for Point<E, Unknown> {
    fn from(p: &Point<E, Unknown>) -> Point<E, Unknown> {
        p.clone()
    }
}

impl<E: JubjubEngine> From<Point<E, PrimeOrder>> for Point<E, Unknown> {
    fn from(p: Point<E, PrimeOrder>) -> Point<E, Unknown> {
        convert_subgroup(&p)
    }
}

impl<E: JubjubEngine> From<&Point<E, PrimeOrder>> for Point<E, Unknown> {
    fn from(p: &Point<E, PrimeOrder>) -> Point<E, Unknown> {
        convert_subgroup(p)
    }
}

impl<E: JubjubEngine, Subgroup> Clone for Point<E, Subgroup> {
    fn clone(&self) -> Self {
        convert_subgroup(self)
    }
}

impl<E: JubjubEngine, Subgroup> PartialEq for Point<E, Subgroup> {
    fn eq(&self, other: &Point<E, Subgroup>) -> bool {
        self.inner.ct_eq(&other.inner).into()
    }
}

impl<E: JubjubEngine> Point<E, Unknown> {
    pub fn read<R: Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
        let mut repr = <E::AffinePoint as CurveAffine>::Compressed::empty();
        reader.read_exact(repr.as_mut())?;
        let p = repr.into_affine();
        if p.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not on curve"));
        }
        Ok(Point {
            inner: p.unwrap().into_projective(),
            _marker: PhantomData,
        })
    }

    /// This guarantees the point is in the prime order subgroup
    #[must_use]
    pub fn mul_by_cofactor(&self, params: &E::Params) -> Point<E, PrimeOrder> {
        let tmp = self.double(params).double(params).double(params);

        convert_subgroup(&tmp)
    }

    pub fn rand<R: Rng>(rng: &mut R, params: &E::Params) -> Self {
        Point {
            inner: E::ExtendedPoint::rand(rng),
            _marker: PhantomData,
        }
    }
}

impl<E: JubjubEngine, Subgroup> Point<E, Subgroup> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.inner.into_affine().into_compressed().as_ref())
    }

    /// Convert from a Montgomery point
    pub fn from_montgomery(m: &montgomery::Point<E, Subgroup>, params: &E::Params) -> Self {
        Point {
            inner: m.inner.into_projective(),
            _marker: PhantomData,
        }
    }

    /// Attempts to cast this as a prime order element, failing if it's
    /// not in the prime order subgroup.
    pub fn as_prime_order(&self, params: &E::Params) -> Option<Point<E, PrimeOrder>> {
        if self.inner.is_prime_order().into() {
            Some(convert_subgroup(self))
        } else {
            None
        }
    }

    pub fn zero() -> Self {
        Point {
            inner: E::ExtendedPoint::zero(),
            _marker: PhantomData,
        }
    }

    pub fn into_xy(&self) -> (E::Fr, E::Fr) {
        let affine = self.inner.into_affine();
        (affine.get_u(), affine.get_v())
    }

    #[must_use]
    pub fn negate(&self) -> Self {
        let mut p = self.clone();
        p.inner = p.inner.neg();
        p
    }

    #[must_use]
    pub fn double(&self, _: &E::Params) -> Self {
        let mut p = self.clone();
        p.inner = p.inner.double();
        p
    }

    #[must_use]
    pub fn add(&self, other: &Self, params: &E::Params) -> Self {
        let mut p = self.clone();
        p.inner = p.inner.add(&other.inner);
        p
    }

    #[must_use]
    pub fn mul<S: Into<E::Fs>>(&self, scalar: S, params: &E::Params) -> Self {
        let mut p = self.clone();
        p.inner.mul_assign(scalar.into());
        p
    }
}
