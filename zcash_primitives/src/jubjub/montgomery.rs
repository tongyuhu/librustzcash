use group::{CurveAffine, CurveProjective};
use std::ops::Neg;
use subtle::ConstantTimeEq;

use super::{edwards, JubjubEngine, PrimeOrder, Unknown};

use rand::{Rand, Rng};

use std::marker::PhantomData;

// Represents the affine point (X, Y)
pub struct Point<E: JubjubEngine, Subgroup> {
    pub(super) inner: E::AffinePoint,
    infinity: bool,
    _marker: PhantomData<Subgroup>,
}

fn convert_subgroup<E: JubjubEngine, S1, S2>(from: &Point<E, S1>) -> Point<E, S2> {
    Point {
        inner: from.inner,
        infinity: from.infinity,
        _marker: PhantomData,
    }
}

impl<E: JubjubEngine> From<Point<E, PrimeOrder>> for Point<E, Unknown> {
    fn from(p: Point<E, PrimeOrder>) -> Point<E, Unknown> {
        convert_subgroup(&p)
    }
}

impl<E: JubjubEngine, Subgroup> Clone for Point<E, Subgroup> {
    fn clone(&self) -> Self {
        convert_subgroup(self)
    }
}

impl<E: JubjubEngine, Subgroup> PartialEq for Point<E, Subgroup> {
    fn eq(&self, other: &Point<E, Subgroup>) -> bool {
        match (self.infinity, other.infinity) {
            (true, true) => true,
            (true, false) | (false, true) => false,
            (false, false) => self.inner.ct_eq(&other.inner).into(),
        }
    }
}

impl<E: JubjubEngine> Point<E, Unknown> {
    // pub fn get_for_x(x: E::Fr, sign: bool, params: &E::Params) -> CtOption<Self> {
    //     // Given an x on the curve, y = sqrt(x^3 + A*x^2 + x)

    //     let mut x2 = x.square();

    //     let mut rhs = x2;
    //     rhs.mul_assign(params.montgomery_a());
    //     rhs.add_assign(&x);
    //     x2.mul_assign(&x);
    //     rhs.add_assign(&x2);

    //     rhs.sqrt().map(|mut y| {
    //         if y.into_repr().is_odd() != sign {
    //             y = y.neg();
    //         }

    //         Point {
    //             x: x,
    //             y: y,
    //             infinity: false,
    //             _marker: PhantomData,
    //         }
    //     })
    // }

    /// This guarantees the point is in the prime order subgroup
    #[must_use]
    pub fn mul_by_cofactor(&self, params: &E::Params) -> Point<E, PrimeOrder> {
        let tmp = self.double(params).double(params).double(params);

        convert_subgroup(&tmp)
    }

    pub fn rand<R: Rng>(rng: &mut R, params: &E::Params) -> Self {
        let p = E::ExtendedPoint::rand(rng).into_affine();
        if p.is_zero() {
            Point::zero()
        } else {
            Point {
                inner: p,
                infinity: false,
                _marker: PhantomData,
            }
        }
    }
}

impl<E: JubjubEngine, Subgroup> Point<E, Subgroup> {
    /// Convert from an Edwards point
    pub fn from_edwards(e: &edwards::Point<E, Subgroup>, params: &E::Params) -> Self {
        if e.inner.is_zero() {
            // The only solution for y = 1 is x = 0. (0, 1) is
            // the neutral element, so we map this to the point
            // at infinity.
            Point::zero()
        } else {
            Point {
                inner: e.inner.into_affine(),
                infinity: false,
                _marker: PhantomData,
            }
        }
    }

    /// Attempts to cast this as a prime order element, failing if it's
    /// not in the prime order subgroup.
    pub fn as_prime_order(&self, params: &E::Params) -> Option<Point<E, PrimeOrder>> {
        if self.inner.into_projective().is_prime_order().into() {
            Some(convert_subgroup(self))
        } else {
            None
        }
    }

    pub fn zero() -> Self {
        Point {
            inner: E::AffinePoint::zero(),
            infinity: true,
            _marker: PhantomData,
        }
    }

    pub fn into_xy(&self) -> Option<(E::Fr, E::Fr)> {
        if self.infinity {
            None
        } else {
            Some((self.inner.get_u(), self.inner.get_v()))
        }
    }

    #[must_use]
    pub fn negate(&self) -> Self {
        let mut p = self.clone();
        p.inner = p.inner.neg();
        p
    }

    #[must_use]
    pub fn double(&self, params: &E::Params) -> Self {
        if self.infinity {
            return Point::zero();
        }

        let doubled = self.inner.into_projective().double();
        if doubled.is_zero() {
            Point::zero()
        } else {
            Point {
                inner: doubled.into_affine(),
                infinity: false,
                _marker: PhantomData,
            }
        }
    }

    #[must_use]
    pub fn add(&self, other: &Self, params: &E::Params) -> Self {
        // This is a standard affine point addition formula
        // See 4.3.2 The group law for Weierstrass curves
        //     Montgomery curves and the Montgomery Ladder
        //     Daniel J. Bernstein and Tanja Lange

        match (self.infinity, other.infinity) {
            (true, true) => Point::zero(),
            (true, false) => other.clone(),
            (false, true) => self.clone(),
            (false, false) => {
                if self.inner == other.inner {
                    self.double(params)
                } else {
                    let added = self.inner.into_projective() + &other.inner.into_projective();
                    if added.is_zero() {
                        Point::zero()
                    } else {
                        Point {
                            inner: added.into_affine(),
                            infinity: false,
                            _marker: PhantomData,
                        }
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn mul<S: Into<E::Fs>>(&self, scalar: S, params: &E::Params) -> Self {
        let mut p = self.clone();
        p.inner = p.inner.mul(scalar.into()).into_affine();
        p
    }
}
