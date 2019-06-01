use super::ToUniform;

pub use new_jubjub::Fr as Fs;

impl ToUniform for Fs {
    /// Convert a little endian byte string into a uniform
    /// field element. The number is reduced mod s. The caller
    /// is responsible for ensuring the input is 64 bytes of
    /// Random Oracle output.
    fn to_uniform(digest: &[u8]) -> Self {
        assert_eq!(digest.len(), 64);
        let mut tmp = [0; 64];
        tmp.copy_from_slice(digest);
        Fs::from_bytes_wide(&tmp)
    }
}

#[cfg(test)]
use ff::{Field, PrimeField, SqrtField};

#[cfg(test)]
use rand::{Rand, SeedableRng, XorShiftRng};

#[cfg(test)]
use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

// #[test]
// fn test_fs_ordering() {
//     fn assert_equality(a: Fs, b: Fs) {
//         assert_eq!(a, b);
//         assert!(a.cmp(&b) == ::std::cmp::Ordering::Equal);
//     }

//     fn assert_lt(a: Fs, b: Fs) {
//         assert!(a < b);
//         assert!(b > a);
//     }

//     assert_equality(
//         Fs::from_raw([9999, 9999, 9999, 9999]),
//         Fs::from_raw([9999, 9999, 9999, 9999]),
//     );
//     assert_equality(
//         Fs::from_raw([9999, 9998, 9999, 9999]),
//         Fs::from_raw([9999, 9998, 9999, 9999]),
//     );
//     assert_equality(
//         Fs::from_raw([9999, 9999, 9999, 9997]),
//         Fs::from_raw([9999, 9999, 9999, 9997]),
//     );
//     assert_lt(
//         Fs::from_raw([9999, 9997, 9999, 9998]),
//         Fs::from_raw([9999, 9997, 9999, 9999]),
//     );
//     assert_lt(
//         Fs::from_raw([9999, 9997, 9998, 9999]),
//         Fs::from_raw([9999, 9997, 9999, 9999]),
//     );
//     assert_lt(
//         Fs::from_raw([9, 9999, 9999, 9997]),
//         Fs::from_raw([9999, 9999, 9999, 9997]),
//     );
// }

#[test]
fn test_fs_from() {
    assert_eq!(Fs::from(100), Fs::from_raw([100, 0, 0, 0]));
}

#[test]
fn test_fs_is_zero() {
    assert!(Fs::from(0).is_zero());
    assert!(!Fs::from(1).is_zero());
    assert!(!Fs::from_raw([0, 0, 1, 0]).is_zero());
}

// #[test]
// fn test_fs_is_valid() {
//     let mut a = Fs(MODULUS);
//     assert!(!a.is_valid());
//     a.0.sub_noborrow(&Fs::from(1));
//     assert!(a.is_valid());
//     assert!(Fs::from(0).is_valid());
//     assert!(Fs::from_raw([
//         0xd0970e5ed6f72cb6,
//         0xa6682093ccc81082,
//         0x6673b0101343b00,
//         0xe7db4ea6533afa9
//     ])
//     .is_valid());
//     assert!(!Fs::from_raw([
//         0xffffffffffffffff,
//         0xffffffffffffffff,
//         0xffffffffffffffff,
//         0xffffffffffffffff
//     ])
//     .is_valid());

//     let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//     for _ in 0..1000 {
//         let a = Fs::rand(&mut rng);
//         assert!(a.is_valid());
//     }
// }

#[test]
fn test_fs_add_assign() {
    {
        // Random number
        let mut tmp = Fs::from_raw([
            0x8e6bfff4722d6e67,
            0x5643da5c892044f9,
            0x9465f4b281921a69,
            0x25f752d3edd7162,
        ]);
        // assert!(tmp.is_valid());
        // Test that adding zero has no effect.
        tmp.add_assign(&Fs::from(0));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x8e6bfff4722d6e67,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ])
        );
        // Add one and test for the result.
        tmp.add_assign(&Fs::from(1));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x8e6bfff4722d6e68,
                0x5643da5c892044f9,
                0x9465f4b281921a69,
                0x25f752d3edd7162
            ])
        );
        // Add another random number that exercises the reduction.
        tmp.add_assign(&Fs::from_raw([
            0xb634d07bc42d4a70,
            0xf724f0c008411f5f,
            0x456d4053d865af34,
            0x24ce814e8c63027,
        ]));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x44a0d070365ab8d8,
                0x4d68cb1c91616459,
                0xd9d3350659f7c99e,
                0x4ac5d4227a3a189
            ])
        );
        // Add one to (s - 1) and test for the result.
        tmp = Fs::from_raw([
            0xd0970e5ed6f72cb6,
            0xa6682093ccc81082,
            0x6673b0101343b00,
            0xe7db4ea6533afa9,
        ]);
        tmp.add_assign(&Fs::from(1));
        assert!(tmp.is_zero());
        // Add a random number to another one such that the result is s - 1
        tmp = Fs::from_raw([
            0xa11fda5950ce3636,
            0x922e0dbccfe0ca0e,
            0xacebb6e215b82d4a,
            0x97ffb8cdc3aee93,
        ]);
        tmp.add_assign(&Fs::from_raw([
            0x2f7734058628f680,
            0x143a12d6fce74674,
            0x597b841eeb7c0db6,
            0x4fdb95d88f8c115,
        ]));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0xd0970e5ed6f72cb6,
                0xa6682093ccc81082,
                0x6673b0101343b00,
                0xe7db4ea6533afa9
            ])
        );
        // Add one to the result and test for it.
        tmp.add_assign(&Fs::from(1));
        assert!(tmp.is_zero());
    }

    // Test associativity

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);
        let c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);

        let mut tmp2 = b;
        tmp2.add_assign(&c);
        tmp2.add_assign(&a);

        // assert!(tmp1.is_valid());
        // assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fs_sub_assign() {
    {
        // Test arbitrary subtraction that tests reduction.
        let mut tmp = Fs::from_raw([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ]);
        tmp.sub_assign(&Fs::from_raw([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ]));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x97c015841f9b79f6,
                0xe7fcb121eb6ffc49,
                0xb8c050814de2a3c1,
                0x943c0589dcafa21
            ])
        );

        // Test the opposite subtraction which doesn't test reduction.
        tmp = Fs::from_raw([
            0xec5bd2d13ed6b05a,
            0x2adc0ab3a39b5fa,
            0x82d3360a493e637e,
            0x53ccff4a64d6679,
        ]);
        tmp.sub_assign(&Fs::from_raw([
            0xb384d9f6877afd99,
            0x4442513958e1a1c1,
            0x352c4b8a95eccc3f,
            0x2db62dee4b0f2,
        ]));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x38d6f8dab75bb2c1,
                0xbe6b6f71e1581439,
                0x4da6ea7fb351973e,
                0x539f491c768b587
            ])
        );

        // Test for sensible results with zero
        tmp = Fs::from(0);
        tmp.sub_assign(&Fs::from(0));
        assert!(tmp.is_zero());

        tmp = Fs::from_raw([
            0x361e16aef5cce835,
            0x55bbde2536e274c1,
            0x4dc77a63fd15ee75,
            0x1e14bb37c14f230,
        ]);
        tmp.sub_assign(&Fs::from(0));
        assert_eq!(
            tmp,
            Fs::from_raw([
                0x361e16aef5cce835,
                0x55bbde2536e274c1,
                0x4dc77a63fd15ee75,
                0x1e14bb37c14f230
            ])
        );
    }

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(&tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fs_mul_assign() {
    let mut tmp = Fs::from_raw([
        0xb433b01287f71744,
        0x4eafb86728c4d108,
        0xfdd52c14b9dfbe65,
        0x2ff1f3434821118,
    ]);
    tmp.mul_assign(&Fs::from_raw([
        0xdae00fc63c9fa90f,
        0x5a5ed89b96ce21ce,
        0x913cd26101bd6f58,
        0x3f0822831697fe9,
    ]));
    assert!(
        tmp == Fs::from_raw([
            0x0c5ee583109a143c,
            0xd9a7915ec05b5ce8,
            0xbbbe189f7e43bca7,
            0xdd7213097a66bca
        ])
    );

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fs::rand(&mut rng);
        let b = Fs::rand(&mut rng);
        let c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fs::rand(&mut rng);
        let mut a = Fs::rand(&mut rng);
        let mut b = Fs::rand(&mut rng);
        let mut c = Fs::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(&b);
        a.add_assign(&c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fr_squaring() {
    let a = Fs::from_raw([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xe7db4ea6533afa8,
    ]);
    // assert!(a.is_valid());
    assert_eq!(
        a.square(),
        Fs::from_raw([
            0x8f053247ded5a5d9,
            0x9e86c7de4578a024,
            0xc81e4e619fd9a6e1,
            0x723777d257a7520
        ])
    );

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fs::rand(&mut rng);

        let tmp = a.square();

        let mut tmp2 = a;
        tmp2.mul_assign(&a);

        assert_eq!(tmp, tmp2);
    }
}

#[test]
fn test_fs_invert() {
    assert!(bool::from(Fs::zero().invert().is_none()));

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let one = Fs::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fs::rand(&mut rng);
        let ainv = a.invert().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fs_double() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let mut a = Fs::rand(&mut rng);
        assert_eq!(a.double(), a + a);
    }
}

#[test]
fn test_fs_neg() {
    {
        let a = Fs::zero().neg();

        assert!(a.is_zero());
    }

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fs::rand(&mut rng);
        let b = a.neg();
        a.add_assign(&b);

        assert!(a.is_zero());
    }
}

// #[test]
// fn test_fs_pow() {
//     let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

//     for i in 0..1000 {
//         // Exponentiate by various small numbers and ensure it consists with repeated
//         // multiplication.
//         let a = Fs::rand(&mut rng);
//         let target = a.pow_vartime(&[i]);
//         let mut c = Fs::one();
//         for _ in 0..i {
//             c.mul_assign(&a);
//         }
//         assert_eq!(c, target);
//     }

//     for _ in 0..1000 {
//         // Exponentiating by the modulus should have no effect in a prime field.
//         let a = Fs::rand(&mut rng);

//         assert_eq!(a, a.pow_vartime(Fs::char()));
//     }
// }

#[test]
fn test_fs_sqrt() {
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    assert_eq!(Fs::zero().sqrt().unwrap(), Fs::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fs::rand(&mut rng);
        let nega = a.neg();
        let b = a.square();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fs::rand(&mut rng);

        let tmp = a.sqrt();
        if tmp.is_some().into() {
            assert_eq!(a, tmp.unwrap().square());
        }
    }
}

#[test]
fn test_fs_from_into_repr() {
    // r + 1 should not be in the field
    assert!(bool::from(
        Fs::from_bytes(&[
            0xb8, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20,
            0x68, 0xa6, 0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65,
            0xea, 0xb4, 0x7d, 0x0e
        ])
        .is_none()
    ));

    // r should not be in the field
    assert!(bool::from(
        Fs::from_bytes(&[
            0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20,
            0x68, 0xa6, 0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65,
            0xea, 0xb4, 0x7d, 0x0e
        ])
        .is_none()
    ));

    // Multiply some arbitrary representations to see if the result is as expected.
    let mut a_fs = Fs::from_raw([
        0x5f2d0c05d0337b71,
        0xa1df2b0f8a20479,
        0xad73785e71bb863,
        0x504a00480c9acec,
    ]);
    let b_fs = Fs::from_raw([
        0x66356ff51e477562,
        0x60a92ab55cf7603,
        0x8e4273c7364dd192,
        0x36df8844a344dc5,
    ]);
    let c = Fs::from_raw([
        0x7eef61708f4f2868,
        0x747a7e6cf52946fb,
        0x83dd75d7c9120017,
        0x762f5177f0f3df7,
    ])
    .to_bytes();
    a_fs.mul_assign(&b_fs);
    assert_eq!(a_fs.to_bytes(), c);

    // Zero should be in the field.
    assert!(Fs::from(0).is_zero());

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    for _ in 0..1000 {
        // Try to turn Fs elements into representations and back again, and compare.
        let a = Fs::rand(&mut rng);
        let a_repr = a.to_bytes();
        let a_again = Fs::from_bytes(&a_repr).unwrap();

        assert_eq!(a, a_again);
    }
}

#[test]
fn test_fs_display() {
    assert_eq!(
        format!(
            "{}",
            Fs::from_raw([
                0x5528efb9998a01a3,
                0x5bd2add5cb357089,
                0xc061fa6adb491f98,
                0x70db9d143db03d9
            ])
        ),
        "Fr(0x070db9d143db03d9c061fa6adb491f985bd2add5cb3570895528efb9998a01a3)".to_string()
    );
    assert_eq!(
        format!(
            "{}",
            Fs::from_raw([
                0xd674745e2717999e,
                0xbeb1f52d3e96f338,
                0x9c7ae147549482b9,
                0x999706024530d22
            ])
        ),
        "Fr(0x0999706024530d229c7ae147549482b9beb1f52d3e96f338d674745e2717999e)".to_string()
    );
}

#[test]
fn test_fs_num_bits() {
    assert_eq!(Fs::NUM_BITS, 252);
    assert_eq!(Fs::CAPACITY, 251);
}

#[test]
fn test_fs_root_of_unity() {
    assert_eq!(Fs::S, 1);
    assert_eq!(Fs::multiplicative_generator(), Fs::from(6));
    assert_eq!(
        Fs::multiplicative_generator().pow_vartime([
            0x684b872f6b7b965b,
            0x53341049e6640841,
            0x83339d80809a1d80,
            0x73eda753299d7d4
        ]),
        Fs::root_of_unity()
    );
    assert_eq!(Fs::root_of_unity().pow_vartime([1 << Fs::S]), Fs::one());
    assert!(bool::from(Fs::multiplicative_generator().sqrt().is_none()));
}
