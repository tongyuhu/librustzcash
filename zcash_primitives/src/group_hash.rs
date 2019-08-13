use jubjub::{
    JubjubEngine,
    PrimeOrder,
    edwards
};

use ff::{
    PrimeField
};

use blake2s_simd::Params;
use constants;

/// Produces a random point in the Jubjub curve.
/// The point is guaranteed to be prime order
/// and not the identity.
pub fn group_hash<E: JubjubEngine>(
    tag: &[u8],
    personalization: &[u8],
    params: &E::Params
) -> Option<edwards::Point<E, PrimeOrder>>
{
    assert_eq!(personalization.len(), 8);

    // Check to see that scalar field is 255 bits
    assert!(E::Fr::NUM_BITS == 255);

    let h = Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(constants::GH_FIRST_BLOCK)
        .update(tag)
        .finalize();

    match edwards::Point::<E, _>::read(h.as_ref(), params) {
        Ok(p) => {
            let p = p.mul_by_cofactor(params);

            if p != edwards::Point::zero() {
                Some(p)
            } else {
                None
            }
        },
        Err(_) => None
    }
}

pub fn find_group_hash<E: JubjubEngine>(
    m: &[u8],
    personalization: &[u8; 8],
    params: &E::Params
) -> edwards::Point<E, PrimeOrder>
{
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    loop {
        let gh = group_hash(
            &tag,
            personalization,
            params
        );

        // We don't want to overflow and start reusing generators
        assert!(tag[i] != u8::max_value());
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}
