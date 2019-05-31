use byteorder::{ByteOrder, LittleEndian};
use ff::{Field, PrimeField};
use jubjub::*;
use std::ops::{AddAssign, Neg};

#[derive(Copy, Clone)]
pub enum Personalization {
    NoteCommitment,
    MerkleTree(usize)
}

impl Personalization {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalization::NoteCommitment =>
                vec![true, true, true, true, true, true],
            Personalization::MerkleTree(num) => {
                assert!(num < 63);

                (0..6).map(|i| (num >> i) & 1 == 1).collect()
            }
        }
    }
}

pub fn pedersen_hash<E, I>(
    personalization: Personalization,
    bits: I,
    params: &E::Params
) -> edwards::Point<E, PrimeOrder>
    where I: IntoIterator<Item=bool>,
          E: JubjubEngine
{
    let mut bits = personalization.get_bits().into_iter().chain(bits.into_iter());

    let mut result = edwards::Point::zero();
    let mut generators = params.pedersen_hash_exp_table().iter();

    loop {
        let mut acc = E::Fs::zero();
        let mut cur = E::Fs::one();
        let mut chunks_remaining = params.pedersen_hash_chunks_per_generator();
        let mut encountered_bits = false;

        // Grab three bits from the input
        while let Some(a) = bits.next() {
            encountered_bits = true;

            let b = bits.next().unwrap_or(false);
            let c = bits.next().unwrap_or(false);

            // Start computing this portion of the scalar
            let mut tmp = cur;
            if a {
                tmp.add_assign(&cur);
            }
            cur = cur.double(); // 2^1 * cur
            if b {
                tmp.add_assign(&cur);
            }

            // conditionally negate
            if c {
                tmp = tmp.neg();
            }

            acc.add_assign(&tmp);

            chunks_remaining -= 1;

            if chunks_remaining == 0 {
                break;
            } else {
                cur = cur.double().double().double(); // 2^4 * cur
            }
        }

        if !encountered_bits {
            break;
        }

        let mut table: &[Vec<edwards::Point<E, _>>] =
            &generators.next().expect("we don't have enough generators");
        let window = JubjubBls12::pedersen_hash_exp_window_size() as usize;
        let window_mask = (1 << window) - 1;

        let acc = acc.to_bytes();
        let bit_len = acc.as_ref().len() * 8;
        let u64_len = bit_len / 64;

        let mut acc_u64 = vec![0u64; u64_len + 1];
        LittleEndian::read_u64_into(acc.as_ref(), &mut acc_u64[0..u64_len]);

        let mut tmp = edwards::Point::zero();

        let mut pos = 0;
        while pos < bit_len {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64;
            if bit_idx < 64 - window {
                // This window's bits are contained in a single u64
                bit_buf = acc_u64[u64_idx] >> bit_idx;
            } else {
                // Combine the current u64's bits with the bits from the next u64
                bit_buf = (acc_u64[u64_idx] >> bit_idx) | (acc_u64[1 + u64_idx] << (64 - bit_idx));
            }
            let i = (bit_buf & window_mask) as usize;

            tmp = tmp.add(&table[0][i], params);

            pos += window;
            table = &table[1..];
        }

        result = result.add(&tmp, params);
    }

    result
}
