#[macro_use]
extern crate lazy_static;

extern crate aes;
extern crate blake2_rfc;
extern crate byteorder;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate fpe;
extern crate hex;
extern crate pairing;
extern crate rand;
extern crate sha2;
extern crate subtle;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

use crate::jubjub::JubjubBls12;

pub mod block;
pub mod constants;
pub mod group_hash;
pub mod jubjub;
pub mod keys;
pub mod legacy;
pub mod merkle_tree;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod primitives;
pub mod prover;
pub mod redjubjub;
pub mod sapling;
mod serialize;
pub mod transaction;
mod util;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
