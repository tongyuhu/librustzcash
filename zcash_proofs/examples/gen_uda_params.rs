extern crate bellman;
extern crate pairing;
extern crate rand_os;
extern crate zcash_primitives;
extern crate zcash_proofs;

use bellman::groth16::generate_random_parameters;
use pairing::bls12_381::Bls12;
use rand_os::OsRng;
use std::fs::File;
use zcash_primitives::JUBJUB;
use zcash_proofs::circuit::sapling::{Output, Spend, TREE_DEPTH};

fn main() {
    let mut rng = OsRng;

    println!("Creating UDA spend parameters...");
    let spend_params = generate_random_parameters::<Bls12, _, _>(
        Spend::<Bls12> {
            params: &JUBJUB,
            value_commitment: None,
            proof_generation_key: None,
            payment_address: None,
            commitment_randomness: None,
            ar: None,
            auth_path: vec![None; TREE_DEPTH],
            anchor: None,
        },
        &mut rng,
    )
    .unwrap();

    println!("Creating UDA output parameters...");
    let output_params = generate_random_parameters::<Bls12, _, _>(
        Output::<Bls12> {
            params: &JUBJUB,
            value_commitment: None,
            payment_address: None,
            commitment_randomness: None,
            esk: None,
        },
        &mut rng,
    )
    .unwrap();

    let spend_fs =
        File::create("uda-spend.params").expect("couldn't open UDA spend parameters file");
    let output_fs =
        File::create("uda-output.params").expect("couldn't open UDA output parameters file");

    spend_params.write(spend_fs).unwrap();
    output_params.write(output_fs).unwrap();
}
