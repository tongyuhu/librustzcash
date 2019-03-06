//! Add a Sapling output to a PCZT.

use pczt::add_sapling_output;
use rand::{OsRng, Rng};
use std::env;
use std::path::Path;
use zcash_client_backend::{
    constants::{
        HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY_TEST, HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST,
        HRP_SAPLING_PAYMENT_ADDRESS_TEST,
    },
    encoding::{
        decode_extended_full_viewing_key, decode_extended_spending_key, decode_payment_address,
    },
    note_encryption::Memo,
};
use zcash_primitives::JUBJUB;
use zcash_proofs::load_parameters;
use zip32::OutgoingViewingKey;

fn main() {
    let options = vec![
        "f/from#The Sapling ExtendedFullViewingKey to make this output decryptable by; default=undecryptable:",
        ":/pczt#The PCZT to modify",
        ":/to#A Sapling address",
        ":/value#The amount, in zatoshis, of the output",
    ];

    let mut vars = match pirate::vars("add_output", &options) {
        Ok(v) => v,
        Err(why) => panic!("Error: {}", why),
    };

    let args: Vec<String> = env::args().collect();
    let matches = match pirate::matches(&args, &mut vars) {
        Ok(m) => m,
        Err(why) => {
            println!("Error: {}", why);
            pirate::usage(&vars);
            return;
        }
    };

    let pczt = {
        let encoded = matches.get("pczt").unwrap();
        base64::decode(encoded).unwrap()
    };

    let ovk = {
        if let Some(encoded) = matches.get("from") {
            let extsk =
                decode_extended_spending_key(HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST, encoded)
                    .unwrap();
            extsk.expsk.ovk
        } else {
            let mut rng = OsRng::new().expect("should be able to construct RNG");
            let mut ovk = [0; 32];
            rng.fill_bytes(&mut ovk);
            OutgoingViewingKey(ovk)
        }
    };

    let to = {
        let encoded = matches.get("to").unwrap();
        decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS_TEST, encoded).unwrap()
    };

    let value = {
        let value = matches.get("value").unwrap();
        value.parse::<u64>().unwrap()
    };

    let (_, _, output_params, _, _) = load_parameters(
        Path::new("/home/str4d/.zcash-params/sapling-spend.params"),
        "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
        Path::new("/home/str4d/.zcash-params/sapling-output.params"),
        "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
        None,
        None,
    );

    let pczt = add_sapling_output(
        &pczt,
        ovk,
        to,
        value,
        Memo::default(),
        &output_params,
        &JUBJUB,
    )
    .unwrap();

    println!("Updated PCZT: {}", base64::encode(&pczt));
}
