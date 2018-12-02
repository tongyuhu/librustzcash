use bech32::{convert_bits, Bech32};
use failure::Error;
use pairing::bls12_381::Bls12;
use sapling_crypto::{
    jubjub::edwards,
    primitives::{Diversifier, PaymentAddress},
};
use std::io::Write;
use zcash_primitives::JUBJUB;

pub fn encode_payment_address(hrp: &str, addr: &PaymentAddress<Bls12>) -> String {
    let mut data: Vec<u8> = Vec::with_capacity(43);
    data.write_all(&addr.diversifier.0)
        .expect("Should be able to write to a Vec");
    addr.pk_d
        .write(&mut data)
        .expect("Should be able to write to a Vec");

    let converted =
        convert_bits(&data, 8, 5, true).expect("Should be able to convert Vec<u8> to Vec<u5>");
    let encoded = Bech32::new_check_data(hrp.into(), converted).expect("hrp is not empty");

    encoded.to_string()
}

pub fn decode_payment_address(hrp: &str, s: &str) -> Result<PaymentAddress<Bls12>, Error> {
    let encoded = Bech32::from_str_lenient(s)?;
    if encoded.hrp() == hrp {
        let data = convert_bits(encoded.data(), 5, 8, false)?;
        let mut diversifier = Diversifier([0; 11]);
        diversifier.0.copy_from_slice(&data[0..11]);
        match edwards::Point::<Bls12, _>::read(&data[11..], &JUBJUB) {
            Ok(p) => match p.as_prime_order(&JUBJUB) {
                Some(pk_d) => Ok(PaymentAddress { pk_d, diversifier }),
                None => Err(format_err!("pk_d is not prime order")),
            },
            Err(e) => Err(format_err!("{}", e)),
        }
    } else {
        Err(format_err!("Invalid HRP"))
    }
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};
    use sapling_crypto::{
        jubjub::edwards,
        primitives::{Diversifier, PaymentAddress},
    };
    use zcash_primitives::JUBJUB;

    use super::{decode_payment_address, encode_payment_address};
    use constants;

    #[test]
    fn payment_address() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let addr = PaymentAddress {
            diversifier: Diversifier([0u8; 11]),
            pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        };

        let encoded_main =
            "zs1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjqj2ug6x";
        let encoded_test =
            "ztestsapling1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjq6awtaj";

        assert_eq!(
            encode_payment_address(constants::HRP_SAPLING_EXTENDED_SPENDING_KEY_MAIN, &addr),
            encoded_main
        );
        assert_eq!(
            decode_payment_address(
                constants::HRP_SAPLING_EXTENDED_SPENDING_KEY_MAIN,
                encoded_main
            ).unwrap(),
            addr
        );

        assert_eq!(
            encode_payment_address(constants::HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST, &addr),
            encoded_test
        );
        assert_eq!(
            decode_payment_address(
                constants::HRP_SAPLING_EXTENDED_SPENDING_KEY_TEST,
                encoded_test
            ).unwrap(),
            addr
        );
    }
}
