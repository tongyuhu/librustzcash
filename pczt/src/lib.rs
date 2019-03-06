use bellman::groth16::Parameters;
use failure::{format_err, Error};
use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::Bls12;
use protobuf::{parse_from_bytes, Message};
use rand::{OsRng, Rand};
use sapling_crypto::{
    jubjub::{
        edwards,
        fs::{Fs, FsRepr},
        JubjubBls12,
    },
    primitives::{Note, PaymentAddress},
};
use zcash_client_backend::note_encryption::{Memo, SaplingNoteEncryption};
use zcash_primitives::JUBJUB;
use zcash_proofs::sapling::SaplingProvingContext;
use zip32::OutgoingViewingKey;

pub mod proto;

use crate::proto::pczt::{PartiallyCreatedTransaction, PcztOutput};

pub fn add_sapling_output(
    pczt: &[u8],
    ovk: OutgoingViewingKey,
    to: PaymentAddress<Bls12>,
    value: u64,
    memo: Memo,
    proving_key: &Parameters<Bls12>,
    params: &JubjubBls12,
) -> Result<Vec<u8>, Error> {
    let mut pczt: PartiallyCreatedTransaction = parse_from_bytes(&pczt).unwrap();

    let g_d = match to.g_d(&JUBJUB) {
        Some(g_d) => g_d,
        None => return Err(format_err!("Invalid target address")),
    };

    let mut rng = OsRng::new().expect("should be able to construct RNG");
    let rcm = Fs::rand(&mut rng);

    let note = Note {
        g_d,
        pk_d: to.pk_d.clone(),
        value,
        r: rcm,
    };

    let encryptor = SaplingNoteEncryption::new(ovk, note.clone(), to.clone(), memo);

    let mut ctx = if pczt.get_global().bsk.is_empty() && pczt.get_global().bvk.is_empty() {
        SaplingProvingContext::new()
    } else {
        let bsk = {
            let mut r = FsRepr::default();
            r.read_le(&pczt.get_global().bsk[..])?;
            match Fs::from_repr(r) {
                Ok(p) => p,
                Err(_) => return Err(format_err!("Invalid bsk")),
            }
        };

        let bvk = edwards::Point::<Bls12, _>::read(&pczt.get_global().bvk[..], &JUBJUB)?;

        SaplingProvingContext::from_partial(bsk, bvk)
    };

    let (zkproof, rcv, cv) = ctx.output_proof(
        encryptor.esk().clone(),
        to,
        note.r,
        note.value,
        proving_key,
        params,
    );

    let cmu = note.cm(&JUBJUB);

    let enc_ciphertext = encryptor.encrypt_note_plaintext();
    let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu);

    let mut output = PcztOutput::new();
    cv.write(&mut output.cv)?;
    cmu.into_repr().write_le(&mut output.cmu)?;
    encryptor.epk().write(&mut output.epk)?;
    output.encCiphertext.extend_from_slice(&enc_ciphertext);
    output.outCiphertext.extend_from_slice(&out_ciphertext);
    zkproof.write(&mut output.zkproof)?;
    output.value = value;
    rcv.into_repr().write_le(&mut output.rcv)?;
    pczt.outputs.push(output);

    pczt.mut_global().valueBalance -= value as i64;
    pczt.mut_global().clear_bsk();
    pczt.mut_global().clear_bvk();
    ctx.bsk().into_repr().write_le(&mut pczt.mut_global().bsk)?;
    ctx.bvk().write(&mut pczt.mut_global().bvk)?;

    Ok(pczt.write_to_bytes().unwrap())
}
