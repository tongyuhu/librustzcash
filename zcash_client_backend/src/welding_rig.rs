//! Tools for scanning a compact representation of the Zcash block chain.

use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use protobuf::parse_from_bytes;
use sapling_crypto::jubjub::{edwards, fs::Fs};
use zcash_primitives::{
    note_encryption::try_sapling_compact_note_decryption, transaction::TxId,
    zip32::ExtendedFullViewingKey, JUBJUB,
};

use crate::proto::compact_formats::{CompactBlock, CompactOutput, CompactTx};
use crate::wallet::{EncCiphertextFrag, WalletShieldedOutput, WalletTx};

/// Scans a [`CompactOutput`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a [`WalletShieldedOutput`] if this output belongs to any of the given
/// [`ExtendedFullViewingKey`]s.
fn scan_output(
    (index, output): (usize, CompactOutput),
    ivks: &[Fs],
) -> Option<WalletShieldedOutput> {
    let mut repr = FrRepr::default();
    if repr.read_le(&output.cmu[..]).is_err() {
        return None;
    }
    let cmu = match Fr::from_repr(repr) {
        Ok(cmu) => cmu,
        Err(_) => return None,
    };

    let epk = match edwards::Point::<Bls12, _>::read(&output.epk[..], &JUBJUB) {
        Ok(p) => match p.as_prime_order(&JUBJUB) {
            Some(epk) => epk,
            None => return None,
        },
        Err(_) => return None,
    };

    let ct = output.ciphertext;

    for (account, ivk) in ivks.iter().enumerate() {
        let value = match try_sapling_compact_note_decryption(ivk, &epk, &cmu, &ct) {
            Some((note, _)) => note.value,
            None => continue,
        };

        // It's ours, so let's copy the ciphertext fragment and return
        let mut enc_ct = EncCiphertextFrag([0u8; 52]);
        enc_ct.0.copy_from_slice(&ct);

        return Some(WalletShieldedOutput {
            index,
            cmu,
            epk,
            enc_ct,
            account,
            value,
        });
    }
    None
}

/// Scans a [`CompactTx`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a [`WalletTx`] if this transaction belongs to any of the given
/// [`ExtendedFullViewingKey`]s.
fn scan_tx(tx: CompactTx, extfvks: &[ExtendedFullViewingKey]) -> Option<WalletTx> {
    let num_spends = tx.spends.len();
    let num_outputs = tx.outputs.len();

    // Check for incoming notes
    let shielded_outputs: Vec<WalletShieldedOutput> = {
        let ivks: Vec<_> = extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();
        tx.outputs
            .into_iter()
            .enumerate()
            .filter_map(|(index, output)| scan_output((index, output), &ivks))
            .collect()
    };

    if shielded_outputs.is_empty() {
        None
    } else {
        let mut txid = TxId([0u8; 32]);
        txid.0.copy_from_slice(&tx.hash);
        Some(WalletTx {
            txid,
            num_spends,
            num_outputs,
            shielded_outputs,
        })
    }
}

/// Scans a [`CompactBlock`] for transactions belonging to a set of
/// [`ExtendedFullViewingKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ExtendedFullViewingKey`]s.
pub fn scan_block(block: CompactBlock, extfvks: &[ExtendedFullViewingKey]) -> Vec<WalletTx> {
    block
        .vtx
        .into_iter()
        .filter_map(|tx| scan_tx(tx, extfvks))
        .collect()
}

/// Scans a serialized [`CompactBlock`] for transactions belonging to a set of
/// [`ExtendedFullViewingKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ExtendedFullViewingKey`]s.
///
/// This is a helper function that parses the [`CompactBlock`] and then calls
/// [`scan_block`].
pub fn scan_block_from_bytes(block: &[u8], extfvks: &[ExtendedFullViewingKey]) -> Vec<WalletTx> {
    let block: CompactBlock =
        parse_from_bytes(block).expect("Cannot convert into a `CompactBlock`");

    scan_block(block, extfvks)
}
