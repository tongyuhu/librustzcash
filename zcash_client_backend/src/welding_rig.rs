use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use protobuf::parse_from_bytes;
use sapling_crypto::jubjub::{edwards, fs::Fs, PrimeOrder};
use zcash_primitives::{
    merkle_tree::{CommitmentTree, IncrementalWitness, Node},
    transaction::TxId,
    JUBJUB,
};
use zip32::ExtendedFullViewingKey;

use data::EncCiphertextFrag;
use note_encryption::try_sapling_compact_note_decryption;
use proto::compact_formats::{CompactBlock, CompactOutput};
use wallet::{WalletShieldedOutput, WalletTx};

fn trial_decrypt(
    cmu: &Fr,
    epk: &edwards::Point<Bls12, PrimeOrder>,
    enc_ct: &[u8],
    ivk: &Fs,
) -> Option<u64> {
    match try_sapling_compact_note_decryption(ivk, epk, cmu, enc_ct) {
        Ok((note, _)) => Some(note.value),
        Err(_) => None,
    }
}

/// Returns a WalletShieldedOutput and corresponding IncrementalWitness if this
/// output belongs to any of the given ExtendedFullViewingKeys. The given
/// CommitmentTree and existing IncrementalWitnesses are incremented with this
/// output's commitment.
fn scan_output(
    (index, output): (usize, CompactOutput),
    ivks: &[Fs],
    tree: &mut CommitmentTree,
    existing_witnesses: &mut [&mut IncrementalWitness],
    new_witnesses: &mut [IncrementalWitness],
) -> Option<(WalletShieldedOutput, IncrementalWitness)> {
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

    // Increment tree and witnesses
    let node = Node::new(cmu.into_repr());
    for witness in existing_witnesses {
        witness.append(node).unwrap();
    }
    for witness in new_witnesses {
        witness.append(node).unwrap();
    }
    tree.append(node).unwrap();

    for (account, ivk) in ivks.iter().enumerate() {
        let value = match trial_decrypt(&cmu, &epk, &ct, ivk) {
            Some(value) => value,
            None => continue,
        };

        // It's ours, so let's copy the ciphertext fragment and return
        let mut enc_ct = EncCiphertextFrag([0u8; 52]);
        enc_ct.0.copy_from_slice(&ct);

        return Some((
            WalletShieldedOutput {
                index,
                cmu,
                epk,
                enc_ct,
                account,
                value,
            },
            IncrementalWitness::from_tree(tree),
        ));
    }
    None
}

/// Returns a vector of transactions belonging to any of the given
/// ExtendedFullViewingKeys, and the corresponding new IncrementalWitnesses.
/// The given CommitmentTree and existing IncrementalWitnesses are
/// incremented appropriately.
pub fn scan_block(
    block: CompactBlock,
    extfvks: &[ExtendedFullViewingKey],
    tree: &mut CommitmentTree,
    existing_witnesses: &mut [&mut IncrementalWitness],
) -> Vec<(WalletTx, Vec<IncrementalWitness>)> {
    let mut wtxs = vec![];
    let ivks: Vec<_> = extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();

    for tx in block.vtx.into_iter() {
        let num_spends = tx.spends.len();
        let num_outputs = tx.outputs.len();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs = vec![];
        let mut new_witnesses = vec![];
        for to_scan in tx.outputs.into_iter().enumerate() {
            if let Some((output, new_witness)) =
                scan_output(to_scan, &ivks, tree, existing_witnesses, &mut new_witnesses)
            {
                shielded_outputs.push(output);
                new_witnesses.push(new_witness);
            }
        }

        if !shielded_outputs.is_empty() {
            let mut txid = TxId([0u8; 32]);
            txid.0.copy_from_slice(&tx.hash);
            wtxs.push((
                WalletTx {
                    txid,
                    num_spends,
                    num_outputs,
                    shielded_outputs,
                },
                new_witnesses,
            ));
        }
    }

    wtxs
}

/// Returns a vector of transactions belonging to any of the given
/// ExtendedFullViewingKeys, and the corresponding new IncrementalWitnesses.
/// The given CommitmentTree and existing IncrementalWitnesses are
/// incremented appropriately.
pub fn scan_block_from_bytes(
    block: &[u8],
    extfvks: &[ExtendedFullViewingKey],
    tree: &mut CommitmentTree,
    witnesses: &mut [&mut IncrementalWitness],
) -> Vec<(WalletTx, Vec<IncrementalWitness>)> {
    let block: CompactBlock =
        parse_from_bytes(block).expect("Cannot convert into a `CompactBlock`");

    scan_block(block, extfvks, tree, witnesses)
}
