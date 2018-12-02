//! Tools for scanning a compact representation of the Zcash block chain.

use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use protobuf::parse_from_bytes;
use sapling_crypto::jubjub::{edwards, fs::Fs};
use zcash_primitives::{
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::try_sapling_compact_note_decryption,
    sapling::Node,
    transaction::TxId,
    zip32::ExtendedFullViewingKey,
    JUBJUB,
};

use crate::proto::compact_formats::{CompactBlock, CompactOutput};
use crate::wallet::{EncCiphertextFrag, WalletShieldedOutput, WalletTx};

/// Scans a [`CompactOutput`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a [`WalletShieldedOutput`] and corresponding [`IncrementalWitness`] if this
/// output belongs to any of the given [`ExtendedFullViewingKey`]s.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are incremented
/// with this output's commitment.
fn scan_output(
    (index, output): (usize, CompactOutput),
    ivks: &[Fs],
    tree: &mut CommitmentTree<Node>,
    existing_witnesses: &mut [&mut IncrementalWitness<Node>],
    new_witnesses: &mut [IncrementalWitness<Node>],
) -> Option<(WalletShieldedOutput, IncrementalWitness<Node>)> {
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
        let value = match try_sapling_compact_note_decryption(ivk, &epk, &cmu, &ct) {
            Some((note, _)) => note.value,
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

/// Scans a [`CompactBlock`] with a set of [`ExtendedFullViewingKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ExtendedFullViewingKey`]s, and the corresponding new [`IncrementalWitness`]es.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
/// incremented appropriately.
pub fn scan_block(
    block: CompactBlock,
    extfvks: &[ExtendedFullViewingKey],
    tree: &mut CommitmentTree<Node>,
    existing_witnesses: &mut [&mut IncrementalWitness<Node>],
) -> Vec<(WalletTx, Vec<IncrementalWitness<Node>>)> {
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

/// Scans a serialized [`CompactBlock`] for transactions belonging to a set of
/// [`ExtendedFullViewingKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ExtendedFullViewingKey`]s, and the corresponding new [`IncrementalWitness`]es.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
/// incremented appropriately.
///
/// This is a helper function that parses the [`CompactBlock`] and then calls
/// [`scan_block`].
pub fn scan_block_from_bytes(
    block: &[u8],
    extfvks: &[ExtendedFullViewingKey],
    tree: &mut CommitmentTree<Node>,
    witnesses: &mut [&mut IncrementalWitness<Node>],
) -> Vec<(WalletTx, Vec<IncrementalWitness<Node>>)> {
    let block: CompactBlock =
        parse_from_bytes(block).expect("Cannot convert into a `CompactBlock`");

    scan_block(block, extfvks, tree, witnesses)
}
