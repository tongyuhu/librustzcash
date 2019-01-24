use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use protobuf::parse_from_bytes;
use sapling_crypto::{
    jubjub::{edwards, fs::Fs, PrimeOrder},
    primitives::{Note, PaymentAddress},
};
use std::collections::HashSet;
use zcash_primitives::{
    merkle_tree::{CommitmentTree, IncrementalWitness, Node},
    transaction::TxId,
    JUBJUB,
};
use zip32::ExtendedFullViewingKey;

use note_encryption::try_sapling_compact_note_decryption;
use proto::compact_formats::{CompactBlock, CompactOutput};
use wallet::{WalletShieldedOutput, WalletShieldedSpend, WalletTx};

fn trial_decrypt(
    cmu: &Fr,
    epk: &edwards::Point<Bls12, PrimeOrder>,
    enc_ct: &[u8],
    ivk: &Fs,
) -> Option<(Note<Bls12>, PaymentAddress<Bls12>)> {
    match try_sapling_compact_note_decryption(ivk, epk, cmu, enc_ct) {
        Ok((note, to)) => Some((note, to)),
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
    spent_from_accounts: &HashSet<usize>,
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
        let (note, to) = match trial_decrypt(&cmu, &epk, &ct, ivk) {
            Some(ret) => ret,
            None => continue,
        };

        // A note is marked as "change" if the account that received it
        // also spent notes in the same transaction. This will catch,
        // for instance:
        // - Change created by spending fractions of notes.
        // - Notes created by consolidation transactions.
        // - Notes sent from one account to itself.
        let is_change = spent_from_accounts.contains(&account);

        return Some((
            WalletShieldedOutput {
                index,
                cmu,
                epk,
                account,
                note,
                to,
                is_change,
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
    nullifiers: &[(&[u8], usize)],
    tree: &mut CommitmentTree,
    existing_witnesses: &mut [&mut IncrementalWitness],
) -> Vec<(WalletTx, Vec<IncrementalWitness>)> {
    let mut wtxs = vec![];
    let ivks: Vec<_> = extfvks.iter().map(|extfvk| extfvk.fvk.vk.ivk()).collect();

    for tx in block.vtx.into_iter() {
        let num_spends = tx.spends.len();
        let num_outputs = tx.outputs.len();

        // Check for spent notes
        let shielded_spends: Vec<_> =
            tx.spends
                .into_iter()
                .enumerate()
                .filter_map(|(index, spend)| {
                    if let Some(account) = nullifiers.iter().find_map(|&(nf, acc)| {
                        if nf == &spend.nf[..] {
                            Some(acc)
                        } else {
                            None
                        }
                    }) {
                        Some(WalletShieldedSpend {
                            index,
                            nf: spend.nf,
                            account,
                        })
                    } else {
                        None
                    }
                })
                .collect();

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> =
            shielded_spends.iter().map(|spend| spend.account).collect();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs = vec![];
        let mut new_witnesses = vec![];
        for to_scan in tx.outputs.into_iter().enumerate() {
            if let Some((output, new_witness)) = scan_output(
                to_scan,
                &ivks,
                &spent_from_accounts,
                tree,
                existing_witnesses,
                &mut new_witnesses,
            ) {
                shielded_outputs.push(output);
                new_witnesses.push(new_witness);
            }
        }

        if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
            let mut txid = TxId([0u8; 32]);
            txid.0.copy_from_slice(&tx.hash);
            wtxs.push((
                WalletTx {
                    txid,
                    index: tx.index as usize,
                    num_spends,
                    num_outputs,
                    shielded_spends,
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
    nullifiers: &[(&[u8], usize)],
    tree: &mut CommitmentTree,
    witnesses: &mut [&mut IncrementalWitness],
) -> Vec<(WalletTx, Vec<IncrementalWitness>)> {
    let block: CompactBlock =
        parse_from_bytes(block).expect("Cannot convert into a `CompactBlock`");

    scan_block(block, extfvks, nullifiers, tree, witnesses)
}
