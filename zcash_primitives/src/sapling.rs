//! Structs and constants specific to the Sapling shielded pool.

use ff::{BitIterator, PrimeField};
use pairing::bls12_381::{Bls12, Fr};
use rand::OsRng;
use std::io::{self, Read, Write};

use crate::merkle_tree::Hashable;
use crate::redjubjub::{PrivateKey, PublicKey, Signature};
use crate::{
    jubjub::{fs::Fs, FixedGenerators, JubjubBls12},
    pedersen_hash::{pedersen_hash, Personalization},
    primitives::Note,
};
use JUBJUB;

pub const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &Fr, rhs: &Fr) -> Fr {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().rev().zip(BitIterator::new(lhs.to_bytes())) {
            *a = b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().rev().zip(BitIterator::new(rhs.to_bytes())) {
            *a = b;
        }
        tmp
    };

    pedersen_hash::<Bls12, _>(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .map(|&x| x)
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().map(|&x| x).take(Fr::NUM_BITS as usize)),
        &JUBJUB,
    )
    .into_xy()
    .0
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    repr: Fr,
}

impl Node {
    pub fn new(repr: Fr) -> Self {
        Node { repr }
    }
}

impl Hashable for Node {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0; 32];
        reader.read_exact(&mut repr)?;
        let node = Fr::from_bytes(&repr);
        if node.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid node"));
        }
        Ok(Node::new(node.unwrap()))
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.repr.to_bytes())
    }

    fn combine(depth: usize, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(depth, &lhs.repr, &rhs.repr),
        }
    }

    fn blank() -> Self {
        Node {
            repr: Note::<Bls12>::uncommitted(),
        }
    }

    fn empty_root(depth: usize) -> Self {
        EMPTY_ROOTS[depth]
    }
}

impl From<Node> for Fr {
    fn from(node: Node) -> Self {
        node.repr
    }
}

lazy_static! {
    static ref EMPTY_ROOTS: Vec<Node> = {
        let mut v = vec![Node::blank()];
        for d in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            let next = Node::combine(d, &v[d], &v[d]);
            v.push(next);
        }
        v
    };
}

/// Create the spendAuthSig for a Sapling SpendDescription.
pub fn spend_sig(
    ask: PrivateKey<Bls12>,
    ar: Fs,
    sighash: &[u8; 32],
    params: &JubjubBls12,
) -> Signature {
    // Initialize secure RNG
    let mut rng = OsRng::new().expect("should be able to construct RNG");

    // We compute `rsk`...
    let rsk = ask.randomize(ar);

    // We compute `rk` from there (needed for key prefixing)
    let rk = PublicKey::from_private(&rsk, FixedGenerators::SpendingKeyGenerator, params);

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    rk.0.write(&mut data_to_be_signed[0..32])
        .expect("message buffer should be 32 bytes");
    (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(
        &data_to_be_signed,
        &mut rng,
        FixedGenerators::SpendingKeyGenerator,
        params,
    )
}
