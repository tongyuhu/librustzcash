use pairing::bls12_381::Bls12;
use zcash_primitives::{
    consensus,
    note_encryption::Memo,
    primitives::Note,
    prover::TxProver,
    transaction::{builder::Builder, components::Amount, Transaction, TxId},
    zip32::ExtendedSpendingKey,
};

use crate::proto::compact_formats::CompactBlock;

type Error = ();

type AccountKey<'a> = (u32, &'a ExtendedSpendingKey);
// TODO
type RecipientAddress = String;

type NoteRef = (TxId, usize);

/// A byte-oriented backend for storing
trait StorageBackend {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    fn get_note(&self, txid: &str, n: usize) -> Result<Vec<u8>, Error>;
}

pub trait PersistenceBackend {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    fn get_note(&self, note: NoteRef) -> Result<Note<Bls12>, Error>;
}

struct FfiPersistence {
    backend: Box<dyn StorageBackend>,
}
  
impl PersistenceBackend for FfiPersistence {
    fn get_address(&self, extsk: ExtendedSpendingKey) -> Result<PaymentAddress, Error> {
        self.backend.get_address(account).and_then(|addr| addr.parse())
    }

    fn get_address(&self, account: u32) -> Result<PaymentAddress, Error> {
        self.backend.get_address(account).and_then(|addr| addr.parse())
    }

    fn get_note(&self, note: NoteRef) -> Result<Note<Bls12>, Error> {
        self.backend.get_note(note.0.to_string(), note.1).and_then(|bytes| Note::from(bytes))
    }
}

/// Callbacks.
pub trait ClientCallbacks {}

trait BlockConsumer {
    fn block_received(&mut self, block: CompactBlock) -> Result<(), Error>;
}

trait Wallet {
    fn get_address(&self, account: u32) -> Result<String, Error>;

    fn get_note(&self, note: NoteRef) -> Result<Note<Bls12>, Error>;

    fn get_unspent_notes(&self) -> Result<Vec<NoteRef>, Error>;

    fn lock_notes(&mut self, notes: &[NoteRef]) -> Result<(), Error>;

    fn get_balance(&self, account: u32) -> Result<Amount, Error> {
        self.get_unspent_notes().map(|notes| {
            notes
                .into_iter()
                .map(|note| self.get_note(note))
                .fold(Amount::zero(), |total, note| {
                    total + Amount::from_u64(note.value).expect("unspent notes are valid")
                })
        })
    }

    fn get_verified_balance(&self, account: u32) -> Result<Amount, Error>;

    fn select_notes(&mut self, value: Amount) -> Result<Vec<Note<Bls12>>, Error> {
        let mut unspent = self.get_unspent_notes()?;

        // Selection policy: select the oldest notes until the required value is reached.

        Err(())
    }

    fn create_to_address(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        prover: impl TxProver,
        account_key: AccountKey,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<Transaction, Error> {
        let notes = self.select_notes(value)?;

        // Create the transaction
        let mut builder = Builder::new(height);
        for selected in notes {
            builder.add_sapling_spend(
                extsk.clone(),
                selected.diversifier,
                selected.note,
                selected.witness,
            )?;
        }
        match to {
            RecipientAddress::Shielded(to) => {
                builder.add_sapling_output(ovk, to.clone(), value, memo.clone())
            }
            RecipientAddress::Transparent(to) => builder.add_transparent_output(&to, value),
        }?;
        let (tx, tx_metadata) = builder.build(consensus_branch_id, prover)?;

        Ok(tx)
    }
}

pub struct WalletBackend {
    storage: Box<dyn PersistenceBackend>,
    callbacks: Box<dyn ClientCallbacks>,
}

pub struct AndroidWalletBackend(WalletBackend);

impl Wallet for AndroidWalletBackend {
    fn get_address(&self, account: u32) -> Result<String, Error> {
        self.0.get_address(...)
    }

    fn select_notes(..) {
    }
    
}

impl WalletBackend {
    pub fn init(storage: Box<dyn PersistenceBackend>, callbacks: Box<dyn ClientCallbacks>) -> Self {
        WalletBackend { storage, callbacks }
    }
}

impl Wallet for WalletBackend {
    fn get_address(&self, account: u32) -> Result<String, Error> {
        self.storage.get_address(self.storage.get_key(account))
    }

    fn get_unspent_notes(&self) -> Result<Vec<Note<Bls12>>, Error> {
        Err(())
    }

    fn lock_notes(&mut self, notes: &[Note<Bls12>]) -> Result<(), Error> {
        Err(())
    }
}
