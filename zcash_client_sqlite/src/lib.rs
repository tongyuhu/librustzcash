//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_backend` contains a set of APIs that collectively implement an
//! SQLite-based light client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock

use ff::{PrimeField, PrimeFieldRepr};
use protobuf::parse_from_bytes;
use rusqlite::{types::ToSql, Connection, NO_PARAMS};
use std::cmp;
use std::error;
use std::fmt;
use std::path::Path;
use zcash_client_backend::{
    constants::testnet::{HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, HRP_SAPLING_PAYMENT_ADDRESS},
    encoding::{
        decode_extended_full_viewing_key, encode_extended_full_viewing_key, encode_payment_address,
    },
    proto::compact_formats::CompactBlock,
    welding_rig::scan_block,
};
use zcash_primitives::{
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    transaction::{components::Amount, TxId},
    zip32::ExtendedFullViewingKey,
    JUBJUB,
};

const ANCHOR_OFFSET: u32 = 10;
const SAPLING_ACTIVATION_HEIGHT: i32 = 280_000;

#[derive(Debug)]
pub enum ErrorKind {
    IncorrectHRPExtFVK,
    InvalidHeight(i32, i32),
    InvalidNewWitnessAnchor(usize, TxId, i32, Node),
    InvalidWitnessAnchor(i64, i32),
    ScanRequired,
    TableNotEmpty,
    Bech32(bech32::Error),
    Database(rusqlite::Error),
    IO(std::io::Error),
    Protobuf(protobuf::ProtobufError),
}

#[derive(Debug)]
pub struct Error(ErrorKind);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ErrorKind::IncorrectHRPExtFVK => write!(f, "Incorrect HRP for extfvk"),
            ErrorKind::InvalidHeight(expected, actual) => write!(
                f,
                "Expected height of next CompactBlock to be {}, but was {}",
                expected, actual
            ),
            ErrorKind::InvalidNewWitnessAnchor(output, txid, last_height, anchor) => write!(
                f,
                "New witness for output {} in tx {} has incorrect anchor after scanning block {}: {:?}",
                output, txid, last_height, anchor,
            ),
            ErrorKind::InvalidWitnessAnchor(id_note, last_height) => write!(
                f,
                "Witness for note {} has incorrect anchor after scanning block {}",
                id_note, last_height
            ),
            ErrorKind::ScanRequired => write!(f, "Must scan blocks first"),
            ErrorKind::TableNotEmpty => write!(f, "Table is not empty"),
            ErrorKind::Bech32(e) => write!(f, "{}", e),
            ErrorKind::Database(e) => write!(f, "{}", e),
            ErrorKind::IO(e) => write!(f, "{}", e),
            ErrorKind::Protobuf(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Error(ErrorKind::Bech32(e))
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error(ErrorKind::Database(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(ErrorKind::IO(e))
    }
}

impl From<protobuf::ProtobufError> for Error {
    fn from(e: protobuf::ProtobufError) -> Self {
        Error(ErrorKind::Protobuf(e))
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &addr)
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
fn get_target_and_anchor_heights(data: &Connection) -> Result<(u32, u32), Error> {
    data.query_row_and_then(
        "SELECT MIN(height), MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match (row.get_checked::<_, u32>(0), row.get_checked::<_, u32>(1)) {
            // If there are no blocks, the query returns NULL.
            (Err(rusqlite::Error::InvalidColumnType(_, _)), _)
            | (_, Err(rusqlite::Error::InvalidColumnType(_, _))) => {
                Err(Error(ErrorKind::ScanRequired))
            }
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
            (Ok(min_height), Ok(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height =
                    cmp::max(target_height.saturating_sub(ANCHOR_OFFSET), min_height);

                Ok((target_height, anchor_height))
            }
        },
    )
}

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::init_cache_database;
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_cache = data_file.path();
/// init_cache_database(&db_cache).unwrap();
/// ```
pub fn init_cache_database<P: AsRef<Path>>(db_cache: P) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    cache.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

/// Sets up the internal structure of the data database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::init_data_database;
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = data_file.path();
/// init_data_database(&db_data).unwrap();
/// ```
pub fn init_data_database<P: AsRef<Path>>(db_data: P) -> Result<(), Error> {
    let data = Connection::open(db_data)?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            account INTEGER PRIMARY KEY,
            extfvk TEXT NOT NULL,
            address TEXT NOT NULL
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            time INTEGER NOT NULL,
            sapling_tree BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            id_tx INTEGER PRIMARY KEY,
            txid BLOB NOT NULL UNIQUE,
            created TEXT,
            block INTEGER,
            tx_index INTEGER,
            expiry_height INTEGER,
            raw BLOB,
            FOREIGN KEY (block) REFERENCES blocks(height)
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS received_notes (
            id_note INTEGER PRIMARY KEY,
            tx INTEGER NOT NULL,
            output_index INTEGER NOT NULL,
            account INTEGER NOT NULL,
            diversifier BLOB NOT NULL,
            value INTEGER NOT NULL,
            rcm BLOB NOT NULL,
            nf BLOB NOT NULL UNIQUE,
            is_change BOOLEAN NOT NULL,
            memo BLOB,
            spent INTEGER,
            FOREIGN KEY (tx) REFERENCES transactions(id_tx),
            FOREIGN KEY (account) REFERENCES accounts(account),
            FOREIGN KEY (spent) REFERENCES transactions(id_tx),
            CONSTRAINT tx_output UNIQUE (tx, output_index)
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS sapling_witnesses (
            id_witness INTEGER PRIMARY KEY,
            note INTEGER NOT NULL,
            block INTEGER NOT NULL,
            witness BLOB NOT NULL,
            FOREIGN KEY (note) REFERENCES received_notes(id_note),
            FOREIGN KEY (block) REFERENCES blocks(height),
            CONSTRAINT witness_height UNIQUE (note, block)
        )",
        NO_PARAMS,
    )?;
    data.execute(
        "CREATE TABLE IF NOT EXISTS sent_notes (
            id_note INTEGER PRIMARY KEY,
            tx INTEGER NOT NULL,
            output_index INTEGER NOT NULL,
            from_account INTEGER NOT NULL,
            address TEXT NOT NULL,
            value INTEGER NOT NULL,
            memo BLOB,
            FOREIGN KEY (tx) REFERENCES transactions(id_tx),
            FOREIGN KEY (from_account) REFERENCES accounts(account),
            CONSTRAINT tx_output UNIQUE (tx, output_index)
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

/// Initialises the data database with the given [`ExtendedFullViewingKey`]s.
///
/// The [`ExtendedFullViewingKey`]s are stored internally and used by other APIs such as
/// [`get_address`], [`scan_cached_blocks`], and [`send_to_address`]. `extfvks` **MUST**
/// be arranged in account-order; that is, the [`ExtendedFullViewingKey`] for ZIP 32
/// account `i` **MUST** be at `extfvks[i]`.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{init_accounts_table, init_data_database};
/// use zcash_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db_data = data_file.path();
/// init_data_database(&db_data).unwrap();
///
/// let extsk = ExtendedSpendingKey::master(&[]);
/// let extfvks = [ExtendedFullViewingKey::from(&extsk)];
/// init_accounts_table(&db_data, &extfvks).unwrap();
/// ```
pub fn init_accounts_table<P: AsRef<Path>>(
    db_data: P,
    extfvks: &[ExtendedFullViewingKey],
) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    let mut empty_check = data.prepare("SELECT * FROM accounts LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(Error(ErrorKind::TableNotEmpty));
    }

    // Insert accounts atomically
    data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
    for (account, extfvk) in extfvks.iter().enumerate() {
        let address = address_from_extfvk(extfvk);
        let extfvk =
            encode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, extfvk);
        data.execute(
            "INSERT INTO accounts (account, extfvk, address)
            VALUES (?, ?, ?)",
            &[
                (account as u32).to_sql()?,
                extfvk.to_sql()?,
                address.to_sql()?,
            ],
        )?;
    }
    data.execute("COMMIT", NO_PARAMS)?;

    Ok(())
}

/// Initialises the data database with the given block.
///
/// This enables a newly-created database to be immediately-usable, without needing to
/// synchronise historic blocks.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::init_blocks_table;
///
/// // The block height.
/// let height = 500_000;
/// // The nTime field from the block header.
/// let time = 12_3456_7890;
/// // The serialized Sapling commitment tree as of this block.
/// // Pre-compute and hard-code, or obtain from a service.
/// let sapling_tree = &[];
///
/// init_blocks_table("/path/to/data.db", height, time, sapling_tree);
/// ```
pub fn init_blocks_table<P: AsRef<Path>>(
    db_data: P,
    height: i32,
    time: u32,
    sapling_tree: &[u8],
) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    let mut empty_check = data.prepare("SELECT * FROM blocks LIMIT 1")?;
    if empty_check.exists(NO_PARAMS)? {
        return Err(Error(ErrorKind::TableNotEmpty));
    }

    data.execute(
        "INSERT INTO blocks (height, time, sapling_tree)
        VALUES (?, ?, ?)",
        &[height.to_sql()?, time.to_sql()?, sapling_tree.to_sql()?],
    )?;

    Ok(())
}

/// Returns the address for the account.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::get_address;
///
/// let addr = get_address("/path/to/data.db", 0);
/// ```
pub fn get_address<P: AsRef<Path>>(db_data: P, account: u32) -> Result<String, Error> {
    let data = Connection::open(db_data)?;

    let addr = data.query_row(
        "SELECT address FROM accounts
        WHERE account = ?",
        &[account],
        |row| row.get(0),
    )?;

    Ok(addr)
}

/// Returns the balance for the account, including all unspent notes that we know about.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::get_balance;
///
/// let addr = get_balance("/path/to/data.db", 0);
/// ```
pub fn get_balance<P: AsRef<Path>>(db_data: P, account: u32) -> Result<Amount, Error> {
    let data = Connection::open(db_data)?;

    let balance = data.query_row(
        "SELECT SUM(value) FROM received_notes
        WHERE account = ? AND spent IS NULL",
        &[account],
        |row| row.get_checked(0).unwrap_or(0),
    )?;

    Ok(Amount(balance))
}

/// Returns the verified balance for the account, which ignores notes that have been
/// received too recently and are not yet deemed spendable.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::get_verified_balance;
///
/// let addr = get_verified_balance("/path/to/data.db", 0);
/// ```
pub fn get_verified_balance<P: AsRef<Path>>(db_data: P, account: u32) -> Result<Amount, Error> {
    let data = Connection::open(db_data)?;

    let (_, anchor_height) = get_target_and_anchor_heights(&data)?;

    let balance = data.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        &[account, anchor_height],
        |row| row.get_checked(0).unwrap_or(0),
    )?;

    Ok(Amount(balance))
}

struct CompactBlockRow {
    height: i32,
    data: Vec<u8>,
}

#[derive(Clone)]
struct WitnessRow {
    id_note: i64,
    witness: IncrementalWitness<Node>,
}

/// Scans new blocks added to the cache for any transactions received by the tracked
/// accounts.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ErrorKind::InvalidHeight`].
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::scan_cached_blocks;
///
/// scan_cached_blocks("/path/to/cache.db", "/path/to/data.db");
/// ```
pub fn scan_cached_blocks<P: AsRef<Path>, Q: AsRef<Path>>(
    db_cache: P,
    db_data: Q,
) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use sapling activation height to select all cached CompactBlocks.
    let mut last_height =
        data.query_row(
            "SELECT MAX(height) FROM blocks",
            NO_PARAMS,
            |row| match row.get_checked(0) {
                Ok(h) => h,
                Err(_) => SAPLING_ACTIVATION_HEIGHT - 1,
            },
        )?;

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache
        .prepare("SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC")?;
    let rows = stmt_blocks.query_map(&[last_height], |row| CompactBlockRow {
        height: row.get(0),
        data: row.get(1),
    })?;

    // Fetch the ExtendedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts =
        data.prepare("SELECT extfvk FROM accounts ORDER BY account ASC")?;
    let extfvks = stmt_fetch_accounts.query_map(NO_PARAMS, |row| {
        let extfvk: String = row.get(0);
        decode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, &extfvk)
    })?;
    // Raise SQL errors from the query, IO errors from parsing, and incorrect HRP errors.
    let extfvks: Vec<_> = extfvks
        .collect::<Result<Result<Option<_>, _>, _>>()??
        .ok_or(Error(ErrorKind::IncorrectHRPExtFVK))?;

    // Get the most recent CommitmentTree
    let mut stmt_fetch_tree = data.prepare("SELECT sapling_tree FROM blocks WHERE height = ?")?;
    let mut tree = match stmt_fetch_tree.query_row(&[last_height], |row| match row.get_checked(0) {
        Ok(data) => {
            let data: Vec<_> = data;
            CommitmentTree::read(&data[..])
        }
        Err(_) => Ok(CommitmentTree::new()),
    }) {
        Ok(tree) => tree,
        Err(_) => Ok(CommitmentTree::new()),
    }?;

    // Get most recent incremental witnesses for the notes we are tracking
    let mut stmt_fetch_witnesses =
        data.prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let witnesses = stmt_fetch_witnesses.query_map(&[last_height], |row| {
        let data: Vec<_> = row.get(1);
        IncrementalWitness::read(&data[..]).map(|witness| WitnessRow {
            id_note: row.get(0),
            witness,
        })
    })?;
    let mut witnesses: Vec<_> = witnesses.collect::<Result<Result<_, _>, _>>()??;

    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers =
        data.prepare("SELECT id_note, nf, account FROM received_notes WHERE spent IS NULL")?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let nf: Vec<_> = row.get(1);
        let account: i64 = row.get(2);
        (nf, account as usize)
    })?;
    let mut nullifiers: Vec<_> = nullifiers.collect::<Result<_, _>>()?;

    // Prepare per-block SQL statements
    let mut stmt_insert_block = data.prepare(
        "INSERT INTO blocks (height, time, sapling_tree)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_update_tx = data.prepare(
        "UPDATE transactions
        SET block = ?, tx_index = ? WHERE txid = ?",
    )?;
    let mut stmt_insert_tx = data.prepare(
        "INSERT INTO transactions (txid, block, tx_index)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_select_tx = data.prepare("SELECT id_tx FROM transactions WHERE txid = ?")?;
    let mut stmt_mark_spent_note =
        data.prepare("UPDATE received_notes SET spent = ? WHERE nf = ?")?;
    let mut stmt_insert_note = data.prepare(
        "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut stmt_insert_witness = data.prepare(
        "INSERT INTO sapling_witnesses (note, block, witness)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_prune_witnesses = data.prepare("DELETE FROM sapling_witnesses WHERE block < ?")?;
    let mut stmt_update_expired = data.prepare(
        "UPDATE received_notes SET spent = NULL WHERE EXISTS (
            SELECT id_tx FROM transactions
            WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
        )",
    )?;

    for row in rows {
        let row = row?;

        // Start an SQL transaction for this block.
        data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

        // Scanned blocks MUST be height-sequential.
        if row.height != (last_height + 1) {
            return Err(Error(ErrorKind::InvalidHeight(last_height + 1, row.height)));
        }
        last_height = row.height;

        let block: CompactBlock = parse_from_bytes(&row.data)?;
        let block_time = block.time;

        let txs = {
            let nf_refs: Vec<_> = nullifiers.iter().map(|(nf, acc)| (&nf[..], *acc)).collect();
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.witness).collect();
            scan_block(
                block,
                &extfvks[..],
                &nf_refs,
                &mut tree,
                &mut witness_refs[..],
            )
        };

        // Enforce that all roots match. This is slow, so only include in debug builds.
        #[cfg(debug_assertions)]
        {
            let cur_root = tree.root();
            for row in &witnesses {
                if row.witness.root() != cur_root {
                    return Err(Error(ErrorKind::InvalidWitnessAnchor(
                        row.id_note,
                        last_height,
                    )));
                }
            }
            for (tx, new_witnesses) in &txs {
                for (i, witness) in new_witnesses.iter().enumerate() {
                    if witness.root() != cur_root {
                        return Err(Error(ErrorKind::InvalidNewWitnessAnchor(
                            tx.shielded_outputs[i].index,
                            tx.txid,
                            last_height,
                            witness.root(),
                        )));
                    }
                }
            }
        }

        // Insert the block into the database.
        let mut encoded_tree = Vec::new();
        tree.write(&mut encoded_tree)
            .expect("Should be able to write to a Vec");
        stmt_insert_block.execute(&[
            row.height.to_sql()?,
            block_time.to_sql()?,
            encoded_tree.to_sql()?,
        ])?;

        for (tx, new_witnesses) in txs {
            // First try update an existing transaction in the database.
            let txid = tx.txid.0.to_vec();
            let tx_row = if stmt_update_tx.execute(&[
                row.height.to_sql()?,
                (tx.index as i64).to_sql()?,
                txid.to_sql()?,
            ])? == 0
            {
                // It isn't there, so insert our transaction into the database.
                stmt_insert_tx.execute(&[
                    txid.to_sql()?,
                    row.height.to_sql()?,
                    (tx.index as i64).to_sql()?,
                ])?;
                data.last_insert_rowid()
            } else {
                // It was there, so grab its row number.
                stmt_select_tx.query_row(&[txid], |row| row.get(0))?
            };

            // Mark notes as spent and remove them from the scanning cache
            for spend in &tx.shielded_spends {
                stmt_mark_spent_note.execute(&[tx_row.to_sql()?, spend.nf.to_sql()?])?;
            }
            nullifiers = nullifiers
                .into_iter()
                .filter(|(nf, _acc)| {
                    tx.shielded_spends
                        .iter()
                        .find(|spend| &spend.nf == nf)
                        .is_none()
                })
                .collect();

            for (output, witness) in tx
                .shielded_outputs
                .into_iter()
                .zip(new_witnesses.into_iter())
            {
                let mut rcm = [0; 32];
                output.note.r.into_repr().write_le(&mut rcm[..])?;
                let nf = output.note.nf(
                    &extfvks[output.account].fvk.vk,
                    witness.position() as u64,
                    &JUBJUB,
                );

                // Insert received note into the database.
                // Assumptions:
                // - A transaction will not contain more than 2^63 shielded outputs.
                // - A note value will never exceed 2^63 zatoshis.
                stmt_insert_note.execute(&[
                    tx_row.to_sql()?,
                    (output.index as i64).to_sql()?,
                    (output.account as i64).to_sql()?,
                    output.to.diversifier.0.to_sql()?,
                    (output.note.value as i64).to_sql()?,
                    rcm.to_sql()?,
                    nf.to_sql()?,
                    output.is_change.to_sql()?,
                ])?;
                let note_row = data.last_insert_rowid();

                // Save witness for note.
                witnesses.push(WitnessRow {
                    id_note: note_row,
                    witness,
                });

                // Cache nullifier for note (to detect subsequent spends in this scan).
                nullifiers.push((nf, output.account));
            }
        }

        // Insert current witnesses into the database.
        let mut encoded = Vec::new();
        for witness_row in witnesses.iter() {
            encoded.clear();
            witness_row
                .witness
                .write(&mut encoded)
                .expect("Should be able to write to a Vec");
            stmt_insert_witness.execute(&[
                witness_row.id_note.to_sql()?,
                last_height.to_sql()?,
                encoded.to_sql()?,
            ])?;
        }

        // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
        stmt_prune_witnesses.execute(&[last_height - 100])?;

        // Update now-expired transactions that didn't get mined.
        stmt_update_expired.execute(&[last_height])?;

        // Commit the SQL transaction, writing this block's data atomically.
        data.execute("COMMIT", NO_PARAMS)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ff::{PrimeField, PrimeFieldRepr};
    use pairing::bls12_381::Bls12;
    use protobuf::Message;
    use rand::{thread_rng, Rand, Rng};
    use rusqlite::{types::ToSql, Connection};
    use sapling_crypto::{
        jubjub::fs::Fs,
        primitives::{Note, PaymentAddress},
    };
    use std::path::Path;
    use tempfile::NamedTempFile;
    use zcash_client_backend::{
        constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
        encoding::decode_payment_address,
        proto::compact_formats::{CompactBlock, CompactOutput, CompactSpend, CompactTx},
    };
    use zcash_primitives::{
        note_encryption::{Memo, SaplingNoteEncryption},
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        JUBJUB,
    };

    use super::{
        get_address, get_balance, get_verified_balance, init_accounts_table, init_blocks_table,
        init_cache_database, init_data_database, scan_cached_blocks, ErrorKind,
        SAPLING_ACTIVATION_HEIGHT,
    };

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// the given address. Returns the CompactBlock and the nullifier for the new note.
    fn fake_compact_block(
        height: i32,
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> (CompactBlock, Vec<u8>) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = thread_rng();
        let note = Note {
            g_d: to.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
            pk_d: to.pk_d.clone(),
            value: value.0 as u64,
            r: Fs::rand(&mut rng),
        };
        let encryptor =
            SaplingNoteEncryption::new(extfvk.fvk.ovk, note.clone(), to.clone(), Memo::default());
        let mut cmu = vec![];
        note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
        let mut epk = vec![];
        encryptor.epk().write(&mut epk).unwrap();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::new();
        cout.set_cmu(cmu);
        cout.set_epk(epk);
        cout.set_ciphertext(enc_ciphertext[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.outputs.push(cout);
        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);
        cb.vtx.push(ctx);
        (cb, note.nf(&extfvk.fvk.vk, 0, &JUBJUB))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    fn fake_compact_block_spending(
        height: i32,
        (nf, in_value): (Vec<u8>, Amount),
        extfvk: ExtendedFullViewingKey,
        to: PaymentAddress<Bls12>,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = thread_rng();

        // Create a fake CompactBlock containing the note
        let mut cspend = CompactSpend::new();
        cspend.set_nf(nf);
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);

        // Create a fake Note for the payment
        ctx.outputs.push({
            let note = Note {
                g_d: to.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: to.pk_d.clone(),
                value: value.0 as u64,
                r: Fs::rand(&mut rng),
            };
            let encryptor =
                SaplingNoteEncryption::new(extfvk.fvk.ovk, note.clone(), to, Memo::default());
            let mut cmu = vec![];
            note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        // Create a fake Note for the change
        ctx.outputs.push({
            let change_addr = extfvk.default_address().unwrap().1;
            let note = Note {
                g_d: change_addr.diversifier.g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: change_addr.pk_d.clone(),
                value: (in_value.0 - value.0) as u64,
                r: Fs::rand(&mut rng),
            };
            let encryptor = SaplingNoteEncryption::new(
                extfvk.fvk.ovk,
                note.clone(),
                change_addr,
                Memo::default(),
            );
            let mut cmu = vec![];
            note.cm(&JUBJUB).into_repr().write_le(&mut cmu).unwrap();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);
        cb.vtx.push(ctx);
        cb
    }

    /// Insert a fake CompactBlock into the cache DB.
    fn insert_into_cache<P: AsRef<Path>>(db_cache: P, cb: &CompactBlock) {
        let cb_bytes = cb.write_to_bytes().unwrap();
        let cache = Connection::open(&db_cache).unwrap();
        cache
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(&[
                (cb.height as i32).to_sql().unwrap(),
                cb_bytes.to_sql().unwrap(),
            ])
            .unwrap();
    }

    #[test]
    fn init_accounts_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // We can call the function as many times as we want with no data
        init_accounts_table(&db_data, &[]).unwrap();
        init_accounts_table(&db_data, &[]).unwrap();

        // First call with data should initialise the accounts table
        let extfvks = [ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(
            &[],
        ))];
        init_accounts_table(&db_data, &extfvks).unwrap();

        // Subsequent calls should return an error
        init_accounts_table(&db_data, &[]).unwrap_err();
        init_accounts_table(&db_data, &extfvks).unwrap_err();
    }

    #[test]
    fn init_blocks_table_only_works_once() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // First call with data should initialise the blocks table
        init_blocks_table(&db_data, 1, 1, &[]).unwrap();

        // Subsequent calls should return an error
        init_blocks_table(&db_data, 2, 2, &[]).unwrap_err();
    }

    #[test]
    fn init_accounts_table_stores_correct_address() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &extfvks).unwrap();

        // The account's address should be in the data DB
        let addr = get_address(&db_data, 0).unwrap();
        let pa = decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &addr).unwrap();
        assert_eq!(pa.unwrap(), extsk.default_address().unwrap().1);
    }

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &extfvks).unwrap();

        // The account should be empty
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(0));

        // The account should have no verified balance, as we haven't scanned any blocks
        let e = get_verified_balance(db_data, 0).unwrap_err();
        match e.kind() {
            ErrorKind::ScanRequired => (),
            _ => panic!("Unexpected error: {:?}", e),
        }

        // An invalid account has zero balance
        assert!(get_address(db_data, 1).is_err());
        assert_eq!(get_balance(db_data, 1).unwrap(), Amount(0));
    }

    #[test]
    fn scan_cached_blocks_requires_sequential_blocks() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount(50000);
        let (cb1, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT, extfvk.clone(), value);
        insert_into_cache(db_cache, &cb1);
        scan_cached_blocks(db_cache, db_data).unwrap();
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // We cannot scan a block of height SAPLING_ACTIVATION_HEIGHT + 2 next
        let (cb3, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT + 2, extfvk.clone(), value);
        insert_into_cache(db_cache, &cb3);
        match scan_cached_blocks(db_cache, db_data) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "Expected height of next CompactBlock to be {}, but was {}",
                    SAPLING_ACTIVATION_HEIGHT + 1,
                    SAPLING_ACTIVATION_HEIGHT + 2
                )
            ),
        }

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan both
        let (cb2, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT + 1, extfvk.clone(), value);
        insert_into_cache(db_cache, &cb2);
        scan_cached_blocks(db_cache, db_data).unwrap();
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(150_000));
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(0));

        // Create a fake CompactBlock sending value to the address
        let value = Amount(5);
        let (cb, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT, extfvk.clone(), value);
        insert_into_cache(db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount(7);
        let (cb2, _) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT + 1, extfvk, value2);
        insert_into_cache(db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect both received notes
        // TODO: impl Sum for Amount
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(value.0 + value2.0));
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = cache_file.path();
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(0));

        // Create a fake CompactBlock sending value to the address
        let value = Amount(5);
        let (cb, nf) = fake_compact_block(SAPLING_ACTIVATION_HEIGHT, extfvk.clone(), value);
        insert_into_cache(db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(db_data, 0).unwrap(), value);

        // Create a second fake CompactBlock spending value from the address
        let extsk2 = ExtendedSpendingKey::master(&[0]);
        let to2 = extsk2.default_address().unwrap().1;
        let value2 = Amount(2);
        insert_into_cache(
            db_cache,
            &fake_compact_block_spending(
                SAPLING_ACTIVATION_HEIGHT + 1,
                (nf, value),
                extfvk,
                to2,
                value2,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(db_cache, db_data).unwrap();

        // Account balance should equal the change
        // TODO: impl Sum for Amount
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount(value.0 - value2.0));
    }
}
