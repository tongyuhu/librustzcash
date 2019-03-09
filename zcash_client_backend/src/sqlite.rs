use rusqlite::{types::ToSql, Connection, NO_PARAMS};
use std::cmp;
use std::error;
use std::fmt;
use std::path::Path;
use zcash_primitives::transaction::components::Amount;
use zip32::ExtendedFullViewingKey;

use crate::{
    constants::{HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY_TEST, HRP_SAPLING_PAYMENT_ADDRESS_TEST},
    encoding::{encode_extended_full_viewing_key, encode_payment_address},
};

const ANCHOR_OFFSET: u32 = 10;

#[derive(Debug)]
pub enum ErrorKind {
    ScanRequired,
    TableNotEmpty,
    Database(rusqlite::Error),
}

#[derive(Debug)]
pub struct Error(ErrorKind);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ErrorKind::ScanRequired => write!(f, "Must scan blocks first"),
            ErrorKind::TableNotEmpty => write!(f, "Table is not empty"),
            ErrorKind::Database(e) => write!(f, "{}", e),
        }
    }
}

impl error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error(ErrorKind::Database(e))
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS_TEST, &addr)
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

/// Initialises the data database with the given accounts.
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
            encode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY_TEST, extfvk);
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

/// Initialises the data database with the given block. This enables a newly-created
/// database to be immediately-usable, without needing to synchronise historic blocks.
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

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_primitives::transaction::components::Amount;
    use zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};

    use super::{
        get_address, get_balance, get_verified_balance, init_accounts_table, init_blocks_table,
        init_data_database, ErrorKind,
    };
    use crate::{constants::HRP_SAPLING_PAYMENT_ADDRESS_TEST, encoding::decode_payment_address};

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
        let pa = decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS_TEST, &addr).unwrap();
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
}
