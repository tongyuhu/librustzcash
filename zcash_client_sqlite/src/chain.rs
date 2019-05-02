//! Functions for enforcing chain validity and handling chain reorgs.
//!
//! # Examples
//!
//! ```
//! use zcash_client_sqlite::{
//!     chain::{rewind_to_height, validate_combined_chain},
//!     ErrorKind, scan_cached_blocks,
//! };
//!
//! let db_cache = "/path/to/cache.db";
//! let db_data = "/path/to/data.db";
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_combined_chain(&db_cache, &db_data) {
//!     match e.kind() {
//!         ErrorKind::InvalidChain(upper_bound, _) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = upper_bound - 10;
//!
//!             // b) Rewind scanned block information.
//!             rewind_to_height(&db_data, rewind_height);
//!
//!             // c) Delete cached blocks from rewind_height onwards.
//!             //
//!             // This does imply that assumed-valid blocks will be re-downloaded, but it
//!             // is also possible that in the intervening time, a chain reorg has
//!             // occurred that orphaned some of those blocks.
//!
//!             // d) If there is some separate thread or service downloading
//!             // CompactBlocks, tell it to go back and download from rewind_height
//!             // onwards.
//!         }
//!         _ => {
//!             // Handle other errors.
//!         }
//!     }
//! }
//!
//! // 3) Scan (any remaining) cached blocks.
//! //
//! // At this point, the cache and scanned data are locally consistent (though not
//! // necessarily consistent with the latest chain tip - this would be discovered the
//! // next time this codepath is executed after new blocks are received).
//! scan_cached_blocks(&db_cache, &db_data);
//! ```

use protobuf::parse_from_bytes;
use rusqlite::{Connection, NO_PARAMS};
use std::path::Path;
use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::{CompactBlockRow, Error, ErrorKind, SAPLING_ACTIVATION_HEIGHT};

#[derive(Debug)]
pub enum ChainInvalidCause {
    PrevHashMismatch,
}

/// Checks that the scanned blocks in the data database, when combined with the recent
/// `CompactBlock`s in the cache database, form a valid chain.
///
/// This function is built on the core assumption that the information provided in the
/// cache database is more likely to be accurate than the previously-scanned information.
/// This follows from the design (and trust) assumption that the `lightwalletd` server
/// provides accurate block information as of the time it was requested.
///
/// Returns:
/// - `Ok(())` if the combined chain is valid.
/// - `Err(ErrorKind::InvalidChain(upper_bound, cause))` if the combined chain is invalid.
///   `upper_bound` is the height of the highest invalid block (on the assumption that the
///   highest block in the cache database is correct).
/// - `Err(e)` if there was an error during validation unrelated to chain validity.
///
/// This function does not mutate either of the databases.
pub fn validate_combined_chain<P: AsRef<Path>, Q: AsRef<Path>>(
    db_cache: P,
    db_data: Q,
) -> Result<(), Error> {
    let cache = Connection::open(db_cache)?;
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height to select all cached CompactBlocks.
    let last_scanned_height = data.query_row(
        "SELECT MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match row.get_checked(0) {
            Ok(h) => h,
            Err(_) => SAPLING_ACTIVATION_HEIGHT - 1,
        },
    )?;

    // Fetch the CompactBlocks we need to validate
    let mut stmt_blocks = cache
        .prepare("SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height DESC")?;
    let mut rows = stmt_blocks.query_map(&[last_scanned_height], |row| CompactBlockRow {
        height: row.get(0),
        data: row.get(1),
    })?;

    // Take the highest cached block as accurate.
    let (mut last_height, mut last_prev_hash) = {
        let assumed_correct = match rows.next() {
            Some(row) => row?,
            None => {
                // No cached blocks, and we've already validated the blocks we've scanned,
                // so there's nothing to validate.
                // TODO: Maybe we still want to check if there are cached blocks that are
                // at heights we previously scanned? Check scanning flow again.
                return Ok(());
            }
        };
        let block: CompactBlock = parse_from_bytes(&assumed_correct.data)?;
        (block.height as i32, block.prev_hash())
    };

    for row in rows {
        let row = row?;

        // Scanned blocks MUST be height-sequential.
        if row.height != (last_height - 1) {
            return Err(Error(ErrorKind::InvalidHeight(last_height - 1, row.height)));
        }
        last_height = row.height;

        let block: CompactBlock = parse_from_bytes(&row.data)?;

        // Cached blocks MUST be hash-chained.
        if block.hash() != last_prev_hash {
            return Err(Error(ErrorKind::InvalidChain(
                last_height,
                ChainInvalidCause::PrevHashMismatch,
            )));
        }
        last_prev_hash = block.prev_hash();
    }

    // Cached blocks MUST hash-chain to the last scanned block.
    let last_scanned_hash = data.query_row(
        "SELECT hash FROM blocks WHERE height = ?",
        &[last_scanned_height],
        |row| row.get_checked::<_, Vec<_>>(0),
    )??;
    if &last_scanned_hash[..] != &last_prev_hash.0[..] {
        return Err(Error(ErrorKind::InvalidChain(
            last_scanned_height,
            ChainInvalidCause::PrevHashMismatch,
        )));
    }

    // All good!
    Ok(())
}

/// Rewinds the data database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
pub fn rewind_to_height<P: AsRef<Path>>(db_data: P, height: i32) -> Result<(), Error> {
    let data = Connection::open(db_data)?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height.
    let last_scanned_height = data.query_row(
        "SELECT MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match row.get_checked(0) {
            Ok(h) => h,
            Err(_) => SAPLING_ACTIVATION_HEIGHT - 1,
        },
    )?;

    if height >= last_scanned_height {
        // Nothing to do.
        return Ok(());
    }

    // Start an SQL transaction for rewinding.
    data.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

    // Decrement witnesses.
    data.execute("DELETE FROM sapling_witnesses WHERE block > ?", &[height])?;

    // Un-mine transactions.
    data.execute(
        "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block > ?",
        &[height],
    )?;

    // Now that they aren't depended on, delete scanned blocks.
    data.execute("DELETE FROM blocks WHERE height > ?", &[height])?;

    // Commit the SQL transaction, rewinding atomically.
    data.execute("COMMIT", NO_PARAMS)?;

    Ok(())
}
