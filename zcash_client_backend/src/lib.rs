//! *A crate for implementing Zcash light clients.*
//!
//! `zcash_client_backend` contains Rust structs and traits for creating shielded Zcash
//! light clients.

pub mod constants;
pub mod encoding;
pub mod keys;
pub mod proto;
pub mod wallet;
pub mod welding_rig;
