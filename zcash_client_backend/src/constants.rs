//! Zcash global and per-network constants.

pub mod mainnet;
pub mod testnet;

pub const SPROUT_CONSENSUS_BRANCH_ID: u32 = 0;
pub const OVERWINTER_CONSENSUS_BRANCH_ID: u32 = 0x5ba8_1b19;
pub const SAPLING_CONSENSUS_BRANCH_ID: u32 = 0x76b8_09bb;
