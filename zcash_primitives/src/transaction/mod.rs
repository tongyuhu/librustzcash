use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::Deref;

use redjubjub::Signature;
use serialize::Vector;

pub mod builder;
pub mod components;
mod sighash;

#[cfg(test)]
mod tests;

pub use self::sighash::{signature_hash, signature_hash_data, SIGHASH_ALL};

use self::components::{Amount, JSDescription, OutputDescription, SpendDescription, TxIn, TxOut};

const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;
const OVERWINTER_TX_VERSION: u32 = 3;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;
const SAPLING_TX_VERSION: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxId(pub [u8; 32]);

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &b in self.0.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// A Zcash transaction.
#[derive(Debug)]
pub struct Transaction {
    txid: TxId,
    data: TransactionData,
}

impl Deref for Transaction {
    type Target = TransactionData;

    fn deref(&self) -> &TransactionData {
        &self.data
    }
}

pub struct TransactionData {
    pub overwintered: bool,
    pub version: u32,
    pub version_group_id: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance: Amount,
    pub shielded_spends: Vec<SpendDescription>,
    pub shielded_outputs: Vec<OutputDescription>,
    pub joinsplits: Vec<JSDescription>,
    pub joinsplit_pubkey: Option<[u8; 32]>,
    pub joinsplit_sig: Option<[u8; 64]>,
    pub binding_sig: Option<Signature>,
}

impl std::fmt::Debug for TransactionData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TransactionData(
                overwintered = {:?},
                version = {:?},
                version_group_id = {:?},
                vin = {:?},
                vout = {:?},
                lock_time = {:?},
                expiry_height = {:?},
                value_balance = {:?},
                shielded_spends = {:?},
                shielded_outputs = {:?},
                joinsplits = {:?},
                joinsplit_pubkey = {:?},
                binding_sig = {:?})",
            self.overwintered,
            self.version,
            self.version_group_id,
            self.vin,
            self.vout,
            self.lock_time,
            self.expiry_height,
            self.value_balance,
            self.shielded_spends,
            self.shielded_outputs,
            self.joinsplits,
            self.joinsplit_pubkey,
            self.binding_sig
        )
    }
}

impl TransactionData {
    pub fn new() -> Self {
        TransactionData {
            overwintered: true,
            version: SAPLING_TX_VERSION,
            version_group_id: SAPLING_VERSION_GROUP_ID,
            vin: vec![],
            vout: vec![],
            lock_time: 0,
            expiry_height: 0,
            value_balance: Amount(0),
            shielded_spends: vec![],
            shielded_outputs: vec![],
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        }
    }

    fn header(&self) -> u32 {
        let mut header = self.version;
        if self.overwintered {
            header |= 1 << 31;
        }
        header
    }

    pub fn freeze(self) -> io::Result<Transaction> {
        Transaction::from_data(self)
    }
}

impl Transaction {
    fn from_data(data: TransactionData) -> io::Result<Self> {
        let mut tx = Transaction {
            txid: TxId([0; 32]),
            data,
        };
        let mut raw = vec![];
        tx.write(&mut raw)?;
        tx.txid
            .0
            .copy_from_slice(&Sha256::digest(&Sha256::digest(&raw)));
        Ok(tx)
    }

    pub fn txid(&self) -> TxId {
        self.txid
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let header = {
            let mut tmp = [0; 4];
            reader.read_exact(&mut tmp)?;
            u32::from_le_bytes(tmp)
        };
        let overwintered = (header >> 31) == 1;
        let version = header & 0x7FFFFFFF;

        let version_group_id = match overwintered {
            true => {
                let mut tmp = [0; 4];
                reader.read_exact(&mut tmp)?;
                u32::from_le_bytes(tmp)
            }
            false => 0,
        };

        let is_overwinter_v3 = overwintered
            && version_group_id == OVERWINTER_VERSION_GROUP_ID
            && version == OVERWINTER_TX_VERSION;
        let is_sapling_v4 = overwintered
            && version_group_id == SAPLING_VERSION_GROUP_ID
            && version == SAPLING_TX_VERSION;
        if overwintered && !(is_overwinter_v3 || is_sapling_v4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        let vin = Vector::read(&mut reader, TxIn::read)?;
        let vout = Vector::read(&mut reader, TxOut::read)?;
        let lock_time = {
            let mut tmp = [0; 4];
            reader.read_exact(&mut tmp)?;
            u32::from_le_bytes(tmp)
        };
        let expiry_height = match is_overwinter_v3 || is_sapling_v4 {
            true => {
                let mut tmp = [0; 4];
                reader.read_exact(&mut tmp)?;
                u32::from_le_bytes(tmp)
            }
            false => 0,
        };

        let (value_balance, shielded_spends, shielded_outputs) = if is_sapling_v4 {
            let vb = Amount::read_i64(&mut reader, true)?;
            let ss = Vector::read(&mut reader, SpendDescription::read)?;
            let so = Vector::read(&mut reader, OutputDescription::read)?;
            (vb, ss, so)
        } else {
            (Amount(0), vec![], vec![])
        };

        let (joinsplits, joinsplit_pubkey, joinsplit_sig) = if version >= 2 {
            let jss = Vector::read(&mut reader, |r| {
                JSDescription::read(r, overwintered && version >= SAPLING_TX_VERSION)
            })?;
            let (pubkey, sig) = if !jss.is_empty() {
                let mut joinsplit_pubkey = [0; 32];
                let mut joinsplit_sig = [0; 64];
                reader.read_exact(&mut joinsplit_pubkey)?;
                reader.read_exact(&mut joinsplit_sig)?;
                (Some(joinsplit_pubkey), Some(joinsplit_sig))
            } else {
                (None, None)
            };
            (jss, pubkey, sig)
        } else {
            (vec![], None, None)
        };

        let binding_sig =
            match is_sapling_v4 && !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
                true => Some(Signature::read(&mut reader)?),
                false => None,
            };

        Transaction::from_data(TransactionData {
            overwintered,
            version,
            version_group_id,
            vin,
            vout,
            lock_time,
            expiry_height,
            value_balance,
            shielded_spends,
            shielded_outputs,
            joinsplits,
            joinsplit_pubkey,
            joinsplit_sig,
            binding_sig,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.header().to_le_bytes())?;
        if self.overwintered {
            writer.write_all(&self.version_group_id.to_le_bytes())?;
        }

        let is_overwinter_v3 = self.overwintered
            && self.version_group_id == OVERWINTER_VERSION_GROUP_ID
            && self.version == OVERWINTER_TX_VERSION;
        let is_sapling_v4 = self.overwintered
            && self.version_group_id == SAPLING_VERSION_GROUP_ID
            && self.version == SAPLING_TX_VERSION;
        if self.overwintered && !(is_overwinter_v3 || is_sapling_v4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown transaction format",
            ));
        }

        Vector::write(&mut writer, &self.vin, |w, e| e.write(w))?;
        Vector::write(&mut writer, &self.vout, |w, e| e.write(w))?;
        writer.write_all(&self.lock_time.to_le_bytes())?;
        if is_overwinter_v3 || is_sapling_v4 {
            writer.write_all(&self.expiry_height.to_le_bytes())?;
        }

        if is_sapling_v4 {
            writer.write_all(&self.value_balance.0.to_le_bytes())?;
            Vector::write(&mut writer, &self.shielded_spends, |w, e| e.write(w))?;
            Vector::write(&mut writer, &self.shielded_outputs, |w, e| e.write(w))?;
        }

        if self.version >= 2 {
            Vector::write(&mut writer, &self.joinsplits, |w, e| e.write(w))?;
            if !self.joinsplits.is_empty() {
                match self.joinsplit_pubkey {
                    Some(pubkey) => writer.write_all(&pubkey)?,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Missing JoinSplit pubkey",
                        ));
                    }
                }
                match self.joinsplit_sig {
                    Some(sig) => writer.write_all(&sig)?,
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Missing JoinSplit signature",
                        ));
                    }
                }
            }
        }

        if self.version < 2 || self.joinsplits.is_empty() {
            if self.joinsplit_pubkey.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JoinSplit pubkey should not be present",
                ));
            }
            if self.joinsplit_sig.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JoinSplit signature should not be present",
                ));
            }
        }

        if is_sapling_v4 && !(self.shielded_spends.is_empty() && self.shielded_outputs.is_empty()) {
            match self.binding_sig {
                Some(sig) => sig.write(&mut writer)?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Missing binding signature",
                    ));
                }
            }
        } else if self.binding_sig.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Binding signature should not be present",
            ));
        }

        Ok(())
    }
}
