//! Memo-building interface.

use pairing::bls12_381::Bls12;
use std::str::FromStr;

use super::{Memo, Payload, StructuredMemo, TextMemo};
use crate::primitives::PaymentAddress;

pub struct Builder {
    return_address: Option<PaymentAddress<Bls12>>,
    text: Option<String>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            return_address: None,
            text: None,
        }
    }

    pub fn return_address(&mut self, return_address: PaymentAddress<Bls12>) -> &mut Self {
        self.return_address = Some(return_address);
        self
    }

    pub fn text(&mut self, text: String) -> &mut Self {
        self.text = Some(text);
        self
    }

    pub fn build(&self) -> Result<Memo, ()> {
        if let Some(pa) = self.return_address.as_ref() {
            let mut payloads = vec![Payload::ReturnAddress(pa.clone())];

            if let Some(s) = self.text.as_ref() {
                payloads.push(Payload::Text(TextMemo(s.clone())));
            }

            StructuredMemo::new(payloads).map(Memo::Structured)
        } else if let Some(s) = self.text.as_ref() {
            Memo::from_str(s)
        } else {
            Ok(Memo::Empty)
        }
    }
}
