// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Utilities for signing offer messages and verifying metadata.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use core::convert::TryInto;
use bitcoin::secp256k1::PublicKey;
use crate::io;
use crate::ln::inbound_payment::{ExpandedKey, Nonce};

use crate::prelude::*;

/// A pubkey derived from a base key and nonce. Used to crate metadata for a message such that it
/// can be verified using [`verify_metadata`].
pub(crate) struct DerivedPubkey {
	public_key: PublicKey,
	metadata_material: MetadataMaterial,
}

impl DerivedPubkey {
	pub(crate) fn new(expanded_key: &ExpandedKey, nonce: Nonce) -> Self {
		Self {
			public_key: expanded_key.signing_pubkey_for_offer(nonce),
			metadata_material: MetadataMaterial::new(nonce, expanded_key),
		}
	}

	pub(super) fn into_parts(self) -> (PublicKey, MetadataMaterial) {
		(self.public_key, self.metadata_material)
	}
}

/// Material used to create metadata for a message. Once initialized, write the applicable data from
/// the message into it and call [`MetadataMaterial::into_metadata`].
pub(super) struct MetadataMaterial {
	nonce: Nonce,
	hmac: HmacEngine<Sha256>,
}

impl MetadataMaterial {
	pub fn new(nonce: Nonce, expanded_key: &ExpandedKey) -> Self {
		Self {
			nonce,
			hmac: expanded_key.hmac_for_offer(nonce),
		}
	}

	pub fn into_metadata(self) -> Vec<u8> {
		let mut bytes = self.nonce.as_slice().to_vec();
		bytes.extend_from_slice(&Hmac::from_engine(self.hmac).into_inner());
		bytes
	}
}

impl io::Write for MetadataMaterial {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.hmac.write(buf)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.hmac.flush()
	}
}
