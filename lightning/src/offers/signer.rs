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
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::io;
use crate::ln::inbound_payment::{EncryptedNonce, ExpandedKey, Nonce};

use crate::prelude::*;

/// Message metadata which possibly is derived from [`MetadataMaterial`] such that it can be
/// verified.
pub(super) enum Metadata {
	/// Metadata not set.
	Empty,

	/// Metadata set to predetermined bytes.
	Bytes(Vec<u8>),

	/// Metadata to be derived from message contents and given material.
	Derived(MetadataMaterial),

	/// Metadata and signing pubkey to be derived from message contents and given material.
	DerivedSigningPubkey(MetadataMaterial),
}

impl Metadata {
	pub fn material(&self) -> Option<&MetadataMaterial> {
		match self {
			Metadata::Empty => None,
			Metadata::Bytes(_) => None,
			Metadata::Derived(material) => Some(material),
			Metadata::DerivedSigningPubkey(material) => Some(material),
		}
	}

	pub fn material_mut(&mut self) -> Option<&mut MetadataMaterial> {
		match self {
			Metadata::Empty => None,
			Metadata::Bytes(_) => None,
			Metadata::Derived(material) => Some(material),
			Metadata::DerivedSigningPubkey(material) => Some(material),
		}
	}

	pub fn into_parts(self) -> (Option<Vec<u8>>, Option<PublicKey>) {
		match self {
			Metadata::Empty => (None, None),
			Metadata::Bytes(metadata) => (Some(metadata), None),
			Metadata::Derived(metadata_material) => (Some(metadata_material.into_metadata()), None),
			Metadata::DerivedSigningPubkey(metadata_material) => {
				let (metadata, pubkey) = metadata_material.into_parts();
				(Some(metadata), Some(pubkey))
			},
		}
	}
}

/// Material used to create metadata for a message. Once initialized, write the applicable data from
/// the message into it and call [`Metadata::into_parts`] to retrieve the metadata and derived
/// signing pubkey, if any.
#[derive(Clone)]
pub(super) struct MetadataMaterial {
	nonce: EncryptedNonce,
	hmac: HmacEngine<Sha256>,
}

impl MetadataMaterial {
	pub fn new(nonce: Nonce, expanded_key: &ExpandedKey) -> Self {
		Self {
			nonce: expanded_key.encrypt_nonce_for_offer(nonce),
			hmac: expanded_key.hmac_for_offer(nonce),
		}
	}

	fn into_metadata(self) -> Vec<u8> {
		let mut bytes = self.nonce.as_slice().to_vec();
		bytes.extend_from_slice(&Hmac::from_engine(self.hmac).into_inner());
		bytes
	}

	fn into_parts(self) -> (Vec<u8>, PublicKey) {
		let secp_ctx = Secp256k1::new();
		let hmac = Hmac::from_engine(self.hmac);
		let pubkey = SecretKey::from_slice(hmac.as_inner()).unwrap().public_key(&secp_ctx);
		(self.nonce.as_slice().to_vec(), pubkey)
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
