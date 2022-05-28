// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! LDK sends, receives, and forwards onion messages via the [`OnionMessenger`]. See its docs for
//! more information.

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;

use chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager, Recipient, Sign};
use ln::msgs;
use ln::onion_utils;
use super::blinded_route::{BlindedRoute, ForwardTlvs, ReceiveTlvs};
use super::packet::{BIG_PACKET_HOP_DATA_LEN, ForwardControlTlvs, Packet, Payload, ReceiveControlTlvs, SMALL_PACKET_HOP_DATA_LEN};
use super::utils;
use util::chacha20::ChaCha20;
use util::logger::Logger;
use util::ser::Writeable;

use core::ops::Deref;
use sync::{Arc, Mutex};
use prelude::*;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers].
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
pub struct OnionMessenger<Signer: Sign, K: Deref, L: Deref>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	keys_manager: K,
	logger: L,
	pending_messages: Mutex<HashMap<PublicKey, Vec<msgs::OnionMessage>>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
	// custom_handler: CustomHandler, // handles custom onion messages
}

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded route.
	BlindedRoute(BlindedRoute),
}

impl Destination {
	pub(super) fn num_hops(&self) -> usize {
		match self {
			Destination::Node(_) => 1,
			Destination::BlindedRoute(BlindedRoute { blinded_hops, .. }) => blinded_hops.len(),
		}
	}
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
	      L::Target: Logger,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(keys_manager: K, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		OnionMessenger {
			keys_manager,
			pending_messages: Mutex::new(HashMap::new()),
			secp_ctx,
			logger,
		}
	}

	/// Send an empty onion message to `destination`, routing it through `intermediate_nodes`.
	pub fn send_onion_message(&self, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(), secp256k1::Error> {
		let blinding_secret_bytes = self.keys_manager.get_secure_random_bytes();
		let blinding_secret = SecretKey::from_slice(&blinding_secret_bytes[..]).expect("RNG is busted");
		let (introduction_node_id, blinding_point) = if intermediate_nodes.len() != 0 {
			(intermediate_nodes[0].clone(), PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret))
		} else {
			match destination {
				Destination::Node(pk) => (pk.clone(), PublicKey::from_secret_key(&self.secp_ctx, &blinding_secret)),
				Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, .. }) =>
					(introduction_node_id.clone(), blinding_point.clone()),
			}
		};
		let (control_tlvs_keys, onion_packet_keys) = construct_sending_keys(
			&self.secp_ctx, &intermediate_nodes, &destination, &blinding_secret)?;
		let payloads = build_payloads(intermediate_nodes, destination, control_tlvs_keys);

		let prng_seed = self.keys_manager.get_secure_random_bytes();
		let onion_packet = construct_onion_message_packet(payloads, onion_packet_keys, prng_seed);

		let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
		let pending_msgs = pending_per_peer_msgs.entry(introduction_node_id).or_insert(Vec::new());
		pending_msgs.push(
			msgs::OnionMessage {
				blinding_point,
				len: onion_packet.len(),
				onion_routing_packet: onion_packet,
			}
		);
		Ok(())
	}

	/// Handle an incoming onion message. Currently, if a message was destined for us we will log, but
	/// soon we'll delegate the onion message to a handler that can generate invoices or send
	/// payments.
	pub fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {
		let node_secret = match self.keys_manager.get_node_secret(Recipient::Node) {
			Ok(secret) => secret,
			Err(e) => {
				log_trace!(self.logger, "Failed to retrieve node secret: {:?}", e);
				return
			}
		};
		let control_tlvs_ss = SharedSecret::new(&msg.blinding_point, &node_secret);
		let onion_decode_shared_secret = {
			let blinding_factor = {
				let mut hmac = HmacEngine::<Sha256>::new(b"blinded_node_id");
				hmac.input(control_tlvs_ss.as_ref());
				Hmac::from_engine(hmac).into_inner()
			};
			let mut blinded_priv = node_secret.clone();
			if let Err(e) = blinded_priv.mul_assign(&blinding_factor) {
				log_trace!(self.logger, "Failed to compute our blinded secret key: {}", e);
				return
			}
			SharedSecret::new(&msg.onion_routing_packet.public_key, &blinded_priv).secret_bytes()
		};
		match onion_utils::decode_next_hop(onion_decode_shared_secret,
			&msg.onion_routing_packet.hop_data[..], msg.onion_routing_packet.hmac, control_tlvs_ss)
		{
			Ok((Payload::Receive {
				control_tlvs: ReceiveControlTlvs::Unblinded(ReceiveTlvs { path_id })
			}, None)) => {
				log_info!(self.logger, "Received an onion message with path_id: {:02x?}", path_id);
			},
			Ok((Payload::Forward(ForwardControlTlvs::Unblinded(ForwardTlvs {
				next_node_id, next_blinding_override
			})), Some((next_hop_hmac, new_packet_bytes)))) => {
				// TODO: we need to check whether `next_node_id` is our node, in which case this is a dummy
				// blinded hop and this onion message is destined for us. In this situation, we should keep
				// unwrapping the onion layers to get to the final payload. Since we don't have the option
				// of creating blinded routes with dummy hops currently, we should be ok to not handle this
				// for now.
				let new_pubkey = match onion_utils::next_hop_packet_pubkey(&self.secp_ctx, msg.onion_routing_packet.public_key, &onion_decode_shared_secret) {
					Ok(pk) => pk,
					Err(e) => {
						log_trace!(self.logger, "Failed to compute next hop packet pubkey: {}", e);
						return
					}
				};
				let outgoing_packet = Packet {
					version: 0,
					public_key: new_pubkey,
					hop_data: new_packet_bytes,
					hmac: next_hop_hmac.clone(),
				};

				let mut pending_per_peer_msgs = self.pending_messages.lock().unwrap();
				let pending_msgs = pending_per_peer_msgs.entry(next_node_id).or_insert(Vec::new());
				pending_msgs.push(
					msgs::OnionMessage {
						blinding_point: match next_blinding_override {
							Some(blinding_point) => blinding_point,
							None => {
								let blinding_factor = {
									let mut sha = Sha256::engine();
									sha.input(&msg.blinding_point.serialize()[..]);
									sha.input(control_tlvs_ss.as_ref());
									Sha256::from_engine(sha).into_inner()
								};
								let mut next_blinding_point = msg.blinding_point.clone();
								if let Err(e) = next_blinding_point.mul_assign(&self.secp_ctx, &blinding_factor[..]) {
									log_trace!(self.logger, "Failed to compute next blinding point: {}", e);
									return
								}
								next_blinding_point
							},
						},
						len: outgoing_packet.len(),
						onion_routing_packet: outgoing_packet,
					},
				);
			},
			Err(e) => {
				log_trace!(self.logger, "Errored decoding onion message packet: {:?}", e);
			},
			_ => {
				log_trace!(self.logger, "Received bogus onion message packet, either the sender encoded a final hop as a forwarding hop or vice versa");
			},
		};
	}
}

// TODO: parameterize the below Simple* types with OnionMessenger and handle the messages it
// produces
/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
///
///[`SimpleArcChannelManager`]: crate::ln::channelmanager::SimpleArcChannelManager
///[`SimpleArcPeerManager`]: crate::ln::peer_handler::SimpleArcPeerManager
pub type SimpleArcOnionMessenger<L> = OnionMessenger<InMemorySigner, Arc<KeysManager>, Arc<L>>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
///
///[`SimpleRefChannelManager`]: crate::ln::channelmanager::SimpleRefChannelManager
///[`SimpleRefPeerManager`]: crate::ln::peer_handler::SimpleRefPeerManager
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<InMemorySigner, &'a KeysManager, &'b L>;

/// Construct keys for sending an onion message along the given `unblinded_path` to the given
/// `destination`.
///
/// Returns: `(control_tlvs_keys, onion_packet_keys)`
/// where the former are for encrypting the control TLVs of the onion message and the latter for
/// encrypting the onion packet.
fn construct_sending_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: &Destination, session_priv: &SecretKey
) -> Result<(Vec<[u8; 32]>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	let num_hops = unblinded_path.len() + destination.num_hops();
	let mut control_tlvs_keys = Vec::with_capacity(num_hops);
	let mut onion_packet_keys = Vec::with_capacity(num_hops);

	utils::construct_keys_callback(secp_ctx, unblinded_path, Some(destination), session_priv, |_, onion_packet_ss, _blinding_factor, ephemeral_pubkey, control_tlvs_ss| {
		control_tlvs_keys.push(control_tlvs_ss);

		let (rho, mu) = onion_utils::gen_rho_mu_from_shared_secret(onion_packet_ss.as_ref());
		onion_packet_keys.push(onion_utils::OnionKeys {
			#[cfg(test)]
			shared_secret: onion_packet_ss,
			#[cfg(test)]
			blinding_factor: _blinding_factor,
			ephemeral_pubkey,
			rho,
			mu,
		});
	})?;

	Ok((control_tlvs_keys, onion_packet_keys))
}

/// Build an onion message's payloads for encoding in the onion packet.
fn build_payloads(intermediate_nodes: Vec<PublicKey>, destination: Destination, mut encrypted_tlvs_keys: Vec<[u8; 32]>) -> Vec<(Payload, [u8; 32])> {
	let num_intermediate_nodes = intermediate_nodes.len();
	let num_payloads = num_intermediate_nodes + destination.num_hops();
	debug_assert_eq!(encrypted_tlvs_keys.len(), num_payloads);
	let mut payloads = Vec::with_capacity(num_payloads);
	let mut enc_tlv_keys = encrypted_tlvs_keys.drain(..);
	for pk in intermediate_nodes.into_iter().skip(1) {
		payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
						ForwardTlvs {
							next_node_id: pk,
							next_blinding_override: None,
						}
		)), enc_tlv_keys.next().unwrap()));
	}
	match destination {
		Destination::Node(pk) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
								ForwardTlvs {
									next_node_id: pk,
									next_blinding_override: None,
								}
				)), enc_tlv_keys.next().unwrap()));
			}
			payloads.push((Payload::Receive { control_tlvs: ReceiveControlTlvs::Unblinded(
						ReceiveTlvs {
							path_id: None,
						}
			)}, enc_tlv_keys.next().unwrap()));
		},
		Destination::BlindedRoute(BlindedRoute { introduction_node_id, blinding_point, blinded_hops }) => {
			if num_intermediate_nodes != 0 {
				payloads.push((Payload::Forward(ForwardControlTlvs::Unblinded(
								ForwardTlvs {
									next_node_id: introduction_node_id,
									next_blinding_override: Some(blinding_point),
								}
				)), enc_tlv_keys.next().unwrap()));
			}
			let num_hops = blinded_hops.len();
			for (idx, hop) in blinded_hops.into_iter().enumerate() {
				if idx != num_hops - 1 {
					payloads.push((Payload::Forward(ForwardControlTlvs::Blinded(hop.encrypted_payload)),
					enc_tlv_keys.next().unwrap()));
				} else {
					payloads.push((Payload::Receive {
						control_tlvs: ReceiveControlTlvs::Blinded(hop.encrypted_payload),
					}, enc_tlv_keys.next().unwrap()));
				}
			}
		}
	}
	payloads
}

fn construct_onion_message_packet(payloads: Vec<(Payload, [u8; 32])>, onion_keys: Vec<onion_utils::OnionKeys>, prng_seed: [u8; 32]) -> Packet {
	let payloads_serialized_len = payloads.iter().map(|p| p.serialized_length() + 32 /* HMAC */).sum();
	let hop_data_len = if payloads_serialized_len <= SMALL_PACKET_HOP_DATA_LEN {
		SMALL_PACKET_HOP_DATA_LEN
	} else if payloads_serialized_len <= BIG_PACKET_HOP_DATA_LEN {
		BIG_PACKET_HOP_DATA_LEN
	} else { payloads_serialized_len };

	let mut packet_data = vec![0; hop_data_len];

	let mut chacha = ChaCha20::new(&prng_seed, &[0; 8]);
	chacha.process_in_place(&mut packet_data);

	onion_utils::construct_onion_packet_with_init_noise::<_, _>(
		payloads, onion_keys, packet_data, None)
}
