// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message testing and test utilities live here.

use chain::keysinterface::{KeysInterface, Recipient};
use super::{BlindedRoute, Destination, OnionMessenger, SendError};
use util::enforcing_trait_impls::EnforcingSigner;
use util::test_utils;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use core::mem;
use sync::Arc;

struct MessengerNode {
	keys_manager: Arc<test_utils::TestKeysInterface>,
	messenger: OnionMessenger<EnforcingSigner, Arc<test_utils::TestKeysInterface>, Arc<test_utils::TestLogger>>,
	logger: Arc<test_utils::TestLogger>,
}

impl MessengerNode {
	fn get_node_pk(&self) -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret(Recipient::Node).unwrap())
	}
}

fn create_nodes(num_messengers: u8) -> Vec<MessengerNode> {
	let mut res = Vec::new();
	for i in 0..num_messengers {
		let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
		let seed = [i as u8; 32];
		let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
		res.push(MessengerNode {
			keys_manager: keys_manager.clone(),
			messenger: OnionMessenger::new(keys_manager, logger.clone()),
			logger,
		});
	}
	res
}

fn pass_along_path(path: Vec<&MessengerNode>, expected_path_id: Option<[u8; 32]>) {
	let mut prev_node = path[0];
	for (idx, node) in path.iter().enumerate().skip(1) {
		let events = prev_node.messenger.get_and_clear_pending_msgs();
		assert_eq!(events.len(), 1);
		let onion_msg =  {
			let msgs = events.get(&node.get_node_pk()).unwrap();
			assert_eq!(msgs.len(), 1);
			msgs[0].clone()
		};
		node.messenger.handle_onion_message(&prev_node.get_node_pk(), &onion_msg);
		if idx == path.len() - 1 {
			node.logger.assert_log_contains(
				"lightning::onion_message::messenger".to_string(),
				format!("Received an onion message with path_id: {:02x?}", expected_path_id).to_string(), 1);
			break
		}
		prev_node = node;
	}
}

#[test]
fn one_hop() {
	let mut nodes = create_nodes(2);
	let (node1, node2) = (nodes.remove(0), nodes.remove(0));

	node1.messenger.send_onion_message(vec![], Destination::Node(node2.get_node_pk())).unwrap();
	pass_along_path(vec![&node1, &node2], None);
}

#[test]
fn two_unblinded_hops() {
	let mut nodes = create_nodes(3);
	let (node1, node2, node3) = (nodes.remove(0), nodes.remove(0), nodes.remove(0));

	node1.messenger.send_onion_message(vec![node2.get_node_pk()], Destination::Node(node3.get_node_pk())).unwrap();
	pass_along_path(vec![&node1, &node2, &node3], None);
}

#[test]
fn two_unblinded_two_blinded() {
	let mut nodes = create_nodes(5);
	let (node1, node2, node3, node4, node5) = (nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0));

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new(vec![node4.get_node_pk(), node5.get_node_pk()], &node5.keys_manager, &secp_ctx).unwrap();

	node1.messenger.send_onion_message(vec![node2.get_node_pk(), node3.get_node_pk()], Destination::BlindedRoute(blinded_route)).unwrap();
	pass_along_path(vec![&node1, &node2, &node3, &node4, &node5], None);
}

#[test]
fn three_blinded_hops() {
	let mut nodes = create_nodes(4);
	let (node1, node2, node3, node4) = (nodes.remove(0), nodes.remove(0), nodes.remove(0), nodes.remove(0));

	let secp_ctx = Secp256k1::new();
	let blinded_route = BlindedRoute::new(vec![node2.get_node_pk(), node3.get_node_pk(), node4.get_node_pk()], &node4.keys_manager, &secp_ctx).unwrap();

	node1.messenger.send_onion_message(vec![], Destination::BlindedRoute(blinded_route)).unwrap();
	pass_along_path(vec![&node1, &node2, &node3, &node4], None);
}

#[test]
fn too_big_packet_error() {
	// Make sure we error as expected if a packet is too big to send.
	let nodes = create_nodes(1);

	let hop_secret = SecretKey::from_slice(&hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap()[..]).unwrap();
	let secp_ctx = Secp256k1::new();
	let hop_node_id = PublicKey::from_secret_key(&secp_ctx, &hop_secret);

	let hops = vec![hop_node_id.clone(); 400];
	let err = nodes[0].messenger.send_onion_message(hops, Destination::Node(hop_node_id)).unwrap_err();
	assert_eq!(err, SendError::TooBigPacket);
}

#[test]
fn invalid_blinded_route_error() {
	// Make sure we error as expected if a provided blinded route has 0 hops.
	let mut nodes = create_nodes(3);
	let (node1, node2, node3) = (nodes.remove(0), nodes.remove(0), nodes.remove(0));

	let secp_ctx = Secp256k1::new();
	let mut blinded_route = BlindedRoute::new(vec![node2.get_node_pk(), node3.get_node_pk()], &node3.keys_manager, &secp_ctx).unwrap();
	let mut empty_hops = Vec::new();
	mem::swap(&mut empty_hops, &mut blinded_route.blinded_hops);

	let err = node1.messenger.send_onion_message(vec![], Destination::BlindedRoute(blinded_route)).unwrap_err();
	assert_eq!(err, SendError::MissingBlindedHops);
}
