// Imports that need to be added manually
use bitcoin::bech32::u5;
use bitcoin::blockdata::script::Script;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;

use lightning::sign::{Recipient, KeyMaterial, EntropySource, NodeSigner, SignerProvider};
use lightning::ln::msgs::{self, DecodeError, OnionMessageHandler};
use lightning::ln::script::ShutdownScript;
use lightning::util::enforcing_trait_impls::EnforcingSigner;
use lightning::util::logger::Logger;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::onion_message::{CustomOnionMessageContents, CustomOnionMessageHandler, Destination, MessageRouter, OffersMessage, OffersMessageHandler, OnionMessagePath, OnionMessenger};

use crate::utils::test_logger;

use std::io::{self, Cursor};
use std::sync::atomic::{AtomicU64, Ordering};

#[inline]
/// Actual fuzz test, method signature and name are fixed
pub fn do_test<L: Logger>(data: &[u8], logger: &L) {
	if let Ok(msg) = <msgs::OnionMessage as Readable>::read(&mut Cursor::new(data)) {
		let mut secret_bytes = [1; 32];
		secret_bytes[31] = 2;
		let secret = SecretKey::from_slice(&secret_bytes).unwrap();
		let keys_manager = KeyProvider {
			node_secret: secret,
			counter: AtomicU64::new(0),
		};
		let message_router = TestMessageRouter {};
		let offers_msg_handler = TestOffersMessageHandler {};
		let custom_msg_handler = TestCustomMessageHandler {};
		let onion_messenger = OnionMessenger::new(
			&keys_manager, &keys_manager, logger, &message_router, &offers_msg_handler,
			&custom_msg_handler
		);
		let mut pk = [2; 33]; pk[1] = 0xff;
		let peer_node_id_not_used = PublicKey::from_slice(&pk).unwrap();
		onion_messenger.handle_onion_message(&peer_node_id_not_used, &msg);
	}
}

/// Method that needs to be added manually, {name}_test
pub fn onion_message_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let logger = test_logger::TestLogger::new("".to_owned(), out);
	do_test(data, &logger);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn onion_message_run(data: *const u8, datalen: usize) {
	let logger = test_logger::TestLogger::new("".to_owned(), test_logger::DevNull {});
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, &logger);
}

struct TestMessageRouter {}

impl MessageRouter for TestMessageRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()> {
		Ok(OnionMessagePath {
			intermediate_nodes: vec![],
			destination,
		})
	}
}

struct TestOffersMessageHandler {}

impl OffersMessageHandler for TestOffersMessageHandler {
	fn handle_message(&self, _message: OffersMessage) -> Option<OffersMessage> {
		None
	}
}

struct TestCustomMessage {}

const CUSTOM_MESSAGE_TYPE: u64 = 4242;
const CUSTOM_MESSAGE_CONTENTS: [u8; 32] = [42; 32];

impl CustomOnionMessageContents for TestCustomMessage {
	fn tlv_type(&self) -> u64 {
		CUSTOM_MESSAGE_TYPE
	}
}

impl Writeable for TestCustomMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		Ok(CUSTOM_MESSAGE_CONTENTS.write(w)?)
	}
}

struct TestCustomMessageHandler {}

impl CustomOnionMessageHandler for TestCustomMessageHandler {
	type CustomMessage = TestCustomMessage;
	fn handle_custom_message(&self, _msg: Self::CustomMessage) -> Option<Self::CustomMessage> {
		Some(TestCustomMessage {})
	}
	fn read_custom_message<R: io::Read>(&self, _message_type: u64, buffer: &mut R) -> Result<Option<Self::CustomMessage>, msgs::DecodeError> {
		let mut buf = Vec::new();
		buffer.read_to_end(&mut buf)?;
		return Ok(Some(TestCustomMessage {}))
	}
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}
struct KeyProvider {
	node_secret: SecretKey,
	counter: AtomicU64,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			(ctr >> 8*7) as u8, (ctr >> 8*6) as u8, (ctr >> 8*5) as u8, (ctr >> 8*4) as u8, (ctr >> 8*3) as u8, (ctr >> 8*2) as u8, (ctr >> 8*1) as u8, 14, (ctr >> 8*0) as u8]
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(())
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(())
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial { unreachable!() }

	fn sign_invoice(&self, _hrp_bytes: &[u8], _invoice_data: &[u5], _recipient: Recipient) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(&self, _msg: lightning::ln::msgs::UnsignedGossipMessage) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		unreachable!()
	}
}

impl SignerProvider for KeyProvider {
	type Signer = EnforcingSigner;

	fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] { unreachable!() }

	fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::Signer {
		unreachable!()
	}

	fn read_chan_signer(&self, _data: &[u8]) -> Result<EnforcingSigner, DecodeError> { unreachable!() }

	fn get_destination_script(&self) -> Result<Script, ()> { unreachable!() }

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> { unreachable!() }
}

impl KeyProvider {
	fn get_node_secret(&self, recipient: Recipient) -> Result<SecretKey, ()> {
		match recipient {
			Recipient::Node => Ok(self.node_secret),
			Recipient::PhantomNode => Err(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{TestCustomMessage, TestCustomMessageHandler, TestMessageRouter, TestOffersMessageHandler};
	use lightning::blinded_path::BlindedPath;
	use lightning::sign::Recipient;
	use lightning::ln::features::InitFeatures;
	use lightning::ln::msgs::{self, OnionMessageHandler};
	use lightning::onion_message::{Destination, OnionMessenger, SendError};
	use lightning::onion_message::OnionMessagePath;
	use lightning::onion_message::OnionMessageContents;
	use lightning::util::enforcing_trait_impls::EnforcingSigner;
	use lightning::util::test_utils;
	use lightning::util::ser::Writeable;

	use bitcoin::network::constants::Network;
	use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};

	use std::sync::Arc;
	use super::KeyProvider;
	use std::sync::atomic::{AtomicU64, Ordering};

	use lightning::util::logger::{Logger, Record};
	use std::collections::HashMap;
	use std::sync::Mutex;

	struct TrackingLogger {
		/// (module, message) -> count
		pub lines: Mutex<HashMap<(String, String), usize>>,
	}
	impl Logger for TrackingLogger {
		fn log(&self, record: &Record) {
			*self.lines.lock().unwrap().entry((record.module_path.to_string(), format!("{}", record.args))).or_insert(0) += 1;
			println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
		}
	}

	struct MessengerNode {
		keys_manager: Arc<KeyProvider>,
		messenger: OnionMessenger<Arc<KeyProvider>, Arc<KeyProvider>, Arc<TrackingLogger>, Arc<TestMessageRouter>, Arc<TestOffersMessageHandler>, Arc<TestCustomMessageHandler>>,
		logger: Arc<TrackingLogger>,
	}

	impl MessengerNode {
		fn get_node_pk(&self) -> PublicKey {
			let secp_ctx = Secp256k1::new();
			PublicKey::from_secret_key(&secp_ctx, &self.keys_manager.get_node_secret(Recipient::Node).unwrap())
		}
	}
	fn create_nodes(num_messengers: u8) -> Vec<MessengerNode> {
		let mut nodes = Vec::new();
		for i in 0..num_messengers {
			let logger = Arc::new(TrackingLogger { lines: Mutex::new(HashMap::new()) });
			let seed = [i as u8; 32];
			let mut secret_bytes = [i as u8; 32];
			secret_bytes[31] = 2;
			let secret = SecretKey::from_slice(&secret_bytes).unwrap();
			let keys_manager = Arc::new(KeyProvider {
				node_secret: secret,
				counter: AtomicU64::new(0),
			});
			let message_router = Arc::new(TestMessageRouter {});
			let offers_msg_handler = Arc::new(TestOffersMessageHandler {});
			let custom_msg_handler = Arc::new(TestCustomMessageHandler {});
			let onion_messenger = OnionMessenger::new(
				keys_manager.clone(), keys_manager.clone(), logger.clone(), message_router, offers_msg_handler,
				custom_msg_handler
			);
			nodes.push(MessengerNode {
				keys_manager: keys_manager.clone(),
				messenger: onion_messenger,
				logger,
			});
		}
		for idx in 0..num_messengers - 1 {
			let i = idx as usize;
			let mut features = InitFeatures::empty();
			features.set_onion_messages_optional();
			let init_msg = msgs::Init { features, remote_network_address: None };
			nodes[i].messenger.peer_connected(&nodes[i + 1].get_node_pk(), &init_msg.clone(), true).unwrap();
			nodes[i + 1].messenger.peer_connected(&nodes[i].get_node_pk(), &init_msg.clone(), false).unwrap();
		}
		nodes
	}

	fn pass_along_path(path: &Vec<MessengerNode>, expected_path_id: Option<[u8; 32]>) {
		let mut prev_node = &path[0];
		let num_nodes = path.len();
		for (idx, node) in path.into_iter().skip(1).enumerate() {
			let events = prev_node.messenger.release_pending_msgs();
			let onion_msg =  {
				let msgs = events.get(&node.get_node_pk()).unwrap();
				assert_eq!(msgs.len(), 1);
				msgs[0].clone()
			};
			println!("VMW: encoded om: {}", hex::encode(&onion_msg.encode()));
			node.messenger.handle_onion_message(&prev_node.get_node_pk(), &onion_msg);
			if idx == num_nodes - 1 {
				// node.logger.assert_log_contains(
				//   "lightning::onion_message::messenger".to_string(),
				//   format!("Received an onion message with path_id: {:02x?}", expected_path_id).to_string(), 1);
			}
			prev_node = node;
		}
	}

	#[test]
	fn vmw_om_one_hop() {
		let nodes = create_nodes(2);
		let path = OnionMessagePath {
			intermediate_nodes: Vec::new(),
			destination: Destination::Node(nodes[1].get_node_pk()),
		};

		nodes[0].messenger.send_onion_message(path, OnionMessageContents::Custom(TestCustomMessage {}), None).unwrap();
		pass_along_path(&nodes, None);
	}

	#[test]
	fn vmw_two_unblinded_hops() {
		let nodes = create_nodes(3);
		let path = OnionMessagePath {
			intermediate_nodes: vec![nodes[1].get_node_pk()],
			destination: Destination::Node(nodes[2].get_node_pk()),
		};

		nodes[0].messenger.send_onion_message(path, OnionMessageContents::Custom(TestCustomMessage {}), None).unwrap();
		pass_along_path(&nodes, None);
	}

	#[test]
	fn vmw_two_unblinded_two_blinded() {
		let nodes = create_nodes(5);
		let secp_ctx = Secp256k1::new();
		let blinded_route = BlindedPath::new_for_message(&[nodes[3].get_node_pk(), nodes[4].get_node_pk()], &*nodes[4].keys_manager, &secp_ctx).unwrap();
		let path = OnionMessagePath {
			intermediate_nodes: vec![nodes[1].get_node_pk(), nodes[2].get_node_pk()],
			destination: Destination::BlindedPath(blinded_route),
		};

		nodes[0].messenger.send_onion_message(path, OnionMessageContents::Custom(TestCustomMessage {}), None).unwrap();
		pass_along_path(&nodes, None);
	}

	#[test]
	fn vmw_three_blinded_hops() {
		let nodes = create_nodes(4);
		let secp_ctx = Secp256k1::new();
		let blinded_route = BlindedPath::new_for_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();
		let path = OnionMessagePath {
			intermediate_nodes: vec![],
			destination: Destination::BlindedPath(blinded_route),
		};

		nodes[0].messenger.send_onion_message(path, OnionMessageContents::Custom(TestCustomMessage {}), None).unwrap();
		pass_along_path(&nodes, None);
	}
	#[test]
	fn test_no_onion_message_breakage() {
		let one_hop_om = "020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000000000000000000000000000000000000000000000000000e01ae0276020000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000000000000000000000e0101022a0000000000000000000000000000014551231950b75fc4402da1732fc9bebf00109500000000000000000000000000000004106d000000000000000000000000000000fd1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005600000000000000000000000000000000000000000000000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&::hex::decode(one_hop_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(),
						"Received an onion message with path_id None and a reply_path".to_string())), Some(&1));
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(),
						"Responding to onion message with path_id None".to_string())), Some(&1));
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(),
						"Failed responding to onion message with path_id None: TooFewBlindedHops".to_string())), Some(&1));
		}

		let two_unblinded_hops_om = "020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000000000000000000000000000000000000000000000000000e0135043304210202020202020202020202020202020202020202020202020202020202020202026d000000000000000000000000000000eb0000000000000000000000000000000000000000000000000000000000000036041096000000000000000000000000000000fd1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004800000000000000000000000000000000000000000000000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&::hex::decode(two_unblinded_hops_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}

		let two_unblinded_two_blinded_om = "020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000000000000000000000000000000000000000000000000000e0135043304210202020202020202020202020202020202020202020202020202020202020202026d0000000000000000000000000000009e0000000000000000000000000000000000000000000000000000000000000058045604210203030303030303030303030303030303030303030303030303030303030303020821020000000000000000000000000000000000000000000000000000000000000e0196000000000000000000000000000000e9000000000000000000000000000000000000000000000000000000000000003504330421020404040404040404040404040404040404040404040404040404040404040402ca00000000000000000000000000000042000000000000000000000000000000000000000000000000000000000000003604103f000000000000000000000000000000fd1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004800000000000000000000000000000000000000000000000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&::hex::decode(two_unblinded_two_blinded_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}

		let three_blinded_om = "020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000000000000000000000000000000000000000000000000000e0135043304210202020202020202020202020202020202020202020202020202020202020202026d000000000000000000000000000000b20000000000000000000000000000000000000000000000000000000000000035043304210203030303030303030303030303030303030303030303030303030303030303029600000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000003604104e000000000000000000000000000000fd1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004800000000000000000000000000000000000000000000000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&::hex::decode(three_blinded_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}
	}
}
