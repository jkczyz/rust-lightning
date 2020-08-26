//! The logic to monitor for on-chain transactions and create the relevant claim responses lives
//! here.
//!
//! ChannelMonitor objects are generated by ChannelManager in response to relevant
//! messages/actions, and MUST be persisted to disk (and, preferably, remotely) before progress can
//! be made in responding to certain messages, see ManyChannelMonitor for more.
//!
//! Note that ChannelMonitors are an important part of the lightning trust model and a copy of the
//! latest ChannelMonitor must always be actively monitoring for chain updates (and no out-of-date
//! ChannelMonitors should do so). Thus, if you're building rust-lightning into an HSM or other
//! security-domain-separated system design, you should consider having multiple paths for
//! ChannelMonitors to get out of the HSM and onto monitoring devices.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::ln::channelmonitor::ChannelMonitorUpdate as nativeChannelMonitorUpdateImport;
type nativeChannelMonitorUpdate = nativeChannelMonitorUpdateImport;

/// An update generated by the underlying Channel itself which contains some new information the
/// ChannelMonitor should be made aware of.
#[must_use]
#[repr(C)]
pub struct ChannelMonitorUpdate {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelMonitorUpdate,
	pub _underlying_ref: bool,
}

impl Drop for ChannelMonitorUpdate {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_free(this_ptr: ChannelMonitorUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelMonitorUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelMonitorUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelMonitorUpdate {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChannelMonitorUpdate {
		assert!(!self._underlying_ref);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for ChannelMonitorUpdate {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelMonitorUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelMonitorUpdate)).clone() })) as *mut c_void
}
/// The sequence number of this update. Updates *must* be replayed in-order according to this
/// sequence number (and updates may panic if they are not). The update_id values are strictly
/// increasing and increase by one for each new update.
///
/// This sequence number is also used to track up to which points updates which returned
/// ChannelMonitorUpdateErr::TemporaryFailure have been applied to all copies of a given
/// ChannelMonitor when ChannelManager::channel_monitor_updated is called.
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_get_update_id(this_ptr: &ChannelMonitorUpdate) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.update_id;
	(*inner_val)
}
/// The sequence number of this update. Updates *must* be replayed in-order according to this
/// sequence number (and updates may panic if they are not). The update_id values are strictly
/// increasing and increase by one for each new update.
///
/// This sequence number is also used to track up to which points updates which returned
/// ChannelMonitorUpdateErr::TemporaryFailure have been applied to all copies of a given
/// ChannelMonitor when ChannelManager::channel_monitor_updated is called.
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_set_update_id(this_ptr: &mut ChannelMonitorUpdate, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.update_id = val;
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_write(obj: *const ChannelMonitorUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdate_read(ser: crate::c_types::u8slice) -> ChannelMonitorUpdate {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		ChannelMonitorUpdate { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		ChannelMonitorUpdate { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}
/// An error enum representing a failure to persist a channel monitor update.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ChannelMonitorUpdateErr {
	/// Used to indicate a temporary failure (eg connection to a watchtower or remote backup of
	/// our state failed, but is expected to succeed at some point in the future).
	///
	/// Such a failure will \"freeze\" a channel, preventing us from revoking old states or
	/// submitting new commitment transactions to the remote party. Once the update(s) which failed
	/// have been successfully applied, ChannelManager::channel_monitor_updated can be used to
	/// restore the channel to an operational state.
	///
	/// Note that a given ChannelManager will *never* re-generate a given ChannelMonitorUpdate. If
	/// you return a TemporaryFailure you must ensure that it is written to disk safely before
	/// writing out the latest ChannelManager state.
	///
	/// Even when a channel has been \"frozen\" updates to the ChannelMonitor can continue to occur
	/// (eg if an inbound HTLC which we forwarded was claimed upstream resulting in us attempting
	/// to claim it on this channel) and those updates must be applied wherever they can be. At
	/// least one such updated ChannelMonitor must be persisted otherwise PermanentFailure should
	/// be returned to get things on-chain ASAP using only the in-memory copy. Obviously updates to
	/// the channel which would invalidate previous ChannelMonitors are not made when a channel has
	/// been \"frozen\".
	///
	/// Note that even if updates made after TemporaryFailure succeed you must still call
	/// channel_monitor_updated to ensure you have the latest monitor and re-enable normal channel
	/// operation.
	///
	/// Note that the update being processed here will not be replayed for you when you call
	/// ChannelManager::channel_monitor_updated, so you must store the update itself along
	/// with the persisted ChannelMonitor on your own local disk prior to returning a
	/// TemporaryFailure. You may, of course, employ a journaling approach, storing only the
	/// ChannelMonitorUpdate on disk without updating the monitor itself, replaying the journal at
	/// reload-time.
	///
	/// For deployments where a copy of ChannelMonitors and other local state are backed up in a
	/// remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return TemporaryFailure until the remote copies could be updated.
	TemporaryFailure,
	/// Used to indicate no further channel monitor updates will be allowed (eg we've moved on to a
	/// different watchtower and cannot update with all watchtowers that were previously informed
	/// of this channel). This will force-close the channel in question (which will generate one
	/// final ChannelMonitorUpdate which must be delivered to at least one ChannelMonitor copy).
	///
	/// Should also be used to indicate a failure to update the local persisted copy of the channel
	/// monitor.
	PermanentFailure,
}
use lightning::ln::channelmonitor::ChannelMonitorUpdateErr as nativeChannelMonitorUpdateErr;
impl ChannelMonitorUpdateErr {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChannelMonitorUpdateErr {
		match self {
			ChannelMonitorUpdateErr::TemporaryFailure => nativeChannelMonitorUpdateErr::TemporaryFailure,
			ChannelMonitorUpdateErr::PermanentFailure => nativeChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChannelMonitorUpdateErr {
		match self {
			ChannelMonitorUpdateErr::TemporaryFailure => nativeChannelMonitorUpdateErr::TemporaryFailure,
			ChannelMonitorUpdateErr::PermanentFailure => nativeChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeChannelMonitorUpdateErr) -> Self {
		match native {
			nativeChannelMonitorUpdateErr::TemporaryFailure => ChannelMonitorUpdateErr::TemporaryFailure,
			nativeChannelMonitorUpdateErr::PermanentFailure => ChannelMonitorUpdateErr::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChannelMonitorUpdateErr) -> Self {
		match native {
			nativeChannelMonitorUpdateErr::TemporaryFailure => ChannelMonitorUpdateErr::TemporaryFailure,
			nativeChannelMonitorUpdateErr::PermanentFailure => ChannelMonitorUpdateErr::PermanentFailure,
		}
	}
}

use lightning::ln::channelmonitor::MonitorUpdateError as nativeMonitorUpdateErrorImport;
type nativeMonitorUpdateError = nativeMonitorUpdateErrorImport;

/// General Err type for ChannelMonitor actions. Generally, this implies that the data provided is
/// inconsistent with the ChannelMonitor being called. eg for ChannelMonitor::update_monitor this
/// means you tried to update a monitor for a different channel or the ChannelMonitorUpdate was
/// corrupted.
/// Contains a human-readable error message.
#[must_use]
#[repr(C)]
pub struct MonitorUpdateError {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorUpdateError,
	pub _underlying_ref: bool,
}

impl Drop for MonitorUpdateError {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn MonitorUpdateError_free(this_ptr: MonitorUpdateError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MonitorUpdateError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMonitorUpdateError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MonitorUpdateError {
	pub(crate) fn take_ptr(mut self) -> *mut nativeMonitorUpdateError {
		assert!(!self._underlying_ref);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::channelmonitor::MonitorEvent as nativeMonitorEventImport;
type nativeMonitorEvent = nativeMonitorEventImport;

/// An event to be processed by the ChannelManager.
#[must_use]
#[repr(C)]
pub struct MonitorEvent {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorEvent,
	pub _underlying_ref: bool,
}

impl Drop for MonitorEvent {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn MonitorEvent_free(this_ptr: MonitorEvent) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MonitorEvent_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMonitorEvent); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MonitorEvent {
	pub(crate) fn take_ptr(mut self) -> *mut nativeMonitorEvent {
		assert!(!self._underlying_ref);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::channelmonitor::HTLCUpdate as nativeHTLCUpdateImport;
type nativeHTLCUpdate = nativeHTLCUpdateImport;

/// Simple structure send back by ManyChannelMonitor in case of HTLC detected onchain from a
/// forward channel and from which info are needed to update HTLC in a backward channel.
#[must_use]
#[repr(C)]
pub struct HTLCUpdate {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHTLCUpdate,
	pub _underlying_ref: bool,
}

impl Drop for HTLCUpdate {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_free(this_ptr: HTLCUpdate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn HTLCUpdate_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeHTLCUpdate); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl HTLCUpdate {
	pub(crate) fn take_ptr(mut self) -> *mut nativeHTLCUpdate {
		assert!(!self._underlying_ref);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for HTLCUpdate {
	fn clone(&self) -> Self {
		Self {
			inner: Box::into_raw(Box::new(unsafe { &*self.inner }.clone())),
			_underlying_ref: false,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCUpdate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHTLCUpdate)).clone() })) as *mut c_void
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_write(obj: *const HTLCUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &(*(*obj).inner) })
}
#[no_mangle]
pub extern "C" fn HTLCUpdate_read(ser: crate::c_types::u8slice) -> HTLCUpdate {
	if let Ok(res) = crate::c_types::deserialize_obj(ser) {
		HTLCUpdate { inner: Box::into_raw(Box::new(res)), _underlying_ref: false }
	} else {
		HTLCUpdate { inner: std::ptr::null_mut(), _underlying_ref: false }
	}
}

use lightning::ln::channelmonitor::ChannelMonitor as nativeChannelMonitorImport;
type nativeChannelMonitor = nativeChannelMonitorImport<crate::chain::keysinterface::ChannelKeys>;

/// A ChannelMonitor handles chain events (blocks connected and disconnected) and generates
/// on-chain transactions to ensure no loss of funds occurs.
///
/// You MUST ensure that no ChannelMonitors for a given channel anywhere contain out-of-date
/// information and are actively monitoring the chain.
///
/// Pending Events or updated HTLCs which have not yet been read out by
/// get_and_clear_pending_monitor_events or get_and_clear_pending_events are serialized to disk and
/// reloaded at deserialize-time. Thus, you must ensure that, when handling events, all events
/// gotten are fully handled before re-serializing the new state.
#[must_use]
#[repr(C)]
pub struct ChannelMonitor {
	/// Nearly everyhwere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelMonitor,
	pub _underlying_ref: bool,
}

impl Drop for ChannelMonitor {
	fn drop(&mut self) {
		if !self._underlying_ref && !self.inner.is_null() {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
#[no_mangle]
pub extern "C" fn ChannelMonitor_free(this_ptr: ChannelMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelMonitor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelMonitor); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelMonitor {
	pub(crate) fn take_ptr(mut self) -> *mut nativeChannelMonitor {
		assert!(!self._underlying_ref);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Simple trait indicating ability to track a set of ChannelMonitors and multiplex events between
/// them. Generally should be implemented by keeping a local SimpleManyChannelMonitor and passing
/// events to it, while also taking any add/update_monitor events and passing them to some remote
/// server(s).
///
/// In general, you must always have at least one local copy in memory, which must never fail to
/// update (as it is responsible for broadcasting the latest state in case the channel is closed),
/// and then persist it to various on-disk locations. If, for some reason, the in-memory copy fails
/// to update (eg out-of-memory or some other condition), you must immediately shut down without
/// taking any further action such as writing the current state to disk. This should likely be
/// accomplished via panic!() or abort().
///
/// Note that any updates to a channel's monitor *must* be applied to each instance of the
/// channel's monitor everywhere (including remote watchtowers) *before* this function returns. If
/// an update occurs and a remote watchtower is left with old state, it may broadcast transactions
/// which we have revoked, allowing our counterparty to claim all funds in the channel!
///
/// User needs to notify implementors of ManyChannelMonitor when a new block is connected or
/// disconnected using their `block_connected` and `block_disconnected` methods. However, rather
/// than calling these methods directly, the user should register implementors as listeners to the
/// BlockNotifier and call the BlockNotifier's `block_(dis)connected` methods, which will notify
/// all registered listeners in one go.
#[repr(C)]
pub struct ManyChannelMonitor {
	pub this_arg: *mut c_void,
	/// Adds a monitor for the given `funding_txo`.
	///
	/// Implementer must also ensure that the funding_txo txid *and* outpoint are registered with
	/// any relevant ChainWatchInterfaces such that the provided monitor receives block_connected
	/// callbacks with the funding transaction, or any spends of it.
	///
	/// Further, the implementer must also ensure that each output returned in
	/// monitor.get_outputs_to_watch() is registered to ensure that the provided monitor learns about
	/// any spends of any of the outputs.
	///
	/// Any spends of outputs which should have been registered which aren't passed to
	/// ChannelMonitors via block_connected may result in FUNDS LOSS.
	#[must_use]
	pub add_monitor: extern "C" fn (this_arg: *const c_void, funding_txo: crate::chain::transaction::OutPoint, monitor: crate::ln::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	/// Updates a monitor for the given `funding_txo`.
	///
	/// Implementer must also ensure that the funding_txo txid *and* outpoint are registered with
	/// any relevant ChainWatchInterfaces such that the provided monitor receives block_connected
	/// callbacks with the funding transaction, or any spends of it.
	///
	/// Further, the implementer must also ensure that each output returned in
	/// monitor.get_watch_outputs() is registered to ensure that the provided monitor learns about
	/// any spends of any of the outputs.
	///
	/// Any spends of outputs which should have been registered which aren't passed to
	/// ChannelMonitors via block_connected may result in FUNDS LOSS.
	#[must_use]
	pub update_monitor: extern "C" fn (this_arg: *const c_void, funding_txo: crate::chain::transaction::OutPoint, monitor: crate::ln::channelmonitor::ChannelMonitorUpdate) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	/// Used by ChannelManager to get list of HTLC resolved onchain and which needed to be updated
	/// with success or failure.
	///
	/// You should probably just call through to
	/// ChannelMonitor::get_and_clear_pending_monitor_events() for each ChannelMonitor and return
	/// the full list.
	#[must_use]
	pub get_and_clear_pending_monitor_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_MonitorEventZ,
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ManyChannelMonitor {}
unsafe impl Sync for ManyChannelMonitor {}

use lightning::ln::channelmonitor::ManyChannelMonitor as rustManyChannelMonitor;
impl rustManyChannelMonitor for ManyChannelMonitor {
	type Keys = crate::chain::keysinterface::ChannelKeys;
	fn add_monitor(&self, funding_txo: lightning::chain::transaction::OutPoint, monitor: lightning::ln::channelmonitor::ChannelMonitor<Self::Keys>) -> Result<(), lightning::ln::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.add_monitor)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo)), _underlying_ref: false }, crate::ln::channelmonitor::ChannelMonitor { inner: Box::into_raw(Box::new(monitor)), _underlying_ref: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(ret.contents.result.take_ptr()) })*/ }), false => Err( { (*unsafe { Box::from_raw(ret.contents.err.take_ptr()) }).into_native() })};
		local_ret
	}
	fn update_monitor(&self, funding_txo: lightning::chain::transaction::OutPoint, monitor: lightning::ln::channelmonitor::ChannelMonitorUpdate) -> Result<(), lightning::ln::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.update_monitor)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo)), _underlying_ref: false }, crate::ln::channelmonitor::ChannelMonitorUpdate { inner: Box::into_raw(Box::new(monitor)), _underlying_ref: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(ret.contents.result.take_ptr()) })*/ }), false => Err( { (*unsafe { Box::from_raw(ret.contents.err.take_ptr()) }).into_native() })};
		local_ret
	}
	fn get_and_clear_pending_monitor_events(&self) -> Vec<lightning::ln::channelmonitor::MonitorEvent> {
		let mut ret = (self.get_and_clear_pending_monitor_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { *unsafe { Box::from_raw(item.take_ptr()) } }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for ManyChannelMonitor {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ManyChannelMonitor_free(this_ptr: ManyChannelMonitor) { }
impl Drop for ManyChannelMonitor {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Updates a ChannelMonitor on the basis of some new information provided by the Channel
/// itself.
///
/// panics if the given update is not the next update by update_id.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_update_monitor(this_arg: &mut ChannelMonitor, mut updates: crate::ln::channelmonitor::ChannelMonitorUpdate, broadcaster: &crate::chain::chaininterface::BroadcasterInterface, logger: &crate::util::logger::Logger) -> crate::c_types::derived::CResult_NoneMonitorUpdateErrorZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.update_monitor(*unsafe { Box::from_raw(updates.take_ptr()) }, broadcaster, logger);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }), Err(mut e) => crate::c_types::CResultTempl::err( { crate::ln::channelmonitor::MonitorUpdateError { inner: Box::into_raw(Box::new(e)), _underlying_ref: false } }) };
	local_ret
}

/// Gets the update_id from the latest ChannelMonitorUpdate which was applied to this
/// ChannelMonitor.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_latest_update_id(this_arg: &ChannelMonitor) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.get_latest_update_id();
	ret
}

/// Gets the funding transaction outpoint of the channel this ChannelMonitor is monitoring for.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_funding_txo(this_arg: &ChannelMonitor) -> crate::c_types::derived::C2Tuple_OutPointScriptZ {
	let mut ret = unsafe { &*this_arg.inner }.get_funding_txo();
	let (ref orig_ret_0, ref orig_ret_1) = ret; let mut local_ret = (crate::chain::transaction::OutPoint { inner: unsafe { ( (&(*orig_ret_0) as *const _) as *mut _) }, _underlying_ref: true }, orig_ret_1.clone().into_bytes().into()).into();
	local_ret
}

/// Get the list of HTLCs who's status has been updated on chain. This should be called by
/// ChannelManager via ManyChannelMonitor::get_and_clear_pending_monitor_events().
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_and_clear_pending_monitor_events(this_arg: &mut ChannelMonitor) -> crate::c_types::derived::CVec_MonitorEventZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_and_clear_pending_monitor_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::ln::channelmonitor::MonitorEvent { inner: Box::into_raw(Box::new(item)), _underlying_ref: false } }); };
	local_ret.into()
}

/// Gets the list of pending events which were generated by previous actions, clearing the list
/// in the process.
///
/// This is called by ManyChannelMonitor::get_and_clear_pending_events() and is equivalent to
/// EventsProvider::get_and_clear_pending_events() except that it requires &mut self as we do
/// no internal locking in ChannelMonitors.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_and_clear_pending_events(this_arg: &mut ChannelMonitor) -> crate::c_types::derived::CVec_EventZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_and_clear_pending_events();
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { crate::util::events::Event::native_into(item) }); };
	local_ret.into()
}

/// Used by ChannelManager deserialization to broadcast the latest local state if its copy of
/// the Channel was out-of-date. You may use it to get a broadcastable local toxic tx in case of
/// fallen-behind, i.e when receiving a channel_reestablish with a proof that our remote side knows
/// a higher revocation secret than the local commitment number we are aware of. Broadcasting these
/// transactions are UNSAFE, as they allow remote side to punish you. Nevertheless you may want to
/// broadcast them if remote don't close channel with his higher commitment transaction after a
/// substantial amount of time (a month or even a year) to get back funds. Best may be to contact
/// out-of-band the other node operator to coordinate with him if option is available to you.
/// In any-case, choice is up to the user.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelMonitor_get_latest_local_commitment_txn(this_arg: &mut ChannelMonitor, logger: &crate::util::logger::Logger) -> crate::c_types::derived::CVec_TransactionZ {
	let mut ret = unsafe { &mut (*(this_arg.inner as *mut nativeChannelMonitor)) }.get_latest_local_commitment_txn(logger);
	let mut local_ret = Vec::new(); for item in ret.drain(..) { local_ret.push( { let mut local_ret_0 = ::bitcoin::consensus::encode::serialize(&item); local_ret_0.into() }); };
	local_ret.into()
}

