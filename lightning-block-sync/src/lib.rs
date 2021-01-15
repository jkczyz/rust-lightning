//! A lightweight client for keeping in sync with chain activity.
//!
//! Defines a [`BlockSource`] trait, which is an asynchronous interface for retrieving block headers
//! and data.
//!
//! [`BlockSource`]: trait.BlockSource.html

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::hash_types::BlockHash;
use bitcoin::util::uint::Uint256;

use std::future::Future;
use std::pin::Pin;

/// Abstract type for retrieving block headers and data.
pub trait BlockSource : Sync + Send {
	/// Returns the header for a given hash. A height hint may be provided in case a source cannot
	/// easily find headers based on a hash. This is merely a hint and thus the returned header must
	/// have the same hash as was requested. Otherwise, an error must be returned.
	///
	/// Implementations that cannot find headers based on the hash should return a `Transient` error
	/// when `height_hint` is `None`. In such a case, `get_best_block` should never return `None`
	/// for the height. Otherwise, the source could not be used independently for an initial sync.
	fn get_header<'a>(&'a mut self, header_hash: &'a BlockHash, height_hint: Option<u32>) -> AsyncBlockSourceResult<'a, BlockHeaderData>;

	/// Returns the block for a given hash. A headers-only block source should return a `Transient`
	/// error.
	fn get_block<'a>(&'a mut self, header_hash: &'a BlockHash) -> AsyncBlockSourceResult<'a, Block>;

	/// Returns the hash of the best block and, optionally, its height. The height is passed to
	/// `get_header` to allow a more efficient lookup on some block sources.
	fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)>;
}

/// Result type for `BlockSource` requests.
type BlockSourceResult<T> = Result<T, BlockSourceError>;

// TODO: Replace with BlockSourceResult once `async` trait functions are supported. For details,
// see: https://areweasyncyet.rs.
/// Result type for asynchronous `BlockSource` requests.
type AsyncBlockSourceResult<'a, T> = Pin<Box<dyn Future<Output = BlockSourceResult<T>> + 'a + Send>>;

/// Error type for `BlockSource` requests.
///
/// Transient errors may be resolved when re-polling, but no attempt will be made to re-poll on
/// persistent errors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BlockSourceError {
	/// Indicates an error that won't resolve when retrying a request (e.g., invalid data).
	Persistent,

	/// Indicates an error that may resolve when retrying a request (e.g., unresponsive).
	Transient,
}

/// A block header and some associated data. This information should be available from most block
/// sources (and, notably, is available in Bitcoin Core's RPC and REST interfaces).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockHeaderData {
	/// The block header itself.
	pub header: BlockHeader,

	/// The block height where the genesis block has height 0.
	pub height: u32,

	/// The total chain work in expected number of double-SHA256 hashes required to build a chain
	/// of equivalent weight.
	pub chainwork: Uint256,
}
