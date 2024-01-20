//! This library provides methods for encoding the data into chunks and
//! reconstructing the original data from chunks as well as verifying
//! individual chunks against an erasure root.

mod error;
mod merklize;

pub use self::{
	error::Error,
	merklize::{ErasureRoot, MerklizedChunks, Proof},
};

use scale::{Decode, Encode};
use std::ops::AddAssign;

pub const MAX_CHUNKS: u16 = 16384;

// The reed-solomon library requires each shards to be 64 bytes aligned.
const SHARD_ALIGNMENT: usize = 64;

/// The index of an erasure chunk.
#[derive(Eq, Ord, PartialEq, PartialOrd, Copy, Clone, Encode, Decode, Hash, Debug)]
pub struct ChunkIndex(pub u16);

impl From<u16> for ChunkIndex {
	fn from(n: u16) -> Self {
		ChunkIndex(n)
	}
}

impl AddAssign<u16> for ChunkIndex {
	fn add_assign(&mut self, rhs: u16) {
		self.0 += rhs
	}
}

/// A chunk of erasure-encoded block data.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct ErasureChunk {
	/// The erasure-encoded chunk of data belonging to the candidate block.
	pub chunk: Vec<u8>,
	/// The index of this erasure-encoded chunk of data.
	pub index: ChunkIndex,
	/// Proof for this chunk against an erasure root.
	pub proof: Proof,
}

/// Obtain a threshold of chunks that should be enough to recover the data.
pub const fn recovery_threshold(n_chunks: u16) -> Result<u16, Error> {
	if n_chunks > MAX_CHUNKS {
		return Err(Error::TooManyTotalChunks);
	}
	if n_chunks == 0 {
		return Err(Error::NotEnoughTotalChunks);
	}

	let needed = (n_chunks - 1) / 3;
	Ok(needed + 1)
}

/// Obtain the threshold of systematic chunks that should be enough to recover the data.
pub fn systematic_recovery_threshold(n_chunks: u16) -> Result<u16, Error> {
	recovery_threshold(n_chunks)
}

/// Reconstruct the original data from the set of systematic chunks.
///
/// Provide a vector containing the first k chunks in order. If too few chunks are provided,
/// recovery is not possible.
///
/// Due to the internals of the erasure coding algorithm, the output might be
/// larger than the original data and padded with zeroes; passing `data_len`
/// allows to truncate the output to the original data size.
pub fn reconstruct_from_systematic(
	n_chunks: u16,
	systematic_chunks: Vec<Vec<u8>>,
	data_len: usize,
) -> Result<Vec<u8>, Error> {
	let k = systematic_recovery_threshold(n_chunks)? as usize;
	let Some(first_shard) = systematic_chunks.first() else {
		return Err(Error::NotEnoughChunks);
	};
	if k == 1 {
		return Ok(first_shard[..data_len].to_vec());
	}
	if systematic_chunks.len() < k {
		return Err(Error::NotEnoughChunks);
	}
	let shard_len = first_shard.len();
	if shard_len % SHARD_ALIGNMENT != 0 {
		return Err(Error::UnalignedChunk);
	}
	for shard_data in systematic_chunks.iter().take(k) {
		if shard_data.len() != shard_len {
			return Err(Error::NonUniformChunks)
		}
	}

	let mut bytes: Vec<u8> = Vec::with_capacity(shard_len * k);
	for chunk in systematic_chunks.into_iter().take(k) {
		bytes.extend_from_slice(&chunk);
	}
	bytes.resize(data_len, 0);

	Ok(bytes)
}

/// Construct erasure-coded chunks.
///
/// Works only for 1..65536 chunks.
/// The data must be non-empty.
pub fn construct_chunks(n_chunks: u16, data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
	if data.is_empty() {
		return Err(Error::BadPayload);
	}
	if n_chunks == 1 {
		return Ok(vec![data.to_vec()]);
	}
	let systematic = systematic_recovery_threshold(n_chunks)?;
	let original_data = make_original_shards(systematic, data);
	let original_count = systematic as usize;
	let recovery_count = (n_chunks - systematic) as usize;

	let original_iter = original_data.iter();
	let recovery = reed_solomon::encode(original_count, recovery_count, original_iter)?;

	let mut result = original_data;
	result.extend(recovery);
	Ok(result)
}

fn next_aligned(n: usize, alignment: usize) -> usize {
	((n + alignment - 1) / alignment) * alignment
}

// The reed-solomon library takes sharded data as input.
fn make_original_shards(original_count: u16, data: &[u8]) -> Vec<Vec<u8>> {
	let n_shards = original_count as usize;
	assert!(!data.is_empty(), "data must be non-empty");
	assert_ne!(n_shards, 0);

	let shard_bytes = (data.len() + n_shards - 1) / n_shards;
	let shard_bytes = next_aligned(shard_bytes, SHARD_ALIGNMENT);
	assert_ne!(shard_bytes, 0);

	let mut result = vec![vec![0u8; shard_bytes]; n_shards];
	for (i, chunk) in data.chunks(shard_bytes).enumerate() {
		result[i][..chunk.len()].as_mut().copy_from_slice(chunk);
	}

	result
}

/// Reconstruct the original data from a set of chunks.
///
/// Provide an iterator containing chunk data and the corresponding index.
/// The indices of the present chunks must be indicated. If too few chunks
/// are provided, recovery is not possible.
///
/// Works only for 1..65536 chunks.
///
/// Due to the internals of the erasure coding algorithm, the output might be
/// larger than the original data and padded with zeroes; passing `data_len`
/// allows to truncate the output to the original data size.
pub fn reconstruct<I>(n_chunks: u16, chunks: I, data_len: usize) -> Result<Vec<u8>, Error>
where
	I: IntoIterator<Item = (ChunkIndex, Vec<u8>)>,
{
	if n_chunks == 1 {
		return chunks.into_iter().next().map(|(_, v)| v).ok_or(Error::NotEnoughChunks);
	}
	let n = n_chunks as usize;
	let original_count = systematic_recovery_threshold(n_chunks)? as usize;
	let recovery_count = n - original_count;

	let (mut original, recovery): (Vec<_>, Vec<_>) = chunks
		.into_iter()
		.map(|(i, v)| (i.0 as usize, v))
		.partition(|(i, _)| *i < original_count);

	original.sort_by_key(|(i, _)| *i);
	let original_iter = original.iter().map(|(i, v)| (*i, v));
	let recovery = recovery.into_iter().map(|(i, v)| (i - original_count, v));

	let mut recovered =
		reed_solomon::decode(original_count, recovery_count, original_iter, recovery)?;

	let mut original = original.into_iter();
	let mut bytes = Vec::with_capacity(data_len);

	for i in 0..original_count {
		let chunk = recovered.remove(&i).unwrap_or_else(|| {
			let (j, v) = original.next().expect("what is not recovered must be present; qed");
			debug_assert_eq!(i, j);
			v
		});
		bytes.extend_from_slice(chunk.as_slice());
	}

	bytes.truncate(data_len);

	Ok(bytes)
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use super::*;
	use quickcheck::{Arbitrary, Gen, QuickCheck};

	#[derive(Clone, Debug)]
	struct ArbitraryAvailableData(Vec<u8>);

	impl Arbitrary for ArbitraryAvailableData {
		fn arbitrary(g: &mut Gen) -> Self {
			// Limit the POV len to 16KiB, otherwise the test will take forever
			let data_len = (u32::arbitrary(g) % (16 * 1024)).max(2);

			let data = (0..data_len).map(|_| u8::arbitrary(g)).collect();

			ArbitraryAvailableData(data)
		}
	}

	#[derive(Clone, Debug)]
	struct SmallAvailableData(Vec<u8>);

	impl Arbitrary for SmallAvailableData {
		fn arbitrary(g: &mut Gen) -> Self {
			let data_len = (u32::arbitrary(g) % (2 * 1024)).max(2);

			let data = (0..data_len).map(|_| u8::arbitrary(g)).collect();

			Self(data)
		}
	}

	#[test]
	fn round_trip_systematic_works() {
		fn property(available_data: ArbitraryAvailableData, n_chunks: u16) {
			let n_chunks = n_chunks.max(1).min(MAX_CHUNKS);
			let threshold = systematic_recovery_threshold(n_chunks).unwrap();
			let data_len = available_data.0.len();
			let chunks = construct_chunks(n_chunks, &available_data.0).unwrap();
			let reconstructed: Vec<u8> = reconstruct_from_systematic(
				n_chunks,
				chunks.into_iter().take(threshold as usize).collect(),
				data_len,
			)
			.unwrap();
			assert_eq!(reconstructed, available_data.0);
		}

		QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
	}

	#[test]
	fn round_trip_works() {
		fn property(available_data: ArbitraryAvailableData, n_chunks: u16) {
			let n_chunks = n_chunks.max(1).min(MAX_CHUNKS);
			let data_len = available_data.0.len();
			let threshold = recovery_threshold(n_chunks).unwrap();
			let chunks = construct_chunks(n_chunks, &available_data.0).unwrap();
			let map: HashMap<ChunkIndex, Vec<u8>> = chunks
				.into_iter()
				.enumerate()
				.map(|(i, v)| (ChunkIndex::from(i as u16), v))
				.collect();
			let some_chunks = map.into_iter().take(threshold as usize);
			let reconstructed: Vec<u8> = reconstruct(n_chunks, some_chunks, data_len).unwrap();
			assert_eq!(reconstructed, available_data.0);
		}

		QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
	}

	#[test]
	fn proof_verification_works() {
		fn property(data: SmallAvailableData, n_chunks: u16) {
			let n_chunks = n_chunks.max(1).min(2048);
			let chunks = construct_chunks(n_chunks, &data.0).unwrap();
			assert_eq!(chunks.len() as u16, n_chunks);

			let iter = MerklizedChunks::compute(chunks.clone());
			let root = iter.root();
			let erasure_chunks: Vec<_> = iter.collect();

			assert_eq!(erasure_chunks.len(), chunks.len());

			for erasure_chunk in erasure_chunks.into_iter() {
				let encode = Encode::encode(&erasure_chunk.proof);
				let decode = Decode::decode(&mut &encode[..]).unwrap();
				assert_eq!(erasure_chunk.proof, decode);
				assert_eq!(encode, Encode::encode(&decode));

				assert_eq!(&erasure_chunk.chunk, &chunks[erasure_chunk.index.0 as usize]);

				assert!(erasure_chunk.verify(&root));
			}
		}

		QuickCheck::new().quickcheck(property as fn(SmallAvailableData, u16))
	}
}
