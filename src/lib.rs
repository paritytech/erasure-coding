//! This library provides methods for encoding the data into chunks and
//! reconstructing the original data from chunks as well as verifying
//! individual chunks against an erasure root.

mod error;
mod merklize;
mod subshard;

pub use self::{
	error::Error,
	merklize::{ErasureRoot, MerklizedChunks, Proof},
};

use scale::{Decode, Encode};
use std::ops::AddAssign;
pub use subshard::*;

use rayon::prelude::*;
use std::sync::Arc;

#[cfg(feature = "arena")]
use bumpalo::Bump;

// Prefetch hints for cache locality optimization
#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Branch prediction hints
#[cold]
#[inline(never)]
fn cold() {}

#[inline(always)]
fn likely(b: bool) -> bool {
	if !b {
		cold();
	}
	b
}

#[inline(always)]
fn unlikely(b: bool) -> bool {
	if b {
		cold();
	}
	b
}

pub const MAX_CHUNKS: u16 = 16384;

// The reed-solomon library requires each shards to be 64 bytes aligned.
const SHARD_ALIGNMENT: usize = 64;

const PADDING_ALIGNMENT: usize = 4;

#[derive(Clone)]
pub enum ThreadMode {
	Multi(Arc<rayon::ThreadPool>),
	Single,
}

impl ThreadMode {
	pub fn multi_with_num_threads(num_threads: Option<usize>) -> Result<Self, Error> {
		let threads = match num_threads {
			None => {
				let logical_cores =
					std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
				(logical_cores / 2).max(1)
			},
			Some(0) => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
			Some(n) => n,
		};

		let pool = rayon::ThreadPoolBuilder::new()
			.num_threads(threads)
			.build()
			.map_err(|_| Error::Unknown)?;

		Ok(ThreadMode::Multi(Arc::new(pool)))
	}

	pub fn single() -> Self {
		ThreadMode::Single
	}

	pub fn num_threads(&self) -> usize {
		match self {
			ThreadMode::Multi(pool) => pool.current_num_threads(),
			ThreadMode::Single => 1,
		}
	}
}

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
#[inline]
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
#[inline]
pub fn systematic_recovery_threshold(n_chunks: u16) -> Result<u16, Error> {
	recovery_threshold(n_chunks)
}

/// Reconstruct the original data from the set of systematic chunks.
///
/// Provide a vector containing the first k chunks in order. If too few chunks are provided,
/// recovery is not possible.
pub fn reconstruct_from_systematic<'a>(
	n_chunks: u16,
	systematic_len: usize,
	systematic_chunks: &'a mut impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, Error> {
	let k = systematic_recovery_threshold(n_chunks)? as usize;
	if unlikely(systematic_len < k) {
		return Err(Error::NotEnoughChunks);
	}

	let mut bytes: Vec<u8> = Vec::with_capacity(0);
	let mut shard_len = 0;
	let mut nb = 0;

	for chunk in systematic_chunks.by_ref() {
		nb += 1;
		if unlikely(shard_len == 0) {
			shard_len = chunk.len();
			if unlikely(shard_len % SHARD_ALIGNMENT != 0 && nb != k) {
				return Err(Error::UnalignedChunk);
			}

			if unlikely(k == 1) {
				let mut result = chunk.to_vec();
				remove_padding(&mut result);
				return Ok(result);
			}
			bytes = Vec::with_capacity(shard_len * k);
		}

		if unlikely(chunk.len() != shard_len) {
			return Err(Error::NonUniformChunks);
		}

		// extend_from_slice uses optimized memcpy
		bytes.extend_from_slice(chunk);

		if unlikely(nb == k) {
			break;
		}
	}

	remove_padding(&mut bytes);
	Ok(bytes)
}

/// Construct erasure-coded chunks.
///
/// Works only for 1..65536 chunks.
/// The data must be non-empty.
pub fn construct_chunks(
	n_chunks: u16,
	data: &[u8],
	mode: &ThreadMode,
) -> Result<Vec<Vec<u8>>, Error> {
	if unlikely(data.is_empty()) {
		return Err(Error::BadPayload);
	}

	let padded = add_padding(data);

	if unlikely(n_chunks == 1) {
		return Ok(vec![padded]);
	}

	#[cfg(feature = "arena")]
	{
		construct_chunks_arena(n_chunks, &padded, mode)
	}

	#[cfg(not(feature = "arena"))]
	{
		construct_chunks_default(n_chunks, &padded, mode)
	}
}

/// Construct erasure-coded chunks.
///
/// Works only for 1..65536 chunks.
/// The data must be non-empty.
#[inline]
fn construct_chunks_default(
	n_chunks: u16,
	data: &[u8],
	mode: &ThreadMode,
) -> Result<Vec<Vec<u8>>, Error> {
	let systematic = systematic_recovery_threshold(n_chunks)?;
	let original_data = make_original_shards(systematic, data, mode)?;
	let original_iter = original_data.iter();
	let original_count = systematic as usize;
	let recovery_count = (n_chunks - systematic) as usize;

	let recovery = reed_solomon::encode(original_count, recovery_count, original_iter)?;

	let mut result = original_data;
	result.extend(recovery);

	Ok(result)
}

#[cfg(feature = "arena")]
fn construct_chunks_arena(
	n_chunks: u16,
	data: &[u8],
	_mode: &ThreadMode,
) -> Result<Vec<Vec<u8>>, Error> {
	let systematic = systematic_recovery_threshold(n_chunks)?;
	let original_count = systematic as usize;
	let recovery_count = (n_chunks - systematic) as usize;
	let shard_size = shard_bytes(systematic, data.len());

	// Arena for temporary allocations
	let arena = Bump::with_capacity(original_count * shard_size + 4096);

	// Create shards using arena for intermediate data
	let original_data = make_original_shards_arena(&arena, systematic, data, shard_size);
	let original_iter = original_data.iter();

	let recovery = reed_solomon::encode(original_count, recovery_count, original_iter)?;

	let mut result = original_data;
	result.extend(recovery);

	Ok(result)
}

/// Creating shards using arena allocator
#[cfg(feature = "arena")]
fn make_original_shards_arena(
	_arena: &Bump,
	original_count: u16,
	data: &[u8],
	shard_size: usize,
) -> Vec<Vec<u8>> {
	let total_size = original_count as usize * shard_size;
	let mut flat_buffer = vec![0u8; total_size];

	let data_to_copy = data.len().min(total_size);
	flat_buffer[..data_to_copy].copy_from_slice(&data[..data_to_copy]);

	let mut result = Vec::with_capacity(original_count as usize);
	for chunk_data in flat_buffer.chunks_exact(shard_size) {
		result.push(chunk_data.to_vec());
	}

	result
}

#[inline(always)]
fn next_aligned(n: usize, alignment: usize) -> usize {
	((n + alignment - 1) / alignment) * alignment
}

#[inline]
fn shard_bytes(systematic: u16, data_len: usize) -> usize {
	let shard_bytes = (data_len + systematic as usize - 1) / systematic as usize;
	next_aligned(shard_bytes, SHARD_ALIGNMENT)
}

#[inline]
fn add_padding(data: &[u8]) -> Vec<u8> {
	let remainder = data.len() % PADDING_ALIGNMENT;
	let padding_len = if remainder == 0 { PADDING_ALIGNMENT } else { PADDING_ALIGNMENT - remainder };
	let mut padded = Vec::with_capacity(data.len() + padding_len);
	padded.extend_from_slice(data);
	padded.resize(data.len() + padding_len, padding_len as u8);
	padded
}

#[inline]
fn remove_padding(bytes: &mut Vec<u8>) {
	// Find the last non-zero byte
	if let Some(last_non_zero) = bytes.iter().rposition(|&b| b != 0) {
		// Truncate trailing zeros
		bytes.truncate(last_non_zero + 1);
		// Last byte is the padding length
		let padding_len = bytes[last_non_zero] as usize;
		// Remove padding bytes
		bytes.truncate(bytes.len().saturating_sub(padding_len));
	} else {
		// All zeros — shouldn't happen if padding was added correctly
		bytes.clear();
	}
}

// The reed-solomon library takes sharded data as input.
fn make_original_shards(
	original_count: u16,
	data: &[u8],
	mode: &ThreadMode,
) -> Result<Vec<Vec<u8>>, Error> {
	assert!(!data.is_empty(), "data must be non-empty");
	assert_ne!(original_count, 0);

	let shard_bytes = shard_bytes(original_count, data.len());
	assert_ne!(shard_bytes, 0);

	match mode {
		ThreadMode::Multi(pool) => Ok(pool.install(|| {
			(0..original_count as usize)
				.into_par_iter()
				.map(|i| {
					let mut chunk = vec![0u8; shard_bytes];
					let start = i * shard_bytes;
					let end = (start + shard_bytes).min(data.len());

					if likely(start < data.len()) {
						let copy_len = end - start;
						chunk[..copy_len].copy_from_slice(&data[start..end]);
					}

					chunk
				})
				.collect()
		})),
		ThreadMode::Single => {
			let mut result = Vec::with_capacity(original_count as usize);
			let mut remaining_data = data;

			for i in 0..original_count as usize {
				let mut chunk = vec![0u8; shard_bytes];
				let copy_len = remaining_data.len().min(shard_bytes);

				#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
				if i + 1 < original_count as usize && remaining_data.len() > shard_bytes {
					unsafe {
						let next_ptr = remaining_data.as_ptr().add(shard_bytes);
						if (remaining_data.len() - shard_bytes) >= 64 {
							_mm_prefetch(next_ptr as *const i8, _MM_HINT_T0);
						}
					}
				}

				chunk[..copy_len].copy_from_slice(&remaining_data[..copy_len]);

				if likely(remaining_data.len() >= shard_bytes) {
					remaining_data = &remaining_data[shard_bytes..];
				} else {
					remaining_data = &[];
				}

				result.push(chunk);
			}
			Ok(result)
		},
	}
}

/// Reconstruct the original data from a set of chunks.
///
/// Provide an iterator containing chunk data and the corresponding index.
/// The indices of the present chunks must be indicated. If too few chunks
/// are provided, recovery is not possible.
///
/// Works only for 1..65536 chunks.
pub fn reconstruct<I>(n_chunks: u16, chunks: I) -> Result<Vec<u8>, Error>
where
	I: IntoIterator<Item = (ChunkIndex, Vec<u8>)>,
{
	if n_chunks == 1 {
		let mut data = chunks.into_iter().next().map(|(_, v)| v).ok_or(Error::NotEnoughChunks)?;
		remove_padding(&mut data);
		return Ok(data);
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

	let shard_bytes = recovered
		.values()
		.next()
		.or_else(|| original.first().map(|(_, v)| v))
		.map(|v| v.len())
		.ok_or(Error::NotEnoughChunks)?;

	let mut bytes = Vec::with_capacity(shard_bytes * original_count);

	let mut original = original.into_iter();
	for i in 0..original_count {
		let chunk = recovered.remove(&i).unwrap_or_else(|| {
			let (j, v) = original.next().expect("what is not recovered must be present; qed");
			debug_assert_eq!(i, j);
			v
		});
		bytes.extend_from_slice(chunk.as_slice());
	}

	remove_padding(&mut bytes);

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

			for mode in [ThreadMode::single(), ThreadMode::multi_with_num_threads(None).unwrap()] {
				let chunks = construct_chunks(n_chunks, &available_data.0, &mode).unwrap();

				let reconstructed: Vec<u8> = reconstruct_from_systematic(
					n_chunks,
					chunks.len(),
					&mut chunks.iter().take(threshold as usize).map(Vec::as_slice),
				)
				.unwrap();
				assert_eq!(reconstructed, available_data.0);
			}
		}

		QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
	}

	#[test]
	fn round_trip_works() {
		fn property(available_data: ArbitraryAvailableData, n_chunks: u16) {
			let n_chunks = n_chunks.max(1).min(MAX_CHUNKS);
			let threshold = recovery_threshold(n_chunks).unwrap();

			for mode in [ThreadMode::single(), ThreadMode::multi_with_num_threads(None).unwrap()] {
				let chunks = construct_chunks(n_chunks, &available_data.0, &mode).unwrap();
				let map: HashMap<ChunkIndex, Vec<u8>> = chunks
					.into_iter()
					.enumerate()
					.map(|(i, v)| (ChunkIndex::from(i as u16), v))
					.collect();
				let some_chunks = map.into_iter().take(threshold as usize);
				let reconstructed: Vec<u8> = reconstruct(n_chunks, some_chunks).unwrap();
				assert_eq!(reconstructed, available_data.0);
			}
		}

		QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
	}

	#[test]
	fn proof_verification_works() {
		fn property(data: SmallAvailableData, n_chunks: u16) {
			let n_chunks = n_chunks.max(1).min(2048);

			for mode in [ThreadMode::single(), ThreadMode::multi_with_num_threads(None).unwrap()] {
				let chunks = construct_chunks(n_chunks, &data.0, &mode).unwrap();
				assert_eq!(chunks.len() as u16, n_chunks);
				let iter = MerklizedChunks::compute(chunks.clone(), &mode).unwrap();
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
		}

		QuickCheck::new().quickcheck(property as fn(SmallAvailableData, u16))
	}

	#[test]
	fn stress_test_various_sizes_with_random_chunk_loss() {
		use rand::{seq::SliceRandom, Rng, SeedableRng};

		let data_sizes = vec![10, 1000, 10_000, 100_000, 1_000_000, 10_000_000, 50_000_000];

		let chunk_configs = vec![16, 64, 256, 1024];

		for data_size in data_sizes.iter() {
			println!("Testing data size: {} bytes", data_size);

			for &n_chunks in chunk_configs.iter() {
				if *data_size < 1000 && n_chunks > 64 {
					continue;
				}

				println!("  Testing with {} chunks", n_chunks);

				let mut rng =
					rand::rngs::SmallRng::seed_from_u64((*data_size as u64) ^ (n_chunks as u64));
				let original_data: Vec<u8> = (0..*data_size).map(|_| rng.gen()).collect();

				for (mode_name, mode) in [
					("Single", ThreadMode::single()),
					("Multi", ThreadMode::multi_with_num_threads(None).unwrap()),
				] {
					let chunks = construct_chunks(n_chunks, &original_data, &mode).unwrap();

					assert_eq!(chunks.len(), n_chunks as usize);

					let threshold = recovery_threshold(n_chunks).unwrap() as usize;

					let mut chunk_indices: Vec<usize> = (0..n_chunks as usize).collect();

					chunk_indices.shuffle(&mut rng);

					let selected_indices = &chunk_indices[..threshold];

					let available_chunks: HashMap<ChunkIndex, Vec<u8>> = selected_indices
						.iter()
						.map(|&idx| (ChunkIndex(idx as u16), chunks[idx].clone()))
						.collect();

				let reconstructed =
					reconstruct(n_chunks, available_chunks.into_iter())
						.unwrap();

					assert_eq!(
						reconstructed.len(),
						original_data.len(),
						"Reconstructed data length mismatch for size {} with {} chunks (mode: {})",
						data_size,
						n_chunks,
						mode_name
					);

					assert_eq!(
						reconstructed, original_data,
						"Reconstructed data does not match original for size {} with {} chunks (mode: {})",
						data_size, n_chunks, mode_name
					);
				}
			}

			println!("  ✓ All chunk configurations passed for size {}", data_size);
		}

		println!("✓ All stress tests passed!");
	}

	#[test]
	fn test_thread_mode_configurations() {
		use std::thread::available_parallelism;

		let data = vec![1u8; 1024];
		let n_chunks = 16;

		let mode_default = ThreadMode::multi_with_num_threads(None).unwrap();
		let logical_cores = available_parallelism().map(|n| n.get()).unwrap_or(1);
		let expected_default = (logical_cores / 2).max(1);
		assert_eq!(
			mode_default.num_threads(),
			expected_default,
			"Thread mode with None should use half of logical cores"
		);
		let chunks = construct_chunks(n_chunks, &data, &mode_default).unwrap();
		assert_eq!(chunks.len(), n_chunks as usize);

		let all_cores = available_parallelism().map(|n| n.get()).unwrap_or(1);
		let mode_all = ThreadMode::multi_with_num_threads(Some(0)).unwrap();
		assert_eq!(
			mode_all.num_threads(),
			all_cores,
			"Thread mode with Some(0) should use all logical cores"
		);
		let chunks = construct_chunks(n_chunks, &data, &mode_all).unwrap();
		assert_eq!(chunks.len(), n_chunks as usize);

		let mode_2 = ThreadMode::multi_with_num_threads(Some(2)).unwrap();
		assert_eq!(
			mode_2.num_threads(),
			2,
			"Thread mode with Some(2) should use exactly 2 threads"
		);
		let chunks = construct_chunks(n_chunks, &data, &mode_2).unwrap();
		assert_eq!(chunks.len(), n_chunks as usize);

		let mode_4 = ThreadMode::multi_with_num_threads(Some(4)).unwrap();
		assert_eq!(
			mode_4.num_threads(),
			4,
			"Thread mode with Some(4) should use exactly 4 threads"
		);
		let chunks = construct_chunks(n_chunks, &data, &mode_4).unwrap();
		assert_eq!(chunks.len(), n_chunks as usize);

		let mode_single = ThreadMode::single();
		assert_eq!(mode_single.num_threads(), 1, "Single thread mode should report 1 thread");
		let chunks = construct_chunks(n_chunks, &data, &mode_single).unwrap();
		assert_eq!(chunks.len(), n_chunks as usize);

		println!("✓ Thread mode configuration test passed!");
	}

	#[test]
	fn test_padding_add_remove() {
		// Alignment 4: data of length 3 → 1 byte of padding [1]
		let data = vec![10, 20, 30];
		let padded = add_padding(&data);
		assert_eq!(padded, vec![10, 20, 30, 1]);

		// Alignment 4: data of length 4 → 4 bytes of padding [4,4,4,4]
		let data = vec![10, 20, 30, 40];
		let padded = add_padding(&data);
		assert_eq!(padded, vec![10, 20, 30, 40, 4, 4, 4, 4]);

		// Alignment 4: data of length 5 → 3 bytes of padding [3,3,3]
		let data = vec![1, 2, 3, 4, 5];
		let padded = add_padding(&data);
		assert_eq!(padded, vec![1, 2, 3, 4, 5, 3, 3, 3]);

		// Alignment 4: data of length 1 → 3 bytes of padding [3,3,3]
		let data = vec![42];
		let padded = add_padding(&data);
		assert_eq!(padded, vec![42, 3, 3, 3]);

		// Test remove_padding reverses add_padding
		for len in 1..=20 {
			let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
			let mut padded = add_padding(&data);
			// Simulate trailing zeros from reed-solomon
			padded.extend_from_slice(&[0u8; 100]);
			remove_padding(&mut padded);
			assert_eq!(padded, data, "Round-trip failed for data length {}", len);
		}
	}

	#[test]
	fn test_padding_data_ending_with_zeros() {
		// Data consisting entirely of zeros
		for len in 1..=16 {
			let data = vec![0u8; len];

			for mode in [ThreadMode::single(), ThreadMode::multi_with_num_threads(None).unwrap()] {
				let n_chunks = 4u16;
				let chunks = construct_chunks(n_chunks, &data, &mode).unwrap();

				// Test reconstruct_from_systematic
				let systematic = systematic_recovery_threshold(n_chunks).unwrap() as usize;
				let reconstructed_sys = reconstruct_from_systematic(
					n_chunks,
					chunks.len(),
					&mut chunks.iter().take(systematic).map(Vec::as_slice),
				)
				.unwrap();
				assert_eq!(
					reconstructed_sys, data,
					"Systematic failed for zero-data of length {} (mode: {:?})",
					len, mode.num_threads()
				);

				// Test reconstruct
				let threshold = recovery_threshold(n_chunks).unwrap();
				let map: HashMap<ChunkIndex, Vec<u8>> = chunks
					.into_iter()
					.enumerate()
					.take(threshold as usize)
					.map(|(i, v)| (ChunkIndex::from(i as u16), v))
					.collect();
				let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
				assert_eq!(
					reconstructed, data,
					"Reconstruct failed for zero-data of length {} (mode: {:?})",
					len, mode.num_threads()
				);
			}
		}
	}

	#[test]
	fn test_padding_aligned_and_unaligned_data() {
		// Test various data lengths: multiples of 4 and non-multiples
		let test_sizes = vec![
			1, 2, 3, 4, 5, 6, 7, 8,
			15, 16, 17,
			63, 64, 65,
			100, 127, 128, 129,
			255, 256, 257,
			1000, 1023, 1024, 1025,
		];

		for data_len in test_sizes {
			let original_data: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();

			for n_chunks in [2u16, 4, 8, 16] {
				for mode in [ThreadMode::single(), ThreadMode::multi_with_num_threads(None).unwrap()] {
					let chunks = construct_chunks(n_chunks, &original_data, &mode).unwrap();

					// Test reconstruct_from_systematic
					let systematic = systematic_recovery_threshold(n_chunks).unwrap() as usize;
					let reconstructed_sys = reconstruct_from_systematic(
						n_chunks,
						chunks.len(),
						&mut chunks.iter().take(systematic).map(Vec::as_slice),
					)
					.unwrap();
					assert_eq!(
						reconstructed_sys, original_data,
						"Systematic failed: data_len={}, n_chunks={}",
						data_len, n_chunks
					);

					// Test reconstruct
					let threshold = recovery_threshold(n_chunks).unwrap();
					let map: HashMap<ChunkIndex, Vec<u8>> = chunks
						.into_iter()
						.enumerate()
						.take(threshold as usize)
						.map(|(i, v)| (ChunkIndex::from(i as u16), v))
						.collect();
					let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
					assert_eq!(
						reconstructed, original_data,
						"Reconstruct failed: data_len={}, n_chunks={}",
						data_len, n_chunks
					);
				}
			}
		}
	}

	#[test]
	fn test_padding_data_with_padding_like_values() {
		// Data ending with bytes that look like padding values [4,4,4,4]
		let data = vec![4u8; 4];
		for n_chunks in [2u16, 4, 8] {
			let mode = ThreadMode::single();
			let chunks = construct_chunks(n_chunks, &data, &mode).unwrap();
			let threshold = recovery_threshold(n_chunks).unwrap();
			let map: HashMap<ChunkIndex, Vec<u8>> = chunks
				.into_iter()
				.enumerate()
				.take(threshold as usize)
				.map(|(i, v)| (ChunkIndex::from(i as u16), v))
				.collect();
			let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
			assert_eq!(reconstructed, data, "Failed for data=[4,4,4,4], n_chunks={}", n_chunks);
		}

		// Data ending with [1]
		let data = vec![1u8];
		for n_chunks in [2u16, 4, 8] {
			let mode = ThreadMode::single();
			let chunks = construct_chunks(n_chunks, &data, &mode).unwrap();
			let threshold = recovery_threshold(n_chunks).unwrap();
			let map: HashMap<ChunkIndex, Vec<u8>> = chunks
				.into_iter()
				.enumerate()
				.take(threshold as usize)
				.map(|(i, v)| (ChunkIndex::from(i as u16), v))
				.collect();
			let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
			assert_eq!(reconstructed, data, "Failed for data=[1], n_chunks={}", n_chunks);
		}

		// Data ending with [3, 3, 3]
		let data = vec![3u8; 3];
		for n_chunks in [2u16, 4, 8] {
			let mode = ThreadMode::single();
			let chunks = construct_chunks(n_chunks, &data, &mode).unwrap();
			let threshold = recovery_threshold(n_chunks).unwrap();
			let map: HashMap<ChunkIndex, Vec<u8>> = chunks
				.into_iter()
				.enumerate()
				.take(threshold as usize)
				.map(|(i, v)| (ChunkIndex::from(i as u16), v))
				.collect();
			let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
			assert_eq!(reconstructed, data, "Failed for data=[3,3,3], n_chunks={}", n_chunks);
		}
	}

	#[test]
	fn test_padding_random_data() {
		use rand::{Rng, SeedableRng};

		let mut rng = rand::rngs::SmallRng::seed_from_u64(12345);

		for _ in 0..50 {
			let data_len = rng.gen_range(1..=4096);
			let original_data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();
			let n_chunks = [2u16, 4, 8, 16, 32][rng.gen_range(0..5)];

			let mode = ThreadMode::single();
			let chunks = construct_chunks(n_chunks, &original_data, &mode).unwrap();

			// Test reconstruct_from_systematic
			let systematic = systematic_recovery_threshold(n_chunks).unwrap() as usize;
			let reconstructed_sys = reconstruct_from_systematic(
				n_chunks,
				chunks.len(),
				&mut chunks.iter().take(systematic).map(Vec::as_slice),
			)
			.unwrap();
			assert_eq!(
				reconstructed_sys, original_data,
				"Systematic failed: data_len={}, n_chunks={}",
				data_len, n_chunks
			);

			// Test reconstruct
			let threshold = recovery_threshold(n_chunks).unwrap();
			let map: HashMap<ChunkIndex, Vec<u8>> = chunks
				.into_iter()
				.enumerate()
				.take(threshold as usize)
				.map(|(i, v)| (ChunkIndex::from(i as u16), v))
				.collect();
			let reconstructed = reconstruct(n_chunks, map.into_iter()).unwrap();
			assert_eq!(
				reconstructed, original_data,
				"Reconstruct failed: data_len={}, n_chunks={}",
				data_len, n_chunks
			);
		}
	}

	#[test]
	fn test_padding_single_chunk() {
		// n_chunks == 1: special case
		let data = vec![1, 2, 3, 4, 5];
		let mode = ThreadMode::single();
		let chunks = construct_chunks(1, &data, &mode).unwrap();
		assert_eq!(chunks.len(), 1);

		// reconstruct with n_chunks == 1
		let map: HashMap<ChunkIndex, Vec<u8>> = chunks
			.into_iter()
			.enumerate()
			.map(|(i, v)| (ChunkIndex::from(i as u16), v))
			.collect();
		let reconstructed = reconstruct(1, map.into_iter()).unwrap();
		assert_eq!(reconstructed, data);
	}
}
