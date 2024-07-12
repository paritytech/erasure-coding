//! Manage subshards of 12 bytes of 4ko segments.
//! Subshards are processed in to shards of 64 bytes
//! to benefit from the simd optimisation in the
//! best case.

use super::*;
use std::{
	collections::{BTreeMap, BTreeSet},
	mem::MaybeUninit,
};

/// Fix segment size.
pub const SEGMENT_SIZE: usize = 4096;

const SUBSHARD_PER_SEGMENT: usize = ((SEGMENT_SIZE - 1) / SUBSHARD_SIZE) + 1;

/// Segment size with added padding to allow being
/// erasure coded in batch while staying on same points indexes.
const SEGMENT_SIZE_ALIGNED: usize = SUBSHARD_PER_SEGMENT * SUBSHARD_SIZE; // 4104 byte

/// Fix number of shards and subshards.
pub const N_SHARDS: usize = 342;

/// The number of time the erasure coded shards we want.
pub const N_REDUNDANCY: usize = 2;

/// The total number of shards, both original and ec one.
pub const TOTAL_SHARDS: usize = (1 + N_REDUNDANCY) * N_SHARDS;

/// The reed-solomon library requires each shards to be 64 bytes aligned.
const SHARD_MIN_SIZE: usize = SHARD_ALIGNMENT;

/// In shards lower and higher byte of each point are spaced for simd.
const POINT_BYTE_SPACING: usize = SHARD_ALIGNMENT / 2;

/// Number points in each subshards.
const SUBSHARD_POINTS: usize = 6;

/// Size of a point in bytes.
const POINT_SIZE: usize = 2; // gf16

/// Size of a subshard in bytes.
pub const SUBSHARD_SIZE: usize = POINT_SIZE * SUBSHARD_POINTS; // 12bytes

/// Aligned number of full shard to process subshard.
const SUBSHARD_BATCH_MUL: usize = 3; // 3 * 12 is aligned with 64

/// Number of segments in a aligned batch.
const SEGMENTS_PER_SUBSHARD_BATCH_OPTIMAL: usize =
	SUBSHARD_BATCH_MUL * SHARD_MIN_SIZE / SUBSHARD_SIZE; // 16

const BATCH_SHARD_SIZE: usize = SUBSHARD_BATCH_MUL * SHARD_MIN_SIZE; // 192

const SUBSHARD_BATCH_MUL1: usize = SHARD_MIN_SIZE / SUBSHARD_SIZE; // 64 / 12, only 5
const BATCH_SHARD_SIZE_1: usize = SHARD_MIN_SIZE; // 192
const SUBSHARD_BATCH_MUL2: usize = (SHARD_MIN_SIZE * 2) / SUBSHARD_SIZE; // 128 / 12, only 10
const BATCH_SHARD_SIZE_2: usize = 2 * SHARD_MIN_SIZE; // 192

/// Fix size segment of a larger data.
/// Data is padded when unaligned with
/// the segment size.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct Segment {
	/// Fix size chunk of data.
	pub data: Box<[u8; SEGMENT_SIZE]>,
	/// The index of this segment against its full data.
	pub index: u32,
}

/// Subshard (points in sequential orders).
pub type SubShard = [u8; SUBSHARD_SIZE];

/// Subshard uses some temp memory, so these should be used multiple time instead of allocating.
pub struct SubShardEncoder {
	encoder: reed_solomon::ReedSolomonEncoder,
	last_shard_size: usize,
}

impl SubShardEncoder {
	pub fn new() -> Result<Self, Error> {
		Ok(Self {
			last_shard_size: BATCH_SHARD_SIZE,
			encoder: reed_solomon::ReedSolomonEncoder::new(
				N_SHARDS,
				N_REDUNDANCY * N_SHARDS,
				BATCH_SHARD_SIZE,
			)?,
		})
	}

	/// Construct erasure-coded chunks.
	/// Resulting in groups of subshard per input segments.
	pub fn construct_chunks(
		&mut self,
		segments: &[Segment],
	) -> Result<Vec<Box<[SubShard; TOTAL_SHARDS]>>, Error> {
		let mut result = vec![Box::new([[0u8; SUBSHARD_SIZE]; TOTAL_SHARDS]); segments.len()];

		let mut seg_offset = 0;
		let mut shard = [0u8; BATCH_SHARD_SIZE];
		for segments in segments.chunks(SEGMENTS_PER_SUBSHARD_BATCH_OPTIMAL) {
			let s = if segments.len() <= SUBSHARD_BATCH_MUL1 {
				// 1 *
				BATCH_SHARD_SIZE_1
			} else if segments.len() <= SUBSHARD_BATCH_MUL2 {
				// 2 *
				BATCH_SHARD_SIZE_2
			} else {
				// 3 *
				BATCH_SHARD_SIZE
			};
			if self.last_shard_size != s {
				self.encoder.reset(N_SHARDS, N_REDUNDANCY * N_SHARDS, s)?;
				self.last_shard_size = s;
			}

			for shard_a in 0..N_SHARDS {
				let mut shard_i = 0;
				for segment_i in 0..segments.len() {
					for point_i in 0..SUBSHARD_POINTS {
						let data_i = (point_i * N_SHARDS) * 2 + shard_a * 2;
						let point = if data_i < SEGMENT_SIZE {
							(segments[segment_i].data[data_i], segments[segment_i].data[data_i + 1])
						} else {
							(0, 0)
						};
						shard[shard_i] = point.0;
						shard[shard_i + POINT_BYTE_SPACING] = point.1;
						result[seg_offset + segment_i][shard_a][point_i * 2] = point.0;
						result[seg_offset + segment_i][shard_a][point_i * 2 + 1] = point.1;
						shard_i += 1;
						if shard_i % POINT_BYTE_SPACING == 0 {
							shard_i += POINT_BYTE_SPACING;
						}
					}
				}
				self.encoder.add_original_shard(&shard[..s])?;
			}

			let enco_res = self.encoder.encode()?;
			for (shard_a, data) in enco_res.recovery_iter().enumerate() {
				let mut segment_i = 0;
				let mut data_i = 0;
				while data_i != data.len() {
					for point_i in 0..SUBSHARD_POINTS {
						let point = (data[data_i], data[data_i + 32]);
						data_i += 1;
						if data_i % POINT_BYTE_SPACING == 0 {
							data_i += POINT_BYTE_SPACING;
						}
						result[seg_offset + segment_i][shard_a + N_SHARDS][point_i * 2] = point.0;
						result[seg_offset + segment_i][shard_a + N_SHARDS][point_i * 2 + 1] =
							point.1;
					}
					segment_i += 1;
					if segment_i == segments.len() {
						break;
					}
				}
			}
			seg_offset += SEGMENTS_PER_SUBSHARD_BATCH_OPTIMAL;
		}
		Ok(result)
	}
}

/// Subshard uses some temp memory, so these should be used multiple time instead of allocating.
pub struct SubShardDecoder {
	decoder: reed_solomon::ReedSolomonDecoder,
	// cannot access ori shards from decoder, copying them here.
	shards_ori: [[u8; BATCH_SHARD_SIZE]; N_SHARDS],
	last_shard_size: usize,
}

impl SubShardDecoder {
	pub fn new() -> Result<Self, Error> {
		let mut shards: [MaybeUninit<[u8; BATCH_SHARD_SIZE]>; N_SHARDS] =
			unsafe { MaybeUninit::uninit().assume_init() };

		for shard in shards.iter_mut() {
			shard.write([0u8; BATCH_SHARD_SIZE]);
		}

		Ok(Self {
			last_shard_size: BATCH_SHARD_SIZE,
			decoder: reed_solomon::ReedSolomonDecoder::new(
				N_SHARDS,
				N_REDUNDANCY * N_SHARDS,
				BATCH_SHARD_SIZE,
			)?,
			shards_ori: unsafe { std::mem::transmute(shards) },
		})
	}

	// u8 is the segment number.
	pub fn reconstruct<'a, I>(
		&mut self,
		subshards: &'a mut I,
	) -> Result<(Vec<(u8, Segment)>, usize), Error>
	where
		I: Iterator<Item = (u8, ChunkIndex, &'a SubShard)>,
	{
		let mut ori = vec![Vec::new(); TOTAL_SHARDS];
		let mut segments = BTreeMap::<u8, usize>::new();
		let mut nb_decode = 0;

		// TODO processed and run_segments could be skiped if we are sure to get
		// correct number of chunks all for the same given chunk ix and segments.
		for (segment, chunk_index, chunk) in subshards {
			ori[chunk_index.0 as usize].push((segment, chunk));
			*segments.entry(segment).or_default() += 1;
		}

		// make batches of segments
		let mut segment_batches = Vec::new();

		let mut processed_segments = BTreeSet::new();
		let mut nb_segments = 0;
		for (segment, c) in segments.iter() {
			if *c >= N_SHARDS {
				nb_segments += 1;
			} else {
				processed_segments.insert(*segment);
			}
		}
		while nb_segments > 0 {
			// count all segments written, and stop at first segment having enough.
			let mut run_segments = BTreeMap::new();
			let mut ok = false;
			for chunks in ori.iter() {
				let first = run_segments.is_empty();
				for (segment_i, _chunk) in chunks {
					if !processed_segments.contains(segment_i) {
						if first {
							if !processed_segments.contains(segment_i) {
								run_segments.insert(*segment_i, 1);
							}
						} else if let Some(c) = run_segments.get_mut(segment_i) {
							*c += 1;
							if *c == N_SHARDS {
								ok = true;
							}
						}
					}
				}
				if ok {
					break;
				}
			}
			if !ok {
				if run_segments.is_empty() {
					// should not happen
					break;
				}
				for (seg, _count) in run_segments.into_iter() {
					processed_segments.insert(seg);
				}
				continue;
			}
			// TODO max size 16, rather [;16] lookup?
			let mut segment_batch = BTreeSet::new();
			for (seg, count) in run_segments.into_iter() {
				if count == N_SHARDS {
					processed_segments.insert(seg);
					segment_batch.insert(seg);
					if segment_batch.len() == 16 {
						segment_batches.push(segment_batch);
						segment_batch = Default::default();
					}
				}
			}
			if !segment_batch.is_empty() {
				nb_segments -= segment_batch.len();
				segment_batches.push(segment_batch);
			}
		}

		for chunks in ori.iter_mut() {
			chunks.sort_by_key(|c| c.0);
		}

		let mut result2 = Vec::new();
		// Note that sometime byte could stay set to non zero value, but it does not matter.
		let mut shard_buff = [0u8; BATCH_SHARD_SIZE];
		for segments in segment_batches {
			let s = if segments.len() <= SUBSHARD_BATCH_MUL1 {
				// 1 *
				BATCH_SHARD_SIZE_1
			} else if segments.len() <= SUBSHARD_BATCH_MUL2 {
				// 2 *
				BATCH_SHARD_SIZE_2
			} else {
				// 3 *
				BATCH_SHARD_SIZE
			};
			if s != self.last_shard_size {
				self.decoder.reset(N_SHARDS, N_REDUNDANCY * N_SHARDS, s)?;
				self.last_shard_size = s;
			}
			let mut nb_chunk = 0;
			let mut ori_map: std::collections::BTreeMap<usize, &[u8]> = Default::default();
			for (chunk_ix, chunks) in ori.iter().enumerate() {
				if chunks.is_empty() {
					continue;
				}
				let mut nb = 0;
				let shard = if chunk_ix < N_SHARDS {
					let s = &self.shards_ori[chunk_ix] as *const _ as *mut [u8; BATCH_SHARD_SIZE];
					// each shard are only accessed a single time here.
					unsafe { s.as_mut().expect("non null") }
				} else {
					&mut shard_buff
				};
				for (segment_i, chunk) in chunks {
					if segments.contains(segment_i) {
						let shard_i_s = nb * SUBSHARD_SIZE / SHARD_MIN_SIZE;
						let shard_i_r = nb * SUBSHARD_SIZE % SHARD_MIN_SIZE;
						let mut shard_i = shard_i_s * SHARD_MIN_SIZE + shard_i_r / POINT_SIZE;
						for point_i in 0..SUBSHARD_POINTS {
							shard[shard_i] = chunk[point_i * POINT_SIZE];
							shard[shard_i + POINT_BYTE_SPACING] = chunk[(point_i * POINT_SIZE) + 1];
							shard_i += 1;
							if shard_i % POINT_BYTE_SPACING == 0 {
								shard_i += POINT_BYTE_SPACING;
							}
						}
						nb += 1;
					}
				}
				debug_assert!(nb == 0 || nb == segments.len());
				if nb > 0 {
					if chunk_ix < N_SHARDS {
						self.decoder
							.add_original_shard(chunk_ix, &self.shards_ori[chunk_ix][..s])?;
						ori_map.insert(chunk_ix, &self.shards_ori[chunk_ix][..]);
					} else {
						self.decoder.add_recovery_shard(chunk_ix - N_SHARDS, &shard_buff[..s])?;
					}
					nb_chunk += 1;
					if nb_chunk == N_SHARDS {
						break;
					}
				}
			}
			debug_assert!(nb_chunk == N_SHARDS);
			let ori_ret = self.decoder.decode()?;
			nb_decode += 1;
			// TODO modify deps to also access original data and avoid self.ori_shards buffer.
			// Also to avoid instantiating ori_map container.
			for (i, o) in ori_ret.restored_original_iter() {
				ori_map.insert(i, o);
			}
			debug_assert_eq!(ori_map.len(), N_SHARDS);
			for (i, segment) in segments.iter().enumerate() {
				let chunk_start = i * SEGMENT_SIZE_ALIGNED;
				let original = ori_chunk_to_data(&ori_map, chunk_start, Some(SEGMENT_SIZE))
					.expect("number of segments checked");
				result2
					.push((*segment, Segment { data: Box::new(original), index: *segment as u32 }));
			}
		}

		Ok((result2, nb_decode))
	}
}

fn ori_chunk_to_data(
	shards: &BTreeMap<usize, &[u8]>,
	start_data: usize,
	data_len: Option<usize>,
) -> Option<[u8; 4096]> {
	let mut data = [0u8; 4096];

	let mut i_data = 0;
	let (mut full_i, mut shard_i, mut shard_a) = data_index_to_chunk_index(start_data);
	let mut shard_i_offset = full_i * SHARD_MIN_SIZE;
	loop {
		let s = shards.get(&shard_a)?;
		let l = s[shard_i_offset + shard_i];
		data[i_data] = l;
		i_data += 1;
		let r = s[shard_i_offset + shard_i + POINT_BYTE_SPACING];
		data[i_data] = r;
		i_data += 1;
		if data_len.map(|m| i_data >= m).unwrap_or(false) {
			break;
		}
		shard_a += 1;
		if shard_a % N_SHARDS == 0 {
			shard_i += 1;
			if shard_i == POINT_BYTE_SPACING {
				shard_i = 0;
				full_i += 1;
				if full_i == SUBSHARD_BATCH_MUL {
					break;
				}

				shard_i_offset = full_i * SHARD_MIN_SIZE;
			}
			shard_a = 0;
		}
	}
	Some(data)
}

// return chunk index among N_SHARDS (group of n , ix in slice, ix in n)
fn data_index_to_chunk_index(index: usize) -> (usize, usize, usize) {
	let shard_batch_size = SHARD_MIN_SIZE * N_SHARDS;
	let a = index % shard_batch_size;
	let b = a % (N_SHARDS * POINT_SIZE);
	(index / shard_batch_size, a / (N_SHARDS * POINT_SIZE), b / POINT_SIZE)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_segments() {
		for count in [1, 2, 4, 5, 10, 16] {
			test_sc(count);
		}
	}

	fn test_sc(nb_seg: usize) {
		use rand::{rngs::SmallRng, Rng, SeedableRng};
		let mut rng = SmallRng::from_seed([0; 32]);
		let segments: Vec<_> = (0..nb_seg)
			.map(|s| {
				let mut se = [0u8; SEGMENT_SIZE];
				rng.fill::<_>(&mut se[..]);

				Segment { data: Box::new(se), index: s as u32 }
			})
			.collect();

		let mut encoder = SubShardEncoder::new().unwrap();
		let mut decoder = SubShardDecoder::new().unwrap();
		let chunks = encoder.construct_chunks(&segments).unwrap();

		for i_seg in 0..nb_seg {
			let mut it = (chunks[i_seg][0..N_SHARDS / 3])
				.iter()
				.enumerate()
				.map(|(i, c)| (i_seg as u8, ChunkIndex(i as u16), c))
				.chain(
					(chunks[i_seg][N_SHARDS..N_SHARDS + N_SHARDS / 3])
						.iter()
						.enumerate()
						.map(|(i, c)| (i_seg as u8, ChunkIndex(i as u16 + N_SHARDS as u16), c)),
				)
				.chain(
					(chunks[i_seg][N_SHARDS * 2..N_SHARDS * 2 + N_SHARDS / 3])
						.iter()
						.enumerate()
						.map(|(i, c)| (i_seg as u8, ChunkIndex(i as u16 + N_SHARDS as u16 * 2), c)),
				);
			let (s, i) = decoder.reconstruct(&mut it).unwrap();
			assert_eq!(i, 1);
			assert_eq!((i_seg as u8, segments[i_seg].clone()), s[0]);
		}
		// try batching 2 subchunk
		if nb_seg < 2 {
			return;
		}
		let i_seg1 = 0;
		let i_seg2 = nb_seg / 2;

		let it1 = (chunks[i_seg1][0..N_SHARDS / 3])
			.iter()
			.enumerate()
			.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16), c))
			.chain(
				(chunks[i_seg1][N_SHARDS..N_SHARDS + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16 + N_SHARDS as u16), c)),
			)
			.chain(
				(chunks[i_seg1][N_SHARDS * 2..N_SHARDS * 2 + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16 + N_SHARDS as u16 * 2), c)),
			);
		let it2 = (chunks[i_seg2][0..N_SHARDS / 3])
			.iter()
			.enumerate()
			.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16), c))
			.chain(
				(chunks[i_seg2][N_SHARDS..N_SHARDS + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16 + N_SHARDS as u16), c)),
			)
			.chain(
				(chunks[i_seg2][N_SHARDS * 2..N_SHARDS * 2 + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16 + N_SHARDS as u16 * 2), c)),
			);

		let (s, i) = decoder.reconstruct(&mut it1.chain(it2)).unwrap();
		assert_eq!(i, 1); // all chunk ix are aligned so can be processed at once.
		assert_eq!((i_seg1 as u8, segments[i_seg1].clone()), s[0]);
		assert_eq!((i_seg2 as u8, segments[i_seg2].clone()), s[1]);

		let it1 = (chunks[i_seg1][0..N_SHARDS / 3])
			.iter()
			.enumerate()
			.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16), c))
			.chain(
				(chunks[i_seg1][N_SHARDS..N_SHARDS + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16 + N_SHARDS as u16), c)),
			)
			.chain(
				(chunks[i_seg1][N_SHARDS * 2..N_SHARDS * 2 + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg1 as u8, ChunkIndex(i as u16 + N_SHARDS as u16 * 2), c)),
			);

		// unaligned a batch of chunks
		let it3 = (chunks[i_seg2][1..N_SHARDS / 3 + 1])
			.iter()
			.enumerate()
			.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16 + 1), c))
			.chain(
				(chunks[i_seg2][N_SHARDS..N_SHARDS + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16 + N_SHARDS as u16), c)),
			)
			.chain(
				(chunks[i_seg2][N_SHARDS * 2..N_SHARDS * 2 + N_SHARDS / 3])
					.iter()
					.enumerate()
					.map(|(i, c)| (i_seg2 as u8, ChunkIndex(i as u16 + N_SHARDS as u16 * 2), c)),
			);
		let (s, i) = decoder.reconstruct(&mut it1.chain(it3)).unwrap();
		assert_eq!(i, 2); // not all chunk ix are aligned
		assert_eq!((i_seg1 as u8, segments[i_seg1].clone()), s[0]);
		assert_eq!((i_seg2 as u8, segments[i_seg2].clone()), s[1]);
	}
}
