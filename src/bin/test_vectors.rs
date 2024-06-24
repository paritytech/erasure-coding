//! Executable to build or check test vectors.
//! Favor succinct code, to be use directly with cargo run.
//! (no error handling constant parameter definition).

use erasure_coding::{construct_chunks, ChunkIndex, SEGMENT_SIZE};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{
	base64::{Base64, Standard},
	formats::Padded,
	serde_as,
};
use std::{
	fs::File,
	path::{Path, PathBuf},
};

// 3 test vector of each package size.
// Some size may not make sense but this should
// not be an issue regarding EC
const PACKAGE_SIZES: [usize; 7] = [
	1024,    // one page only padded for subshard
	4096,    // one page only for subshard
	15000,   // unaligne padded 4 pages
	21824,   // min size with full 64 byte aligened chunk.
	21888,   // aligned full paralellized subshards.
	100_000, // larger
	200_000, // larger 2
];

const VECS_LOCATION: &str = "vectors";

const N_CHUNKS: u16 = 341;

const N_SUBCHUNKS: usize = 342;

const PREFIX_PACKAGE: &str = "package";

fn main() {
	for index in 0..PACKAGE_SIZES.len() {
		build_package_vector(index);
	}
	let dir: PathBuf = VECS_LOCATION.into();
	let paths = std::fs::read_dir(&dir).unwrap();

	for path in paths {
		check_package_vector(&path.unwrap().path());
	}
}

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Package {
	#[serde_as(as = "Base64<Standard, Padded>")]
	data: Vec<u8>,
	// chunks by index (firsts are split package, size of chunk from vec).
	chunks: Vec<Chunk>,
	// Segments by index.
	segments: Vec<Segment>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Chunk(#[serde_as(as = "Base64<Standard, Padded>")] Vec<u8>);

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Segment {
	subshards: Vec<SubChunk>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Default, Debug)]
struct SubChunk(#[serde_as(as = "Base64<Standard, Padded>")] [u8; 12]);

fn build_package_vector(size_index: usize) {
	let package_size: usize = PACKAGE_SIZES[size_index];
	let mut file_path: PathBuf = VECS_LOCATION.into();
	let file_name: String = format!("{}_{:02}", PREFIX_PACKAGE, size_index);
	file_path.push(&file_name);
	if file_path.exists() {
		std::println!("Skipping size {}, file {} exists already", package_size, file_name);
		return;
	}
	let mut file = File::create(&file_path).unwrap();

	let mut package = Package::default();
	package.data = vec![0; package_size];

	let mut rng = rand::thread_rng();
	rng.fill_bytes(&mut package.data);

	// chunks
	if package_size >= (64 * N_CHUNKS as usize) {
		for chunk in construct_chunks(N_CHUNKS * 3, &package.data).unwrap() {
			package.chunks.push(Chunk(chunk));
		}
	} else {
		std::println!("Skipping size {}, for package", package_size);
	}

	// subshards
	let segments_chunks = build_segments(&package.data);
	let mut encoder = erasure_coding::SubShardEncoder::new().unwrap();
	for segment_chunks in encoder.construct_chunks(&segments_chunks).unwrap().into_iter() {
		let mut segment = Segment { subshards: Vec::with_capacity(segment_chunks.len()) };
		for chunk in segment_chunks.iter() {
			segment.subshards.push(SubChunk(*chunk));
		}
		package.segments.push(segment);
	}
	assert_eq!(package.segments.len(), segments_chunks.len());

	serde_json::to_writer_pretty(&mut file, &package).unwrap();
}

fn build_segments(data: &[u8]) -> Vec<erasure_coding::Segment> {
	data.chunks(SEGMENT_SIZE)
		.enumerate()
		.map(|(i, s)| {
			let mut se = [0u8; SEGMENT_SIZE];
			se[0..s.len()].copy_from_slice(s);
			erasure_coding::Segment { data: Box::new(se), index: i as u32 }
		})
		.collect()
}

fn check_package_vector(path: &Path) {
	let package: Package = serde_json::from_reader(File::open(path).unwrap()).unwrap();
	let package_size = package.data.len();

	// check package data
	if package_size >= (64 * N_CHUNKS as usize) {
		for (i, chunk) in construct_chunks(N_CHUNKS * 3, &package.data).unwrap().iter().enumerate()
		{
			assert_eq!(&package.chunks[i].0, chunk);
		}
	} else {
		std::println!("Skipping check size {}, for package", package_size);
	}

	// check package chunks
	let segments_chunks = build_segments(&package.data);
	assert_eq!(package.segments.len(), segments_chunks.len());
	let mut encoder = erasure_coding::SubShardEncoder::new().unwrap();
	for (i, segment_chunks) in
		encoder.construct_chunks(&segments_chunks).unwrap().into_iter().enumerate()
	{
		for (j, chunk) in segment_chunks.iter().enumerate() {
			assert_eq!(&package.segments[i].subshards[j].0, chunk);
		}
	}

	// check some reconstruct (not necessary)

	// mix half ori half first reco
	fn in_range(i: usize, sub_chunks: bool) -> bool {
		let n_chunks = if sub_chunks { N_SUBCHUNKS } else { N_CHUNKS as usize };
		let split = n_chunks / 2;
		let high_bound = if n_chunks % 2 == 0 { n_chunks + split } else { n_chunks + split + 1 };
		i < split || (i >= n_chunks && i < high_bound)
	}
	if package.chunks.len() > 0 {
		let r = erasure_coding::reconstruct(
			N_CHUNKS * 3,
			package
				.chunks
				.iter()
				.enumerate()
				.filter(|(i, _)| in_range(*i, false))
				.map(|(i, c)| (ChunkIndex(i as u16), &c.0)),
			package_size,
		)
		.unwrap();
		assert_eq!(r, package.data);
	}
	let mut decoder = erasure_coding::SubShardDecoder::new().unwrap();
	// not running segments in parallel (could be but simpler code here)
	for (seg_index, segment) in package.segments.iter().enumerate() {
		let r = decoder
			.reconstruct(
				&mut segment
					.subshards
					.iter()
					.enumerate()
					.filter(|(i, _)| in_range(*i, true))
					.map(|(i, c)| (seg_index as u8, ChunkIndex(i as u16), &c.0)),
			)
			.unwrap();
		assert_eq!(r.1, 1);
		assert_eq!(r.0.len(), 1);
		assert_eq!(r.0[0].0, seg_index as u8);
		assert_eq!(r.0[0].1, segments_chunks[seg_index]);
	}
}
