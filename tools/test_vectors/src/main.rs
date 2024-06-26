//! Executable to build or check test vectors.
//! Favor succinct code, to be use directly with cargo run.
//! (no error handling constant parameter definition).

use erasure_coding::{construct_chunks, ChunkIndex, MerklizedChunks, SEGMENT_SIZE};
use jsonschema::JSONSchema;
use rand::RngCore;
use segment_proof::{PAGE_PROOF_SEGMENT_DISTRIBUTED_SIZE, PAGE_PROOF_SEGMENT_HASHES};
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

// TODO this mod could be part of crate, currently copied for external branch
mod segment_proof;

// 3 test vector of each package size.
// Some size may not make sense but this should
// not be an issue regarding EC
const PACKAGE_SIZES: [usize; 11] = [
	684, // only one point in subshard.
	1024,    // one page only padded for subshard
	2048,
	2052,
	4096,    // one page only for subshard
	4104,   // one page padded
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

	let json_schema: serde_json::value::Value =
		serde_json::from_reader(File::open("vector_schema.json").unwrap()).unwrap();
	let schema = JSONSchema::compile(&json_schema).unwrap();
	for path in paths {
		check_package_vector(&path.unwrap().path(), Some(&schema));
	}
}

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Package {
	#[serde_as(as = "Base64<Standard, Padded>")]
	data: Vec<u8>,
	// chunks by index (firsts are split package, size of chunk from vec).
	chunks: Vec<Chunk>,
	#[serde_as(as = "Base64<Standard, Padded>")]
	// chunks merkle root
	chunks_root: [u8; 32],
	// Segments by index.
	segments: Vec<Segment>,
	// Segments by index.
	#[serde_as(as = "Base64<Standard, Padded>")]
	segments_root: [u8; 32],
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

//#[serde_as]
//#[derive(Deserialize, Serialize, Default, Debug)]
//struct SerHash(#[serde_as(as = "Base64<Standard, Padded>")] [u8; 32]);

fn build_package_vector(size_index: usize) {
	let package_size: usize = PACKAGE_SIZES[size_index];
	let mut file_path: PathBuf = VECS_LOCATION.into();
	let file_name: String = format!("{}_{}", PREFIX_PACKAGE, package_size);
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

	// consider data as work package then chunks
	if package_size >= (64 * N_CHUNKS as usize) {
		for chunk in construct_chunks(N_CHUNKS * 3, &package.data).unwrap() {
			package.chunks.push(Chunk(chunk));
		}
		let chunk_len = package.chunks[0].0.len();
		package.chunks_root = root_build(package.data.as_slice(), chunk_len);
	} else {
		std::println!("Skipping size {}, for package", package_size);
	}

	// consider data as exported segments then subshards
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

	// consider data as containing only hashes of every exported segments up to 2^11 segments.
	package.segments_root = build_segment_root(package.data.as_slice());

	serde_json::to_writer_pretty(&mut file, &package).unwrap();
}

fn root_build(data: &[u8], chunk_len: usize) -> [u8; 32] {
	let chunks_for_root: Vec<_> = data.chunks(chunk_len).map(|s| s.to_vec()).collect();

	// chunks root
	let iter = MerklizedChunks::compute(chunks_for_root.clone());
	let chunks_root: [u8; 32] = iter.root().into();

	// chunks root with segment proof code
	let proof = segment_proof::MerklizedSegments::compute(
		chunks_for_root.len(),
		true,
		false,
		chunks_for_root.iter().map(|i| &i[..]),
	);
	assert_eq!(chunks_root, proof.root());
	chunks_root
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

fn build_page_proofs(data: &[u8]) -> Vec<Box<[u8; PAGE_PROOF_SEGMENT_DISTRIBUTED_SIZE]>> {
	data.chunks(PAGE_PROOF_SEGMENT_DISTRIBUTED_SIZE)
		.map(|s| {
			let mut se = [0u8; PAGE_PROOF_SEGMENT_DISTRIBUTED_SIZE];
			se[0..s.len()].copy_from_slice(s);
			Box::new(se)
		})
		.collect()
}

fn build_segment_root(data: &[u8]) -> [u8; 32] {
	let nb_hash = std::cmp::min(2048, data.len() / 32);
	let data = &data[..nb_hash * 32];
	let page_proofs = build_page_proofs(data);
	let page_proofs_hashes: Vec<_> = page_proofs
		.iter()
		.map(|page| {
			let hash = segment_proof::hash_fn(&page[..]);
			let mut hash_buff = [0u8; 32];
			hash_buff.copy_from_slice(&hash.as_bytes()[..32]);
			hash_buff
		})
		.collect();

	// then build a exported segment root from it.
	let segment_proof = segment_proof::MerklizedSegments::compute(
		nb_hash + page_proofs.len(),
		true,
		true,
		data.chunks(32).chain(page_proofs_hashes.iter().map(|hash| &hash[..])),
	);
	let mut root = [0u8; 32];
	root.copy_from_slice(segment_proof.root());
	root
}

fn check_package_vector(path: &Path, schema: Option<&JSONSchema>) {
	let package: Package = serde_json::from_reader(File::open(path).unwrap()).unwrap();
	if let Some(schema) = schema {
		assert!(schema.is_valid(&serde_json::to_value(&package).unwrap()));
	}
	let package_size = package.data.len();

	// check package data
	if package_size >= (64 * N_CHUNKS as usize) {
		for (i, chunk) in construct_chunks(N_CHUNKS * 3, &package.data).unwrap().iter().enumerate()
		{
			assert_eq!(&package.chunks[i].0, chunk);
		}
		// check root
		let chunk_len = package.chunks[0].0.len();
		assert_eq!(root_build(package.data.as_slice(), chunk_len), package.chunks_root);
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

	let calc_segment_root = build_segment_root(package.data.as_slice());
	assert_eq!(calc_segment_root, package.segments_root);
}
