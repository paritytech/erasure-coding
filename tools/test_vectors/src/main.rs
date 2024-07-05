//! Executable to build or check test vectors.
//! Favor succinct code, to be use directly with cargo run.
//! (no error handling constant parameter definition).

use erasure_coding::{
	construct_chunks, segment_proof, ChunkIndex, IncompleteSegments, MerklizedChunks, PageProof,
	SEGMENT_SIZE,
};
use jsonschema::JSONSchema;
//use rand::{rngs::SmallRng, RngCore, SeedableRng};
use rand::RngCore;
use segment_proof::{
	MAX_SEGMENT_PROOF_LEN, PAGE_PROOF_SEGMENT_HASHES, PAGE_PROOF_SEGMENT_HASHES_SIZE,
};
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
const PACKAGE_SIZES: [usize; 11] = [
	0,
	1,
	32,
	684,     // one subshard point only
	4096,    // one page only for subshard
	4104,    // one page padded
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
		build_vector(index);
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
struct Vector {
	#[serde_as(as = "Base64<Standard, Padded>")]
	data: Vec<u8>,
	work_package: Package,
	segment: Segments,
	page_proof: PageProofs,
}

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Package {
	// chunks by index (firsts are split package, size of chunk from vec).
	chunks: Vec<Bytes>,
	#[serde_as(as = "Base64<Standard, Padded>")]
	// chunks merkle root
	chunks_root: [u8; 32],
}

#[serde_as]
#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug)]
struct Bytes(#[serde_as(as = "Base64<Standard, Padded>")] Vec<u8>);

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Segments {
	// Segments by index.
	segments: Vec<Segment>,
	#[serde_as(as = "Base64<Standard, Padded>")]
	segments_root: [u8; 32],
}

#[serde_as]
#[derive(Deserialize, Serialize, Default)]
struct Segment {
	segment_ec: Vec<SubChunk>,
}

#[serde_as]
#[derive(Deserialize, Serialize, Default, Debug)]
struct SubChunk(#[serde_as(as = "Base64<Standard, Padded>")] [u8; 12]);

#[serde_as]
#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug)]
struct PageProofs {
	page_proofs: Vec<Bytes>,
	#[serde_as(as = "Base64<Standard, Padded>")]
	segments_root: [u8; 32],
}

//#[serde_as]
//#[derive(Deserialize, Serialize, Default, Debug)]
//struct SerHash(#[serde_as(as = "Base64<Standard, Padded>")] [u8; 32]);

fn build_vector(size_index: usize) {
	let package_size: usize = PACKAGE_SIZES[size_index];
	let mut file_path: PathBuf = VECS_LOCATION.into();
	let file_name: String = format!("{}_{}", PREFIX_PACKAGE, package_size);
	file_path.push(&file_name);
	if file_path.exists() {
		std::println!("Skipping size {}, file {} exists already", package_size, file_name);
		return;
	}
	let mut file = File::create(&file_path).unwrap();

	let mut vector = Vector::default();
	vector.data = vec![0; package_size];
	//let mut rng = SmallRng::seed_from_u64(0);
	let mut rng = rand::thread_rng();
	rng.fill_bytes(&mut vector.data);

	// consider data as work package then chunks
	if package_size >= (64 * N_CHUNKS as usize) {
		for chunk in construct_chunks(N_CHUNKS * 3, &vector.data).unwrap() {
			vector.work_package.chunks.push(Bytes(chunk));
		}
		let chunk_len = vector.work_package.chunks[0].0.len();
		let merlized = root_build(vector.data.as_slice(), chunk_len);
		vector.work_package.chunks_root = merlized.root().into();
	} else {
		std::println!("Skipping size {}, for package", package_size);
	}

	// consider data as exported segments then subshards
	let segments_chunks = build_segments(&vector.data);
	let mut encoder = erasure_coding::SubShardEncoder::new().unwrap();
	for segment_chunks in encoder.construct_chunks(&segments_chunks).unwrap().into_iter() {
		let mut segment = Segment { segment_ec: Vec::with_capacity(segment_chunks.len()) };
		for chunk in segment_chunks.iter() {
			segment.segment_ec.push(SubChunk(*chunk));
		}
		vector.segment.segments.push(segment);
	}
	assert_eq!(vector.segment.segments.len(), segments_chunks.len());
	vector.segment.segments_root = root_from_segments(segments_chunks.as_slice());

	// consider data as containing only hashes of every exported segments up to 2^11 segments.
	build_segment_root(vector.data.as_slice(), &mut vector.page_proof);

	serde_json::to_writer_pretty(&mut file, &vector).unwrap();
}

fn root_build(data: &[u8], chunk_len: usize) -> MerklizedChunks {
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
	iter
}

fn build_segments(data: &[u8]) -> Vec<erasure_coding::Segment> {
	data.chunks(SEGMENT_SIZE)
		.map(|s| {
			let mut se = [0u8; SEGMENT_SIZE];
			se[0..s.len()].copy_from_slice(s);
			erasure_coding::Segment { data: Box::new(se) }
		})
		.collect()
}

fn build_page_proofs(data: &[u8]) -> Vec<(usize, Box<[u8; PAGE_PROOF_SEGMENT_HASHES_SIZE]>)> {
	data.chunks(PAGE_PROOF_SEGMENT_HASHES_SIZE)
		.map(|s| {
			let mut se = [0u8; PAGE_PROOF_SEGMENT_HASHES_SIZE];
			se[0..s.len()].copy_from_slice(s);
			(s.len() / 32, Box::new(se))
		})
		.collect()
}

fn root_from_segments(segments: &[erasure_coding::Segment]) -> [u8; 32] {
	let nb_hash = segments.len();
	let m = segment_proof::MerklizedSegments::compute(
		nb_hash,
		true,
		false,
		segments.iter().map(|s| s.data.as_slice()),
	);

	//let hash = segment_proof::hash_fn(&page[..]);
	let mut hash_buff = [0u8; 32];
	hash_buff.copy_from_slice(m.root());
	//hash_buff.copy_from_slice(&hash.as_bytes()[..32]);
	hash_buff
}

fn build_segment_root(data: &[u8], into: &mut PageProofs) {
	let nb_hash = std::cmp::min(2048, data.len() / 32);
	let data = &data[..nb_hash * 32];
	let page_proofs = build_page_proofs(data);

	// then build a exported segment root from it.
	let segment_proof = segment_proof::MerklizedSegments::compute(
		nb_hash,
		true,
		true,
		data.chunks(32).take(nb_hash),
	);

	let mut check_build = IncompleteSegments::new(segment_proof.root());
	let nb_page = page_proofs.len() as u16;
	let mut proof_buf: [&[u8]; MAX_SEGMENT_PROOF_LEN] = Default::default();
	for (i, (nb_hash, page)) in page_proofs.iter().enumerate() {
		// we bound subtree to less than 64 only, otherwhise
		// this is part of a proof larger than a page that is aligned
		// to next power of two so we have to use all tree depth even
		// if it is a single hash.
		let bound = if nb_page == 1 { *nb_hash } else { PAGE_PROOF_SEGMENT_HASHES };
		let subtree_root = segment_proof::MerklizedSegments::compute(
			bound,
			true,
			true,
			page.chunks(32).take(bound),
		);

		assert!(segment_proof.contains_hash(subtree_root.root()));

		let mut encoded_page = [0u8; 4096];
		encoded_page[0..2048].copy_from_slice(&page[..]);
		let proof = segment_proof.page_proof_proof(&mut proof_buf, i as u16);
		let mut enc_at = 2048;
		for p in proof {
			encoded_page[enc_at..enc_at + 32].copy_from_slice(p);
			enc_at += 32;
		}
		let pp = PageProof { index: i as u16, parent_proof: &segment_proof };
		let mut other = [0u8; 4096];
		pp.encoded(&mut other);
		assert_eq!(&encoded_page, &other);
		assert_eq!(check_build.insert_page_proof_hashes(&encoded_page, i as u16), Some(true));
		assert!(segment_proof.check_page_proof_root(&mut proof_buf, i as u16, subtree_root.root()));
		into.page_proofs.push(Bytes(encoded_page.to_vec()));
	}
	assert_eq!(check_build.nb_page_proof(), nb_page);

	into.segments_root[..].copy_from_slice(segment_proof.root());
}

fn check_package_vector(path: &Path, schema: Option<&JSONSchema>) {
	let vector: Vector = serde_json::from_reader(File::open(path).unwrap()).unwrap();
	if let Some(schema) = schema {
		assert!(schema.is_valid(&serde_json::to_value(&vector).unwrap()));
	}
	let package_size = vector.data.len();

	// check package data
	if package_size >= (64 * N_CHUNKS as usize) {
		for (i, chunk) in construct_chunks(N_CHUNKS * 3, &vector.data).unwrap().iter().enumerate() {
			assert_eq!(&vector.work_package.chunks[i].0, chunk);
		}
		// check root
		let chunk_len = vector.work_package.chunks[0].0.len();
		let merlized = root_build(vector.data.as_slice(), chunk_len);
		assert_eq!(Into::<[u8; 32]>::into(merlized.root()), vector.work_package.chunks_root);
	} else {
		std::println!("Skipping check size {}, for package", package_size);
	}

	// check package chunks
	let segments_chunks = build_segments(&vector.data);
	assert_eq!(vector.segment.segments.len(), segments_chunks.len());
	assert_eq!(vector.segment.segments_root, root_from_segments(segments_chunks.as_slice()));
	let mut encoder = erasure_coding::SubShardEncoder::new().unwrap();
	for (i, segment_chunks) in
		encoder.construct_chunks(&segments_chunks).unwrap().into_iter().enumerate()
	{
		for (j, chunk) in segment_chunks.iter().enumerate() {
			assert_eq!(&vector.segment.segments[i].segment_ec[j].0, chunk);
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
	if vector.work_package.chunks.len() > 0 {
		let r = erasure_coding::reconstruct(
			N_CHUNKS * 3,
			vector
				.work_package
				.chunks
				.iter()
				.enumerate()
				.filter(|(i, _)| in_range(*i, false))
				.map(|(i, c)| (ChunkIndex(i as u16), &c.0)),
			package_size,
		)
		.unwrap();
		assert_eq!(r, vector.data);
	}
	let mut decoder = erasure_coding::SubShardDecoder::new().unwrap();
	// not running segments in parallel (could be but simpler code here)
	for (seg_index, segment) in vector.segment.segments.iter().enumerate() {
		let r = decoder
			.reconstruct(
				&mut segment
					.segment_ec
					.iter()
					.enumerate()
					.filter(|(i, _)| in_range(*i, true))
					.map(|(i, c)| (seg_index as u8, ChunkIndex(i as u16), c.0)),
			)
			.unwrap();
		assert_eq!(r.1, 1);
		assert_eq!(r.0.len(), 1);
		assert_eq!(r.0[0].0, seg_index as u8);
		assert_eq!(r.0[0].1, segments_chunks[seg_index]);
	}

	let mut dest = PageProofs::default();
	build_segment_root(vector.data.as_slice(), &mut dest);
	assert_eq!(dest, vector.page_proof);
}
