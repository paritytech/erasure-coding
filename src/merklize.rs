use std::collections::VecDeque;

use crate::{ChunkIndex, ErasureChunk, Error};
use bounded_collections::{BoundedVec, ConstU32};
use scale::{Decode, Encode};

use blake3::{hash as hash_fn, Hash as InnerHash, Hasher as InnerHasher};

// Binary Merkle Tree with 16-bit `ChunkIndex` has depth at most 17.
// The proof has at most `depth - 1` length.
const MAX_MERKLE_PROOF_DEPTH: u32 = 16;

/// The root of the erasure chunks that can be used to verify chunk proofs.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct ErasureRoot(Hash);

impl From<Hash> for ErasureRoot {
	fn from(hash: Hash) -> Self {
		ErasureRoot(hash)
	}
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Encode, Decode, Default)]
struct Hash([u8; 32]);

impl From<InnerHash> for Hash {
	fn from(hash: InnerHash) -> Self {
		Hash(hash.into())
	}
}

/// Proof of an erasure chunk which can be verified against [`ErasureRoot`].
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct Proof(BoundedVec<(Hash, Direction), ConstU32<MAX_MERKLE_PROOF_DEPTH>>);

impl TryFrom<MerklePath> for Proof {
	type Error = Error;

	fn try_from(input: MerklePath) -> Result<Self, Self::Error> {
		Ok(Proof(BoundedVec::try_from(input).map_err(|_| Error::TooLargeProof)?))
	}
}

/// Yields all erasure chunks as an iterator.
pub struct ErasureRootAndProofs {
	root: ErasureRoot,
	data: VecDeque<Vec<u8>>,
	// This is a Binary Merkle Tree,
	// where each level is a vector of hashes starting from leaves.
	// ```
	// 0 -> [c, d, e, Hash::zero()]
	// 1 -> [a = hash(c, d), b = hash(e, Hash::zero())]
	// 2 -> hash(a, b)
	// ```
	// Levels are guaranteed to have a power of 2 elements.
	// Leaves might be padded with `Hash::zero()`.
	tree: Vec<Vec<Hash>>,
	// Used by the iterator implementation.
	current_index: ChunkIndex,
}

// This is what is actually stored in a `Proof`.
type MerklePath = Vec<(Hash, Direction)>;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Encode, Decode)]
enum Direction {
	Left = 0,
	Right = 1,
}

impl ErasureRootAndProofs {
	/// Get the erasure root.
	pub fn root(&self) -> ErasureRoot {
		self.root.clone()
	}
}

impl Iterator for ErasureRootAndProofs {
	type Item = ErasureChunk;

	fn next(&mut self) -> Option<Self::Item> {
		let chunk = self.data.pop_front()?;
		let d = self.tree.len() - 1;
		let idx = self.current_index.0;
		let mut index = idx as usize;
		let mut path = Vec::with_capacity(d);
		for i in 0..d {
			let layer = &self.tree[i];
			if index % 2 == 0 {
				path.push((layer[index + 1], Direction::Right));
			} else {
				path.push((layer[index - 1], Direction::Left));
			}
			index /= 2;
		}
		self.current_index += 1;
		Some(ErasureChunk {
			chunk,
			proof: Proof::try_from(path).expect("the path is limited by tree depth; qed"),
			index: ChunkIndex(idx),
		})
	}
}

/// # Panics
///
/// If `chunks` is empty.
impl From<Vec<Vec<u8>>> for ErasureRootAndProofs {
	fn from(chunks: Vec<Vec<u8>>) -> Self {
		assert!(!chunks.is_empty(), "must have at least one chunk");

		let mut hashes: Vec<Hash> = chunks
			.iter()
			.map(|chunk| {
				let hash = hash_fn(chunk);
				Hash::from(hash)
			})
			.collect();
		hashes.resize(chunks.len().next_power_of_two(), Hash::default());

		let depth = hashes.len().ilog2() as usize + 1;
		let mut tree = vec![Vec::new(); depth];
		tree[0] = hashes;

		// Build the tree bottom-up.
		(1..depth).for_each(|lvl| {
			let len = 2usize.pow((depth - 1 - lvl) as u32);
			tree[lvl].resize(len, Hash::default());

			// NOTE: This can be parallelized.
			(0..len).for_each(|i| {
				let prev = &tree[lvl - 1];

				let hash = combine(prev[2 * i], prev[2 * i + 1]);

				tree[lvl][i] = hash;
			});
		});

		assert!(tree[tree.len() - 1].len() == 1, "root must be a single hash");

		Self {
			root: ErasureRoot::from(tree[tree.len() - 1][0]),
			data: chunks.into(),
			tree,
			current_index: ChunkIndex::from(0),
		}
	}
}

fn combine(left: Hash, right: Hash) -> Hash {
	let mut hasher = InnerHasher::new();

	hasher.update(left.0.as_slice());
	hasher.update(right.0.as_slice());

	Hash::from(hasher.finalize())
}

impl ErasureChunk {
	/// Verify the proof of the chunk against the erasure root and index.
	pub fn verify(&self, root: &ErasureRoot) -> bool {
		self.verify_index() && self.verify_root(root)
	}

	/// Verify the proof of the chunk against the erasure root.
	pub fn verify_root(&self, root: &ErasureRoot) -> bool {
		let leaf_hash = Hash::from(hash_fn(&self.chunk));

		let root_hash =
			self.proof.0.iter().fold(leaf_hash, |acc, (hash, direction)| match direction {
				Direction::Left => combine(*hash, acc),
				Direction::Right => combine(acc, *hash),
			});

		root_hash == root.0
	}

	/// Verify the index of the chunk against the proof.
	/// This check is relatively cheap.
	pub fn verify_index(&self) -> bool {
		let (index, _tree_depth) =
			self.proof.0.iter().fold((0u16, 0), |acc, (_, direction)| match direction {
				Direction::Left => (acc.0 | (1 << acc.1), acc.1 + 1),
				Direction::Right => (acc.0, acc.1 + 1),
			});

		index == self.index.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn iter_works() {
		let chunks = vec![vec![1], vec![2], vec![3]];
		let iter = ErasureRootAndProofs::from(chunks.clone());
		let root = iter.root();
		let erasure_chunks: Vec<ErasureChunk> = iter.collect();
		assert_eq!(erasure_chunks.len(), chunks.len());

		// compute the proof manually
		let proof_0 = {
			let a0 = hash_fn(&chunks[0]).into();
			let a1 = hash_fn(&chunks[1]).into();
			let a2 = hash_fn(&chunks[2]).into();
			let a3 = Hash::default();

			let b0 = combine(a0, a1);
			let b1 = combine(a2, a3);

			let c0 = combine(b0, b1);

			assert_eq!(c0, root.0);

			let p = vec![(a1, Direction::Right), (b1, Direction::Right)];
			Proof::try_from(p).unwrap()
		};

		assert_eq!(erasure_chunks[0].proof, proof_0);

		for chunk in erasure_chunks {
			assert!(chunk.verify_index());
			assert!(chunk.verify_root(&root));
		}
	}
}
