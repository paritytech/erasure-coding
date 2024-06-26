//! Page proof for a sequence of segment, and other segment related constant.

pub use blake2b_simd::State as InnerHasher;
use erasure_coding::SEGMENT_SIZE;

pub fn hash_fn(data: &[u8]) -> blake2b_simd::Hash {
	blake2b_simd::Params::new().hash_length(32).hash(data)
}

const HASH_LEN: usize = 32;
pub type ErasureHash = [u8; HASH_LEN];
pub struct SegmentIndex(u16);

/// Size of stored page proof.
/// TODO @cheme distributed is defined to be half of this, not too sure.
/// Note that we store both distributed data and middle nodes.
pub const PAGE_PROOF_SEGMENT_SIZE: usize = PAGE_PROOF_SEGMENT_HASHES * HASH_LEN * 2;

// half proof are cache of middle nodes
pub const PAGE_PROOF_SEGMENT_DISTRIBUTED_SIZE: usize = PAGE_PROOF_SEGMENT_SIZE / 2;

pub const PAGE_PROOF_SEGMENT_HASHES: usize = 64;

/// Note that we got a bitmap of presence.
pub const SEGMENT_CHUNKS_GROUP_SIZE: usize =
	SEGMENT_CHUNKS_GROUPS * erasure_coding::SUBSHARD_SIZE + SEGMENT_CHUNKS_BITMAP_SIZE;

/// Number of chunks group in constent storage.
/// TODO @cheme this is not a think through number. just want it to be aligned with 8 for the
/// bitmap. Here rather smal, 272 for bigger
pub const SEGMENT_CHUNKS_GROUPS: usize = 136;

pub const SEGMENT_CHUNKS_BITMAP_SIZE: usize = SEGMENT_CHUNKS_GROUPS / 8;

// Layout of binary tree
pub struct Layout {
	// total number of segments
	nb_leafs: usize,
	// if we pad then this is the number of padded leafs.
	// Note that when padded we do hash against the zero hash, unpadded
	// variant do not.
	nb_leafs_aligned: Option<usize>,
}

impl Layout {
	pub fn new(nb_leafs: usize) -> Self {
		Self { nb_leafs, nb_leafs_aligned: Some(nb_leafs.next_power_of_two()) }
	}

	pub fn new_unpadded(nb_leafs: usize) -> Self {
		Self { nb_leafs, nb_leafs_aligned: None }
	}

	pub fn total_leafs(&self) -> usize {
		self.nb_leafs
	}

	pub const fn page_proof_size_const(nb: usize) -> usize {
		nb * HASH_LEN
	}

	pub fn page_proof_size(&self) -> usize {
		Self::page_proof_size_const(self.total_leafs())
	}

	// proof related
	pub const fn nb_nodes_const(size: usize, aligned: bool) -> usize {
		if aligned {
			Self::offset_leaves_const(size.next_power_of_two(), size.next_power_of_two())
		} else {
			Self::offset_leaves_const(size, size)
		}
	}

	// Note layout can be optimize, here we store all depth with all null hash except the last one.
	pub const fn offset_leaves_const(size: usize, at: usize) -> usize {
		size.next_power_of_two() - 1 + at
	}

	pub const fn depth(size: usize) -> usize {
		if size == 0 {
			return 0;
		}
		(usize::BITS as usize - (size - 1).leading_zeros() as usize) + 1
	}

	pub const fn offset_depth_const(depth: usize) -> usize {
		(1 << depth) - 1
	}
}

/// All merkle info for chunks.
pub struct MerklizedSegments {
	layout: Layout,
	// This is a Binary Merkle Tree,
	// with index define as FullPageProof::offset_depth_const.
	// It contains middle nodes followed by page proof.
	pub(crate) tree: Vec<u8>,
}

/// Contains only bytes to distirbute (hash of all segments).
pub struct PageProof<'a>(&'a [u8]);

fn combine(left: &[u8], right: &[u8], dest: &mut [u8], aligned: bool) {
	debug_assert!(aligned || left != &[0; 32]);
	debug_assert!(aligned || right != &[0; 32]);
	debug_assert!(left.len() == 32);
	debug_assert!(right.len() == 32);
	let mut hasher = InnerHasher::new();

	hasher.update(left);
	hasher.update(right);

	let inner_hash = hasher.finalize();

	dest.copy_from_slice(&inner_hash.as_bytes()[..32]);
}

impl MerklizedSegments {
	/// Compute `MerklizedChunks` from a list of erasure chunks.
	pub fn compute<'a, I>(
		total_chunks: usize,
		aligned: bool,
		already_hashed: bool,
		chunks: I,
	) -> Self
	where
		I: Iterator<Item = &'a [u8]>,
	{
		let layout =
			if aligned { Layout::new(total_chunks) } else { Layout::new_unpadded(total_chunks) };
		// Note that for aligned we could skip allocating the 0 nodes and check access.
		let nb_nodes = Layout::nb_nodes_const(total_chunks, layout.nb_leafs_aligned.is_some());
		// aligned.
		let mut tree = vec![0; nb_nodes * 32];
		let offset_leaves = Layout::offset_leaves_const(total_chunks, 0);
		for (i, chunk) in chunks.enumerate() {
			let hashed;
			let hash = if already_hashed {
				&chunk[..32]
			} else {
				hashed = hash_fn(chunk);
				&hashed.as_bytes()[..32]
			};
			tree[(offset_leaves + i) * 32..(offset_leaves + i + 1) * 32].copy_from_slice(hash);
		}
		Self::compute_inner(tree, layout)
	}

	fn compute_inner(mut tree: Vec<u8>, layout: Layout) -> Self {
		let total_chunks = layout.nb_leafs;
		let nb_nodes = Layout::nb_nodes_const(total_chunks, layout.nb_leafs_aligned.is_some());
		let depth = Layout::depth(total_chunks);
		let mut bound = nb_nodes;
		let mut has_prev = false;
		let mut start = Layout::offset_depth_const(depth - 1);
		// Build the tree bottom-up.
		for lvl in (1..depth).rev() {
			let parent_start = Layout::offset_depth_const(lvl - 1);
			let mut i_parent = parent_start;
			for i in start..bound {
				if !has_prev {
					has_prev = true;
				} else {
					has_prev = false;
					let (parent, tree) = tree.split_at_mut((i - 1) * 32);
					combine(
						&tree[0..32],
						&tree[32..64],
						&mut parent[i_parent * 32..(i_parent + 1) * 32],
						layout.nb_leafs_aligned.is_some(),
					);
					i_parent += 1;
				}
			}

			// TODO @cheme: note that this assumes hash(h, 0) = h. TODO check that
			// otherwhise lot of usless work
			if layout.nb_leafs_aligned.is_none() && has_prev {
				// last orphan node
				// unaligned
				let par = i_parent * 32;
				let chil = (bound - 1) * 32;
				let (parent, children) = tree.split_at_mut(chil);
				parent[par..par + 32].copy_from_slice(&children[..32]);
				i_parent += 1;
			}
			has_prev = false;
			bound = i_parent;
			start = parent_start;
		}
		Self { tree, layout }
	}

	pub fn root(&self) -> &[u8] {
		&self.tree[0..32]
	}

	pub fn page_proof(&self) -> PageProof {
		if let Some(al) = self.layout.nb_leafs_aligned {
			let padd = (al - self.layout.nb_leafs) * 32;
			PageProof(
				&self.tree[self.tree.len() - self.layout.nb_leafs - (al * 32)..
					self.tree.len() - self.layout.nb_leafs - (padd * 32)],
			)
		} else {
			PageProof(&self.tree[self.tree.len() - (self.layout.nb_leafs * 32)..])
		}
	}

	pub fn from_page_proof(p: PageProof, aligned: bool) -> Self {
		let total_chunks = p.0.len();
		let layout =
			if aligned { Layout::new(total_chunks) } else { Layout::new_unpadded(total_chunks) };
		let nb_nodes = Layout::nb_nodes_const(total_chunks, aligned);
		let mut tree = vec![0; nb_nodes * 32];
		let offset_leaves = Layout::offset_leaves_const(total_chunks, 0);
		assert!(p.0.len() == nb_nodes * 32);
		let s = offset_leaves * 32;
		tree[s..s + p.0.len()].copy_from_slice(p.0);
		Self::compute_inner(tree, layout)
	}

	pub fn check_chunk(
		&self,
		root: &ErasureHash,
		chunk: &[u8; SEGMENT_SIZE],
		chunk_index: SegmentIndex,
	) -> bool {
		if chunk_index.0 as usize >= self.layout.total_leafs() {
			return false;
		}
		if root.as_slice() != &self.tree[..32] {
			return false;
		}
		let hash = hash_fn(chunk);
		let mut h = ErasureHash::default();
		h.as_mut_slice().copy_from_slice(&hash.as_bytes()[..HASH_LEN]);
		self.check_chunk_hash(&h, chunk_index)
	}

	fn check_chunk_hash(&self, chunk_hash: &ErasureHash, chunk_index: SegmentIndex) -> bool {
		let chunk_index = chunk_index.0 as usize;
		let total_chunks = self.layout.total_leafs();
		if chunk_index >= total_chunks {
			return false;
		}
		let ix = Layout::offset_leaves_const(total_chunks, chunk_index);
		&self.tree[ix * 32..(ix + 1) * 32] == chunk_hash.as_slice()
	}
}

/// All merkle info for chunks.
pub struct MerklizedChunksIter<'a> {
	chunks: &'a MerklizedSegments,
	current_index: SegmentIndex,
}
