//! Page proof for a sequence of segment, and other segment related constant.

use crate::SEGMENT_SIZE;
pub use blake2b_simd::State as InnerHasher;
use scale::{Decode, Encode};

fn hash_fn(data: &[u8]) -> blake2b_simd::Hash {
	blake2b_simd::Params::new().hash_length(32).hash(data)
}

const HASH_LEN: usize = 32;
type ErasureHash = [u8; HASH_LEN];
pub struct SegmentIndex(pub u16);

impl SegmentIndex {
	pub fn page_proof_index(&self) -> u16 {
		self.0 / PAGE_PROOF_SEGMENT_HASHES as u16
	}
}

/// Size of stored page proof.
/// TODO @cheme distributed is defined to be half of this, not too sure.
/// Note that we store both distributed data and middle nodes.
pub const PAGE_PROOF_SEGMENT_SIZE: usize = PAGE_PROOF_SEGMENT_HASHES * HASH_LEN * 2;

// half proof are cache of middle nodes
pub const PAGE_PROOF_SEGMENT_HASHES_SIZE: usize = PAGE_PROOF_SEGMENT_SIZE / 2;

pub const PAGE_PROOF_SEGMENT_HASHES: usize = 64;

/// Note that we got a bitmap of presence.
pub const SEGMENT_CHUNKS_GROUP_SIZE: usize =
	SEGMENT_CHUNKS_GROUPS * crate::SUBSHARD_SIZE + SEGMENT_CHUNKS_BITMAP_SIZE;

/// Number of chunks group in constent storage.
/// TODO @cheme this is not a think through number. just want it to be aligned with 8 for the
/// bitmap. Here rather smal, 272 for bigger
pub const SEGMENT_CHUNKS_GROUPS: usize = 136;

pub const SEGMENT_CHUNKS_BITMAP_SIZE: usize = SEGMENT_CHUNKS_GROUPS / 8;

// 2^11 segment grouped in 2^6 pages
pub const MAX_SEGMENT_PROOF_LEN: usize = 5;

// Max segments produced.
pub const MAX_NB_SEGMENTS: usize = 2048;

// Layout of binary tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Layout {
	// total number of segments
	nb_leafs: usize,
	// if we pad then this is the number of padded leafs.
	// Note that when padded we do hash against the zero hash, unpadded
	// variant do not.
	nb_leafs_aligned: Option<usize>,
}

impl Layout {
	pub(crate) fn new(nb_leafs: usize) -> Self {
		Self { nb_leafs, nb_leafs_aligned: Some(nb_leafs.next_power_of_two()) }
	}

	fn new_unpadded(nb_leafs: usize) -> Self {
		Self { nb_leafs, nb_leafs_aligned: None }
	}

	pub fn total_leafs(&self) -> usize {
		self.nb_leafs_aligned.unwrap_or(self.nb_leafs)
	}

	pub fn nb_leafs(&self) -> usize {
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
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MerklizedSegments {
	// This is a Binary Merkle Tree,
	// with index define as FullPageProof::offset_depth_const.
	// It contains middle nodes followed by page proof.
	pub tree: Vec<u8>,
	pub layout: Layout,
}

// TODO these might not be usefull.
// Should rather store pageproof?
impl Encode for MerklizedSegments {
	fn size_hint(&self) -> usize {
		let size_size = (self.layout.nb_leafs as u32).size_hint();
		let nb_nodes =
			Layout::nb_nodes_const(self.layout.nb_leafs, self.layout.nb_leafs_aligned.is_some());
		return size_size + nb_nodes * 32;
	}

	fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
		(self.layout.nb_leafs as u32).encode_to(dest);
		let nb_nodes =
			Layout::nb_nodes_const(self.layout.nb_leafs, self.layout.nb_leafs_aligned.is_some());
		dest.write(&self.tree[..nb_nodes * 32]);
	}

	fn encoded_size(&self) -> usize {
		self.size_hint()
	}
}

// Should rather store pageproof?
impl Decode for MerklizedSegments {
	fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
		let nb_leafs = u32::decode(input)? as usize;
		let layout = Layout::new(nb_leafs);
		let nb_nodes = Layout::nb_nodes_const(nb_leafs, layout.nb_leafs_aligned.is_some());
		let size = nb_nodes * 32;
		let mut tree = vec![0; size];
		input.read(&mut tree[..])?;
		Ok(MerklizedSegments { tree, layout })
	}
}

/// Contains list of all hashes from page proof.
pub struct PageProofs<'a>(pub &'a [u8]);

pub fn combine(left: &[u8], right: &[u8], dest: &mut [u8], aligned: bool) {
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

	pub fn valid_segment(&self, at: SegmentIndex, segment: &[u8; SEGMENT_SIZE]) -> bool {
		let depth = Layout::depth(self.layout.nb_leafs);
		let start = Layout::offset_depth_const(depth - 1) + at.0 as usize * 32;

		let hash = hash_fn(segment);
		if self.tree.len() < start + 32 {
			return false;
		}
		hash.as_bytes() == &self.tree[start..start + 32]
	}

	pub(crate) fn compute_inner(mut tree: Vec<u8>, layout: Layout) -> Self {
		let total_chunks = layout.nb_leafs;
		if total_chunks == 0 {
			let empty_root = [0u8; 32];
			return Self { tree: empty_root.to_vec(), layout }
		}
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

	pub(crate) fn add_subtree(&mut self, at: u16, hashes: &[u8], parent_proof: &[&[u8]]) -> bool {
		let single = parent_proof.is_empty();
		let nb_hashes = hashes.len() / 32;
		// this is implemented for align: hashes must be 2^n
		if hashes.len() % 32 != 0 {
			// TODO also check aligned
			return false;
		}
		if self.layout.nb_leafs_aligned.is_none() {
			return false;
		}
		if nb_hashes > 64 {
			return false;
		}
		if nb_hashes < 64 && !single {
			return false;
		}

		// TODO merge alog with the compute inner one
		let mut has_prev = false;
		let depth = Layout::depth(nb_hashes);
		let (mut nb, depth_parent, depth) = if single {
			let nb = nb_hashes.next_power_of_two();
			(nb, depth, depth)
		} else {
			let depth_parent = Layout::depth(self.layout.nb_leafs);
			(nb_hashes, depth_parent, depth)
		};

		let mut start = Layout::offset_depth_const(depth_parent - 1);
		let mut offset = at as usize * 64;
		let start_l = (start + offset) * 32;
		let end_l = start_l + hashes.len();
		self.tree[start_l..end_l].copy_from_slice(hashes);

		let tree = &mut self.tree;
		let mut check_buf = [0u8; 32];
		let mut rollback = [0usize; MAX_SEGMENT_PROOF_LEN];
		let mut rollback_len = 0;
		// feed all from hashes
		'a: for lvl in (1..depth_parent).rev() {
			let parent_start = Layout::offset_depth_const(lvl - 1);
			let mut i_parent = parent_start + offset / 2;
			if lvl <= depth_parent - depth {
				let i = start + offset;
				let sibling = parent_proof[parent_proof.len() - lvl];
				let (tree, parent) = if offset % 2 == 0 {
					rollback[rollback_len] = i;
					let (parent, tree) = tree.split_at_mut(i * 32);
					tree[32..64].copy_from_slice(sibling);
					(tree, parent)
				} else {
					rollback[rollback_len] = i - 1;
					let (parent, tree) = tree.split_at_mut((i - 1) * 32);
					tree[..32].copy_from_slice(sibling);
					(tree, parent)
				};
				rollback_len += 1;
				if parent[i_parent * 32..(i_parent + 1) * 32] == [0u8; 32] {
					combine(
						&tree[0..32],
						&tree[32..64],
						&mut parent[i_parent * 32..(i_parent + 1) * 32],
						true,
					);
				} else {
					// already a checked value
					combine(&tree[0..32], &tree[32..64], &mut check_buf, true);
					if check_buf == parent[i_parent * 32..(i_parent + 1) * 32] {
						break 'a;
					} else {
						if !single {
							for r in rollback.iter().take(rollback_len) {
								tree[r * 32..(r + 2) * 32].copy_from_slice(&[0u8; 64][..])
							}
							for j in start_l..end_l {
								self.tree[j] = 0;
							}
						}
						return false
					}
				}
			} else {
				// build from content
				for i in start + offset..start + offset + nb {
					if !has_prev {
						has_prev = true;
					} else {
						has_prev = false;
						let (parent, tree) = tree.split_at_mut((i - 1) * 32);
						if i_parent == depth_parent - depth &&
							parent[i_parent * 32..(i_parent + 1) * 32] != [0u8; 32]
						{
							// root from a sibling added
							combine(&tree[0..32], &tree[32..64], &mut check_buf, true);
							if check_buf == parent[i_parent * 32..(i_parent + 1) * 32] {
								break 'a;
							} else {
								if !single {
									for j in start_l..end_l {
										self.tree[j] = 0;
									}
								}
								return false;
							}
						} else {
							combine(
								&tree[0..32],
								&tree[32..64],
								&mut parent[i_parent * 32..(i_parent + 1) * 32],
								true,
							);
						}
						i_parent += 1;
					}
				}
				debug_assert!(!has_prev);
				nb /= 2;
			}
			offset /= 2;
			start = parent_start;
		}
		true
	}

	pub fn root(&self) -> &[u8] {
		&self.tree[0..32]
	}

	pub fn page_proof(&self) -> PageProofs {
		if let Some(al) = self.layout.nb_leafs_aligned {
			PageProofs(&self.tree[self.tree.len() - (al * 32)..])
		} else {
			PageProofs(&self.tree[self.tree.len() - (self.layout.nb_leafs * 32)..])
		}
	}

	pub fn contains_hash(&self, h1: &[u8]) -> bool {
		for h2 in self.tree.chunks(32) {
			if h1 == h2 {
				return true;
			}
		}
		false
	}

	pub fn from_page_proof(p: PageProofs, aligned: bool) -> Self {
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

	pub fn page_proof_proof<'a, 'b>(
		&'a self,
		buffer: &'b mut [&'a [u8]; MAX_SEGMENT_PROOF_LEN],
		at: u16,
	) -> &'b [&'a [u8]] {
		let nb_page = (((self.layout.nb_leafs - 1) / PAGE_PROOF_SEGMENT_HASHES) + 1) as u16;
		let depth_proof = if nb_page < 2 {
			0
		} else {
			// - 1 as root not needed (we check against the build one)
			16 - (nb_page - 1).leading_zeros() as usize
		};

		let field = Bitfield(at);
		let mut level_index = 0; // skip root
		for i in 0..depth_proof {
			let mut sibling = Layout::offset_depth_const(i + 1) + level_index;
			if !field.get_bit(depth_proof - 1 - i as usize) {
				// switch to right hash
				sibling += 1;
			} else {
				level_index += 1;
			}
			let e = depth_proof - 1 - i; // order of node in proof is from leaf
			buffer[e] = &self.tree[sibling * 32..(sibling + 1) * 32];
			level_index <<= 1;
		}
		&buffer[..depth_proof]
	}

	pub fn check_page_proof_root<'a, 'b>(
		&'a self,
		buffer: &'b mut [&'a [u8]; MAX_SEGMENT_PROOF_LEN],
		at: u16,
		root: &[u8],
	) -> bool {
		let proof = self.page_proof_proof(buffer, at);
		self.check_page_proof_proof(root, proof, at)
	}

	pub fn check_page_proof_proof(&self, page_proof_root: &[u8], proof: &[&[u8]], at: u16) -> bool {
		let nb_page = (((self.layout.nb_leafs - 1) / PAGE_PROOF_SEGMENT_HASHES) + 1) as u16;
		let depth_proof = if nb_page < 2 {
			0
		} else {
			// - 1 as root not needed (we check against the build one)
			16 - (nb_page - 1).leading_zeros() as usize
		};

		let field = Bitfield(at);
		let mut calc_root = page_proof_root;
		let mut hash_buff1 = [0u8; 32];
		hash_buff1.copy_from_slice(page_proof_root);
		let mut hash_buff2 = [0u8; 32];
		let mut odd = true;
		for i in (0..depth_proof).rev() {
			let e = depth_proof - 1 - i;
			let hash = &proof[e];
			let (hb, buff) =
				if odd { (&hash_buff1, &mut hash_buff2) } else { (&hash_buff2, &mut hash_buff1) };
			if field.get_bit(depth_proof - 1 - i as usize) {
				combine(hash, hb, buff, true);
			} else {
				combine(hb, hash, buff, true);
			}
			calc_root = buff;
			odd = !odd;
		}
		self.root() == calc_root
	}
}

struct Bitfield(u16);

impl Bitfield {
	/// Get the bit at the given index.
	pub fn get_bit(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}
}
