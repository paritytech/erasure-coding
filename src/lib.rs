//! This library provides methods for encoding the data into chunks and
//! reconstructing the original data from chunks as well as verifying
//! individual chunks against an erasure root.

mod error;
mod merklize;

pub use self::error::Error;
pub use self::merklize::{ErasureRoot, ErasureRootAndProofs, Proof};

use novelpoly::{CodeParams, WrappedShard};
use scale::{Decode, Encode};
use std::ops::AddAssign;

// We are limited to the field order of GF(2^16), which is 65536.
const MAX_CHUNKS: usize = novelpoly::f2e16::FIELD_SIZE;

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
    if n_chunks as usize > MAX_CHUNKS {
        return Err(Error::TooManyTotalChunks);
    }
    if n_chunks <= 1 {
        return Err(Error::NotEnoughTotalChunks);
    }

    let needed = n_chunks.saturating_sub(1) / 3;
    Ok(needed + 1)
}

/// Obtain the threshold of systematic chunks that should be enough to recover the data.
///
/// If the regular `recovery_threshold` is a power of two, then it returns the same value.
/// Otherwise, it returns the next lower power of two.
pub fn systematic_recovery_threshold(n_chunks: u16) -> Result<u16, Error> {
    code_params(n_chunks).map(|params| params.k() as u16)
}

fn code_params(n_chunks: u16) -> Result<CodeParams, Error> {
    let n_wanted = n_chunks;
    let k_wanted = recovery_threshold(n_wanted)?;

    if n_wanted as usize > MAX_CHUNKS {
        return Err(Error::TooManyTotalChunks);
    }

    let params = CodeParams::derive_parameters(n_wanted as usize, k_wanted as usize)?;
    Ok(params)
}

/// Reconstruct the available data from the set of systematic chunks.
///
/// Provide a vector containing the first k chunks in order. If too few chunks are provided,
/// recovery is not possible.
pub fn reconstruct_from_systematic<T: Decode>(
    n_chunks: u16,
    systematic_chunks: Vec<&[u8]>,
) -> Result<T, Error> {
    let code_params = code_params(n_chunks)?;
    let k = code_params.k();

    for chunk_data in systematic_chunks.iter().take(k) {
        if chunk_data.len() % 2 != 0 {
            return Err(Error::UnevenLength);
        }
    }

    let Some(first_shard) = systematic_chunks.first() else {
        return Err(Error::NotEnoughChunks);
    };
    let shard_len = first_shard.len();
    if shard_len % 2 != 0 {
        return Err(Error::UnevenLength);
    }

    let bytes = code_params.make_encoder().reconstruct_from_systematic(
        systematic_chunks
            .into_iter()
            .take(k)
            .map(|data| WrappedShard::new(data.to_vec()))
            .collect(),
    )?;

    Decode::decode(&mut &bytes[..]).map_err(|err| Error::Decode(err))
}

/// Construct erasure-coded chunks.
///
/// Works only for 2..65536 chunks.
/// The data must be non-empty.
pub fn construct_chunks<T: Encode>(n_chunks: u16, data: &T) -> Result<Vec<Vec<u8>>, Error> {
    let params = code_params(n_chunks)?;
    let encoded = data.encode();

    if encoded.is_empty() {
        return Err(Error::BadPayload);
    }

    let shards = params
        .make_encoder()
        .encode::<WrappedShard>(&encoded[..])
        .expect("Payload non-empty, shard sizes are uniform, and validator numbers checked; qed");

    Ok(shards
        .into_iter()
        .map(|w: WrappedShard| w.into_inner())
        .collect())
}

/// Reconstruct decodable data from a set of chunks.
///
/// Provide an iterator containing chunk data and the corresponding index.
/// The indices of the present chunks must be indicated. If too few chunks
/// are provided, recovery is not possible.
///
/// Works only for 2..65536 chunks.
pub fn reconstruct<'a, I: 'a, T: Decode>(n_chunks: u16, chunks: I) -> Result<T, Error>
where
    I: IntoIterator<Item = (&'a [u8], usize)>,
{
    let params = code_params(n_chunks)?;
    let n = n_chunks as usize;
    let mut received_shards: Vec<Option<WrappedShard>> = vec![None; n];
    for (chunk_data, chunk_idx) in chunks.into_iter().take(n) {
        if chunk_data.len() % 2 != 0 {
            return Err(Error::UnevenLength);
        }

        if chunk_idx >= n {
            return Err(Error::ChunkIndexOutOfBounds {
                chunk_index: chunk_idx,
                n_chunks: n,
            });
        }

        received_shards[chunk_idx] = Some(WrappedShard::new(chunk_data.to_vec()));
    }

    let payload_bytes = params.make_encoder().reconstruct(received_shards)?;

    Decode::decode(&mut &payload_bytes[..]).map_err(|err| Error::Decode(err))
}

#[cfg(test)]
mod tests {
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
            let n_chunks = n_chunks.max(2);
            let threshold = systematic_recovery_threshold(n_chunks).unwrap();
            let chunks = construct_chunks(n_chunks, &available_data.0).unwrap();
            let reconstructed: Vec<u8> = reconstruct_from_systematic(
                n_chunks,
                chunks
                    .iter()
                    .take(threshold as usize)
                    .map(|v| &v[..])
                    .collect(),
            )
            .unwrap();
            assert_eq!(reconstructed, available_data.0);
        }

        QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
    }

    #[test]
    fn round_trip_works() {
        fn property(available_data: ArbitraryAvailableData, n_chunks: u16) {
            let n_chunks = n_chunks.max(2);
            let threshold = recovery_threshold(n_chunks).unwrap();
            let chunks = construct_chunks(n_chunks, &available_data.0).unwrap();
            // take the last `threshold` chunks
            let last_chunks: Vec<(&[u8], usize)> = chunks
                .iter()
                .enumerate()
                .rev()
                .take(threshold as usize)
                .map(|(i, v)| (&v[..], i))
                .collect();
            let reconstructed: Vec<u8> = reconstruct(n_chunks, last_chunks).unwrap();
            assert_eq!(reconstructed, available_data.0);
        }

        QuickCheck::new().quickcheck(property as fn(ArbitraryAvailableData, u16))
    }

    #[test]
    fn proof_verification_works() {
        fn property(data: SmallAvailableData, n_chunks: u16) {
            let n_chunks = n_chunks.max(2).min(2048);
            let chunks = construct_chunks(n_chunks, &data.0).unwrap();
            assert_eq!(chunks.len() as u16, n_chunks);

            let iter = ErasureRootAndProofs::from(chunks.clone());
            let root = iter.root();
            let erasure_chunks: Vec<_> = iter.collect();

            assert_eq!(erasure_chunks.len(), chunks.len());

            for erasure_chunk in erasure_chunks.into_iter() {
                let encode = Encode::encode(&erasure_chunk.proof);
                let decode = Decode::decode(&mut &encode[..]).unwrap();
                assert_eq!(erasure_chunk.proof, decode);
                assert_eq!(encode, Encode::encode(&decode));

                assert_eq!(
                    &erasure_chunk.chunk,
                    &chunks[erasure_chunk.index.0 as usize]
                );

                assert!(erasure_chunk.verify(&root));
            }
        }

        QuickCheck::new().quickcheck(property as fn(SmallAvailableData, u16))
    }
}
