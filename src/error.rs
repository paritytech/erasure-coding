use thiserror::Error;

/// Errors in erasure coding.
#[derive(Debug, Clone, PartialEq, Error)]
#[non_exhaustive]
pub enum Error {
	#[error("There are too many chunks in total")]
	TooManyTotalChunks,
	#[error("Expected at least 1 chunk")]
	NotEnoughTotalChunks,
	#[error("Not enough chunks to reconstruct message")]
	NotEnoughChunks,
	#[error("Chunks are not uniform, mismatch in length or are zero sized")]
	NonUniformChunks,
	#[error("Unaligned chunk length")]
	UnalignedChunk,
	#[error("Chunk is out of bounds: {chunk_index} not included in 0..{n_chunks}")]
	ChunkIndexOutOfBounds { chunk_index: u16, n_chunks: u16 },
	#[error("Reconstructed payload invalid")]
	BadPayload,
	#[error("Invalid chunk proof")]
	InvalidChunkProof,
	#[error("The proof is too large")]
	TooLargeProof,
	#[error("An unknown error has appeared when (re)constructing erasure code chunks")]
	Unknown,
}

impl From<reed_solomon::Error> for Error {
	fn from(error: reed_solomon::Error) -> Self {
		use reed_solomon::Error::*;

		match error {
			NotEnoughShards { .. } => Self::NotEnoughChunks,
			InvalidShardSize { .. } => Self::UnalignedChunk,
			TooManyOriginalShards { .. } => Self::TooManyTotalChunks,
			TooFewOriginalShards { .. } => Self::NotEnoughTotalChunks,
			DifferentShardSize { .. } => Self::NonUniformChunks,
			_ => Self::Unknown,
		}
	}
}
