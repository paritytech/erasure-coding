use thiserror::Error;

/// Errors in erasure coding.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Error)]
pub enum Error {
	#[error("There are too many chunks in total")]
	TooManyTotalChunks,
	#[error("Expected at least 1 chunk")]
	NotEnoughTotalChunks,
	#[error("Not enough chunks to reconstruct message")]
	NotEnoughChunks,
	#[error("Chunks are not uniform, mismatch in length or are zero sized")]
	NonUniformChunks,
	#[error("Uneven length is not valid for field GF(2^16)")]
	UnevenLength,
	#[error("Chunk is out of bounds: {chunk_index} not included in 0..{n_chunks}")]
	ChunkIndexOutOfBounds { chunk_index: u16, n_chunks: u16 },
	#[error("Reconstructed payload invalid")]
	BadPayload,
	#[error("Invalid chunk proof")]
	InvalidChunkProof,
	#[error("The proof is too large")]
	TooLargeProof,
	#[error("An unknown error has appeared when reconstructing erasure code chunks")]
	UnknownReconstruction,
	#[error("An unknown error has appeared when deriving code parameters from validator count")]
	UnknownCodeParam,
}

impl From<novelpoly::Error> for Error {
	fn from(error: novelpoly::Error) -> Self {
		match error {
			novelpoly::Error::NeedMoreShards { .. } => Self::NotEnoughChunks,
			novelpoly::Error::ParamterMustBePowerOf2 { .. } => Self::UnevenLength,
			novelpoly::Error::WantedShardCountTooHigh(_) => Self::TooManyTotalChunks,
			novelpoly::Error::WantedShardCountTooLow(_) => Self::NotEnoughTotalChunks,
			novelpoly::Error::PayloadSizeIsZero { .. } => Self::BadPayload,
			novelpoly::Error::InconsistentShardLengths { .. } => Self::NonUniformChunks,
			_ => Self::UnknownReconstruction,
		}
	}
}
