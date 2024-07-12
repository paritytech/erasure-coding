use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use erasure_coding::*;
use std::time::Duration;

fn chunks(n_chunks: u16, pov: &[u8]) -> Vec<Vec<u8>> {
	construct_chunks(n_chunks, pov).unwrap()
}

fn erasure_root(n_chunks: u16, pov: &[u8]) -> ErasureRoot {
	let chunks = chunks(n_chunks, pov);
	MerklizedChunks::compute(chunks).root()
}

struct BenchParam {
	pov_size: usize,
	n_chunks: u16,
}

impl std::fmt::Display for BenchParam {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		write!(f, "PoV: {} Chunks: {}", self.pov_size, self.n_chunks)
	}
}

fn bench_all(c: &mut Criterion) {
	const KB: usize = 1024;
	const MB: usize = 1024 * KB;
	const POV_SIZES: [usize; 3] = [128 * KB, MB, 5 * MB];
	const N_CHUNKS: [u16; 2] = [1023, 1024];

	let mut group = c.benchmark_group("construct");
	for pov_size in POV_SIZES {
		for n_chunks in N_CHUNKS {
			let param = BenchParam { pov_size, n_chunks };
			let pov = vec![0xfe; pov_size];
			let expected_root = erasure_root(n_chunks, &pov);

			group.throughput(Throughput::Bytes(pov.len() as u64));
			group.bench_with_input(BenchmarkId::from_parameter(param), &n_chunks, |b, &n| {
				b.iter(|| {
					let root = erasure_root(n, &pov);
					assert_eq!(root, expected_root);
				});
			});
		}
	}
	group.finish();

	let mut group = c.benchmark_group("reconstruct_regular");
	for pov_size in POV_SIZES {
		for n_chunks in N_CHUNKS {
			let param = BenchParam { pov_size, n_chunks };
			let pov = vec![0xfe; pov_size];
			let all_chunks = chunks(n_chunks, &pov);

			let chunks: Vec<_> = all_chunks
				.into_iter()
				.enumerate()
				.rev()
				.take(recovery_threshold(n_chunks).unwrap() as _)
				.map(|(i, c)| (ChunkIndex::from(i as u16), c))
				.collect();

			group.throughput(Throughput::Bytes(pov.len() as u64));
			group.bench_with_input(BenchmarkId::from_parameter(param), &n_chunks, |b, &n| {
				b.iter(|| {
					let _pov: Vec<u8> = reconstruct(n, chunks.clone(), pov.len()).unwrap();
				});
			});
		}
	}
	group.finish();

	let mut group = c.benchmark_group("reconstruct_systematic");
	for pov_size in POV_SIZES {
		for n_chunks in N_CHUNKS {
			let param = BenchParam { pov_size, n_chunks };
			let pov = vec![0xfe; pov_size];
			let all_chunks = chunks(n_chunks, &pov);

			let chunks = all_chunks
				.into_iter()
				.take(systematic_recovery_threshold(n_chunks).unwrap() as _)
				.collect::<Vec<_>>();

			group.throughput(Throughput::Bytes(pov.len() as u64));
			group.bench_with_input(BenchmarkId::from_parameter(param), &n_chunks, |b, &n| {
				b.iter(|| {
					let _pov: Vec<u8> = reconstruct_from_systematic(
						n,
						chunks.len(),
						&mut chunks.iter().map(Vec::as_slice),
						pov.len(),
					)
					.unwrap();
				});
			});
		}
	}
	group.finish();

	let mut group = c.benchmark_group("merklize");
	for pov_size in POV_SIZES {
		for n_chunks in N_CHUNKS {
			let param = BenchParam { pov_size, n_chunks };
			let pov = vec![0xfe; pov_size];
			let all_chunks = chunks(n_chunks, &pov);

			group.throughput(Throughput::Bytes(pov.len() as u64));
			group.bench_with_input(BenchmarkId::from_parameter(param), &n_chunks, |b, _| {
				b.iter(|| {
					let iter = MerklizedChunks::compute(all_chunks.clone());
					let n = iter.collect::<Vec<_>>().len();
					assert_eq!(n, all_chunks.len());
				});
			});
		}
	}
	group.finish();

	let mut group = c.benchmark_group("verify_chunk");
	for pov_size in POV_SIZES {
		for n_chunks in N_CHUNKS {
			let param = BenchParam { pov_size, n_chunks };
			let pov = vec![0xfe; pov_size];
			let all_chunks = chunks(n_chunks, &pov);
			let merkle = MerklizedChunks::compute(all_chunks);
			let root = merkle.root();
			let chunks: Vec<_> = merkle.collect();
			let chunk = chunks[n_chunks as usize / 2].clone();

			group.throughput(Throughput::Bytes(pov.len() as u64));
			group.bench_with_input(BenchmarkId::from_parameter(param), &n_chunks, |b, _| {
				b.iter(|| {
					assert!(chunk.verify(&root));
				});
			});
		}
	}
	group.finish();
}

fn criterion_config() -> Criterion {
	Criterion::default()
		.sample_size(15)
		.warm_up_time(Duration::from_millis(200))
		.measurement_time(Duration::from_secs(5))
}

criterion_group!(
	name = all;
	config = criterion_config();
	targets = bench_all,
);
criterion_main!(all);
