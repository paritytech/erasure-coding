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

fn bench_all(c: &mut Criterion) {
	const N_CHUNKS: u16 = 1023;
	const KB: usize = 1024;
	const MB: usize = 1024 * KB;
	const POV_SIZES: [usize; 3] = [128 * KB, MB, 5 * MB];

	let mut group = c.benchmark_group("construct");
	for pov_size in POV_SIZES {
		let pov = vec![0xfe; pov_size];
		let expected_root = erasure_root(N_CHUNKS, &pov);

		group.throughput(Throughput::Bytes(pov.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(pov_size), &N_CHUNKS, |b, &n| {
			b.iter(|| {
				let root = erasure_root(n, &pov);
				assert_eq!(root, expected_root);
			});
		});
	}
	group.finish();

	let mut group = c.benchmark_group("reconstruct_regular");
	for pov_size in POV_SIZES {
		let pov = vec![0xfe; pov_size];
		let all_chunks = chunks(N_CHUNKS, &pov);

		let chunks: Vec<_> = all_chunks
			.into_iter()
			.enumerate()
			.rev()
			.take(recovery_threshold(N_CHUNKS).unwrap() as _)
			.map(|(i, c)| (ChunkIndex::from(i as u16), c))
			.collect();

		group.throughput(Throughput::Bytes(pov.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(pov_size), &N_CHUNKS, |b, &n| {
			b.iter(|| {
				let _pov: Vec<u8> = reconstruct(n, chunks.clone(), pov.len()).unwrap();
			});
		});
	}
	group.finish();

	let mut group = c.benchmark_group("reconstruct_systematic");
	for pov_size in POV_SIZES {
		let pov = vec![0xfe; pov_size];
		let all_chunks = chunks(N_CHUNKS, &pov);

		let chunks = all_chunks
			.into_iter()
			.take(systematic_recovery_threshold(N_CHUNKS).unwrap() as _)
			.collect::<Vec<_>>();

		group.throughput(Throughput::Bytes(pov.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(pov_size), &N_CHUNKS, |b, &n| {
			b.iter(|| {
				let _pov: Vec<u8> =
					reconstruct_from_systematic(n, chunks.clone(), pov.len()).unwrap();
			});
		});
	}
	group.finish();

	let mut group = c.benchmark_group("merklize");
	for pov_size in POV_SIZES {
		let pov = vec![0xfe; pov_size];
		let all_chunks = chunks(N_CHUNKS, &pov);

		group.throughput(Throughput::Bytes(pov.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(pov_size), &N_CHUNKS, |b, _| {
			b.iter(|| {
				let iter = MerklizedChunks::compute(all_chunks.clone());
				let n = iter.collect::<Vec<_>>().len();
				assert_eq!(n, all_chunks.len());
			});
		});
	}
	group.finish();

	let mut group = c.benchmark_group("verify_chunk");
	for pov_size in POV_SIZES {
		let pov = vec![0xfe; pov_size];
		let all_chunks = chunks(N_CHUNKS, &pov);
		let merkle = MerklizedChunks::compute(all_chunks);
		let root = merkle.root();
		let chunks: Vec<_> = merkle.collect();
		let chunk = chunks[N_CHUNKS as usize / 2].clone();

		group.throughput(Throughput::Bytes(pov.len() as u64));
		group.bench_with_input(BenchmarkId::from_parameter(pov_size), &N_CHUNKS, |b, _| {
			b.iter(|| {
				assert!(chunk.verify(&root));
			});
		});
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
