#![no_main]

use erasure_coding::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (Vec<u8>, u16)| {
    let n_chunks = data.1.max(2).min(2048);
    let data = data.0;
    if data.is_empty() || data.len() > 1 * 1024 * 1024 {
        return;
    }
    let chunks = construct_chunks(n_chunks, &data).unwrap();
    assert_eq!(chunks.len() as u16, n_chunks);

    let iter = ErasureRootAndProofs::from(chunks.clone());
    let root = iter.root();
    let erasure_chunks: Vec<_> = iter.collect();

    assert_eq!(erasure_chunks.len(), chunks.len());

    for erasure_chunk in erasure_chunks.into_iter() {
        assert!(erasure_chunk.verify(&root));
    }
});
