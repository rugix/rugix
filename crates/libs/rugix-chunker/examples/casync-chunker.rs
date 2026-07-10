use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use byte_calc::ByteLen;
use byte_calc::NumBytes;

use rugix_chunker::casync::CasyncChunker;
use rugix_chunker::Chunker;
use si_crypto_hashes::HashAlgorithm;

/// Command line arguments.
#[derive(Debug, Parser)]
pub struct Args {
    /// Hash algorithm to use for hashing chunks.
    algorithm: HashAlgorithm,
    /// File to chunk.
    file: PathBuf,
}

pub fn main() {
    let args = Args::parse();
    let mut chunk_offset = NumBytes::ZERO;
    let mut chunk_size = NumBytes::ZERO;
    let mut chunk_hasher = args.algorithm.hasher();
    let mut reader = BufReader::new(std::fs::File::open(&args.file).unwrap());
    let mut chunker = CasyncChunker::default();
    loop {
        let buffer = reader.fill_buf().unwrap();
        let offset = chunker
            .scan(buffer)
            .or_else(|| if buffer.is_empty() { Some(0) } else { None });
        chunk_hasher.update(&buffer[..offset.unwrap_or(buffer.len())]);
        let consume = if let Some(offset) = offset {
            chunk_size += NumBytes::expect_from_usize(
                offset,
                "offset into an in-memory buffer always fits into u64",
            );
            let chunk_digest = std::mem::replace(&mut chunk_hasher, args.algorithm.hasher())
                .finalize::<Arc<[u8]>>();
            println!("Offset: {chunk_offset:#}, Size: {chunk_size:#}, Hash: {chunk_digest}");
            chunk_offset += chunk_size;
            chunk_size = NumBytes::ZERO;
            if buffer.is_empty() {
                break;
            }
            offset
        } else {
            chunk_size += buffer.byte_len();
            buffer.len()
        };
        reader.consume(consume);
    }
}
