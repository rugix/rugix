//! Implementation of the block encoding for Rugix's update bundles.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

use block_index::index_for_block_encoding;
use block_table::BlockTable;
use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::ResultExt;
use rugix_compression::ByteProcessor;
use tracing::debug;
use tracing::trace;

use crate::BundleResult;
use crate::format;
use crate::format::Bytes;
use crate::manifest::BlockEncoding;
use crate::manifest::{self};

pub mod block_index;
pub mod block_table;

/// Encode a payload file.
pub fn encode_payload_file(
    block_encoding: &BlockEncoding,
    payload_file: &Path,
    payload_data: &Path,
) -> BundleResult<format::BlockEncoding> {
    let block_index = index_for_block_encoding(block_encoding, payload_file)?;
    let mut block_table = BlockTable::new();
    let mut block_sizes = Vec::new();
    let mut payload_data =
        std::fs::File::create(payload_data).whatever("unable to create payload data file")?;
    let deduplicate = block_encoding.deduplicate.unwrap_or(false);

    let cores = std::thread::available_parallelism().unwrap().get();
    debug!("using {} cores for block encoding", cores);
    std::thread::scope(|scope| {
        let (input_tx, input_rx) = flume::unbounded();
        let (output_tx, output_rx) = flume::bounded(cores);
        for _ in 0..cores {
            let input_rx = input_rx.clone();
            let output_tx = output_tx.clone();
            let mut payload_file =
                BufReader::with_capacity(16 * 1024, std::fs::File::open(payload_file).unwrap());
            let block_index = &block_index;
            scope.spawn(move || {
                while let Ok((idx, block)) = input_rx.recv() {
                    let entry = block_index.entry(block);
                    payload_file
                        .seek(std::io::SeekFrom::Start(entry.offset.raw))
                        .unwrap();

                    let block_data = match &block_encoding.compression {
                        Some(manifest::Compression::Xz(compression)) => {
                            let mut block_data = std::io::Cursor::new(Vec::<u8>::new());
                            let mut compressor =
                                rugix_compression::XzEncoder::new(compression.level.unwrap_or(6));
                            let mut remaining = entry.size;
                            while remaining > 0 {
                                let buffer = payload_file.fill_buf().unwrap();
                                if buffer.is_empty() {
                                    panic!("payload file has been truncated");
                                };
                                let chunk = &buffer[..remaining
                                    .min(buffer.byte_len())
                                    .expect_usize(
                                        "clamped to an in-memory buffer's own length, always fits into usize",
                                    )];
                                compressor.process(chunk, &mut block_data).unwrap();
                                remaining -= chunk.byte_len();
                                let consumed = chunk.len();
                                payload_file.consume(consumed);
                            }
                            compressor.finalize(&mut block_data).unwrap();
                            block_data.into_inner()
                        }
                        None => {
                            let mut block_data = vec![0u8; entry.size.raw as usize];
                            payload_file.read_exact(&mut block_data).unwrap();
                            block_data
                        }
                    };

                    output_tx.send((idx, block, block_data)).unwrap();
                }
            });
        }
        drop(output_tx);

        let mut blocks_sent = 0;
        debug!("sending blocks to worker threads");
        for block in block_index.iter() {
            if !deduplicate || block_table.insert(&block_index, block) {
                input_tx.send((blocks_sent, block)).unwrap();
                blocks_sent += 1;
            }
        }
        debug!(
            "done sending blocks to worker threads, blocks sent: {}",
            blocks_sent
        );

        drop(input_tx);

        debug!("receiving blocks from worker threads");
        let mut sort_buffer = BTreeMap::new();
        let mut next_index = 0;
        while let Ok((idx, _, block_data)) = output_rx.recv() {
            trace!("received block {idx}");
            sort_buffer.insert(idx, block_data);
            while let Some((idx, data)) = sort_buffer.first_key_value()
                && *idx == next_index
            {
                let idx = *idx;
                trace!("writing block {idx}");
                payload_data.write_all(data).unwrap();
                next_index += 1;
                block_sizes.push(NumBytes::new(data.len() as u64));
                sort_buffer.remove(&idx);
            }
        }
        assert!(sort_buffer.is_empty());
        assert!(next_index == blocks_sent);

        debug!("done receiving blocks from worker threads");
    });
    debug!("done processing blocks");
    let is_fixed_size_chunker = block_index.config().chunker.is_fixed();
    let is_compressed = block_encoding.compression.is_some();
    let include_sizes = !is_fixed_size_chunker || is_compressed;
    Ok(format::BlockEncoding {
        hash_algorithm: block_index.config().hash_algorithm,
        deduplicated: deduplicate,
        compression: block_encoding
            .compression
            .as_ref()
            .map(|compression| match compression {
                manifest::Compression::Xz(_) => rugix_compression::CompressionFormat::Xz,
            }),
        chunker: block_index.config().chunker.clone(),
        block_hashes: Bytes {
            raw: compress_bytes(block_encoding, &block_index.into_hashes_vec()),
        },
        block_sizes: if include_sizes {
            let mut encoded_sizes = Vec::new();
            for size in block_sizes {
                encoded_sizes.extend_from_slice(
                    &u32::try_from(size.raw)
                        .expect("blocks should not be larger than 4GiB")
                        .to_be_bytes(),
                );
            }
            Some(Bytes {
                raw: compress_bytes(block_encoding, &encoded_sizes),
            })
        } else {
            None
        },
    })
}

fn compress_bytes(block_encoding: &BlockEncoding, bytes: &[u8]) -> Vec<u8> {
    match &block_encoding.compression {
        Some(manifest::Compression::Xz(compression)) => {
            let mut compressor = rugix_compression::XzEncoder::new(compression.level.unwrap_or(6));
            let mut output = Vec::new();
            compressor.process(bytes, &mut output).unwrap();
            compressor.finalize(&mut output).unwrap();
            output
        }
        None => bytes.to_vec(),
    }
}
