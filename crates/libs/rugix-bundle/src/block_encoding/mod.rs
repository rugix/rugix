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
use reportify::bail;
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
    encode_payload_file_with(block_encoding, payload_file, payload_data, || Ok(()))
}

fn encode_payload_file_with(
    block_encoding: &BlockEncoding,
    payload_file: &Path,
    payload_data: &Path,
    before_encoding: impl FnOnce() -> BundleResult<()>,
) -> BundleResult<format::BlockEncoding> {
    let block_index = index_for_block_encoding(block_encoding, payload_file)?;
    before_encoding()?;
    let mut block_table = BlockTable::new();
    let mut block_sizes = Vec::new();
    let mut payload_data =
        std::fs::File::create(payload_data).whatever("unable to create payload data file")?;
    let deduplicate = block_encoding.deduplicate.unwrap_or(false);

    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let readers = (0..cores)
        .map(|_| {
            std::fs::File::open(payload_file)
                .map(|file| BufReader::with_capacity(16 * 1024, file))
                .whatever("unable to open payload file for block encoding")
        })
        .collect::<BundleResult<Vec<_>>>()?;
    debug!("using {} cores for block encoding", cores);
    std::thread::scope(|scope| -> BundleResult<()> {
        let (input_tx, input_rx) = flume::unbounded();
        let (output_tx, output_rx) = flume::bounded(cores);
        for mut payload_file in readers {
            let input_rx = input_rx.clone();
            let output_tx = output_tx.clone();
            let block_index = &block_index;
            scope.spawn(move || {
                while let Ok((idx, block)) = input_rx.recv() {
                    let result = (|| -> BundleResult<Vec<u8>> {
                        let entry = block_index.entry(block);
                        payload_file
                            .seek(std::io::SeekFrom::Start(entry.offset.raw))
                            .whatever("unable to seek in payload file")?;

                        match &block_encoding.compression {
                            Some(manifest::Compression::Xz(compression)) => {
                                let mut block_data = std::io::Cursor::new(Vec::<u8>::new());
                                let mut compressor = rugix_compression::XzEncoder::new(
                                    compression.level.unwrap_or(6),
                                );
                                let mut remaining = entry.size;
                                while remaining > 0 {
                                    let buffer = payload_file
                                        .fill_buf()
                                        .whatever("unable to read payload block")?;
                                    if buffer.is_empty() {
                                        bail!("payload file was truncated during block encoding");
                                    }
                                    let chunk_len =
                                        usize::try_from(remaining.min(buffer.byte_len()).raw)
                                            .whatever(
                                                "payload block size does not fit into memory",
                                            )?;
                                    let chunk = &buffer[..chunk_len];
                                    let consumed = chunk.len();
                                    let consumed_bytes = chunk.byte_len();
                                    compressor
                                        .process(chunk, &mut block_data)
                                        .whatever("unable to compress payload block")?;
                                    remaining -= consumed_bytes;
                                    payload_file.consume(consumed);
                                }
                                compressor
                                    .finalize(&mut block_data)
                                    .whatever("unable to finalize payload block compression")?;
                                Ok(block_data.into_inner())
                            }
                            None => {
                                let mut block_data = vec![
                                    0u8;
                                    usize::try_from(entry.size.raw).whatever(
                                        "payload block size does not fit into memory"
                                    )?
                                ];
                                payload_file
                                    .read_exact(&mut block_data)
                                    .whatever("unable to read payload block")?;
                                Ok(block_data)
                            }
                        }
                    })();

                    if output_tx.send((idx, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(output_tx);

        let mut blocks_sent = 0;
        debug!("sending blocks to worker threads");
        for block in block_index.iter() {
            if !deduplicate || block_table.insert(&block_index, block) {
                input_tx
                    .send((blocks_sent, block))
                    .map_err(std::io::Error::other)
                    .whatever("block encoding worker stopped unexpectedly")?;
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
        while next_index < blocks_sent {
            let (idx, block_data) = output_rx
                .recv()
                .map_err(std::io::Error::other)
                .whatever("block encoding worker stopped unexpectedly")?;
            let block_data = block_data?;
            trace!("received block {idx}");
            sort_buffer.insert(idx, block_data);
            while let Some((idx, data)) = sort_buffer.first_key_value()
                && *idx == next_index
            {
                let idx = *idx;
                trace!("writing block {idx}");
                payload_data
                    .write_all(data)
                    .whatever("unable to write encoded payload block")?;
                next_index += 1;
                block_sizes.push(NumBytes::new(data.len() as u64));
                sort_buffer.remove(&idx);
            }
        }
        if !sort_buffer.is_empty() || next_index != blocks_sent {
            bail!("block encoding workers returned an incomplete block sequence");
        }

        debug!("done receiving blocks from worker threads");
        Ok(())
    })?;
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
            raw: compress_bytes(block_encoding, &block_index.into_hashes_vec())?,
        },
        block_sizes: if include_sizes {
            let mut encoded_sizes = Vec::new();
            for size in block_sizes {
                encoded_sizes.extend_from_slice(
                    &u32::try_from(size.raw)
                        .whatever("encoded block is larger than 4 GiB")?
                        .to_be_bytes(),
                );
            }
            Some(Bytes {
                raw: compress_bytes(block_encoding, &encoded_sizes)?,
            })
        } else {
            None
        },
    })
}

fn compress_bytes(block_encoding: &BlockEncoding, bytes: &[u8]) -> BundleResult<Vec<u8>> {
    match &block_encoding.compression {
        Some(manifest::Compression::Xz(compression)) => {
            let mut compressor = rugix_compression::XzEncoder::new(compression.level.unwrap_or(6));
            let mut output = Vec::new();
            compressor
                .process(bytes, &mut output)
                .whatever("unable to compress block metadata")?;
            compressor
                .finalize(&mut output)
                .whatever("unable to finalize block metadata compression")?;
            Ok(output)
        }
        None => Ok(bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::encode_payload_file_with;
    use crate::manifest::BlockEncoding;
    use rugix_chunker::ChunkerAlgorithm;

    #[test]
    fn payload_truncation_during_parallel_encoding_returns_an_error() {
        let tempdir = tempfile::tempdir().unwrap();
        let payload = tempdir.path().join("payload");
        let encoded = tempdir.path().join("encoded");
        std::fs::write(&payload, vec![0x5a; 8192]).unwrap();
        let encoding = BlockEncoding::new(ChunkerAlgorithm::Fixed { block_size_kib: 4 });

        let result = encode_payload_file_with(&encoding, &payload, &encoded, || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&payload)
                .unwrap()
                .set_len(0)
                .unwrap();
            Ok(())
        });

        assert!(result.is_err());
    }
}
