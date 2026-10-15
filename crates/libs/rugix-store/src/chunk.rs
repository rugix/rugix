//! Compression, decompression, and verification of chunk content.

use std::fs;
use std::path::Path;

use reportify::ResultExt;
use reportify::bail;
use rugix_compression::ByteProcessor;
use rugix_compression::CompressionFormat;
use rugix_compression::XzDecoder;
use rugix_compression::XzEncoder;
use si_crypto_hashes::HashAlgorithm;

use crate::StoreResult;

/// XZ preset for chunks compressed by the store.
// Chunks are at most a few hundred KiB, so the larger dictionaries of higher presets
// barely improve compression while costing devices time and up to 94 MiB of memory.
// Preset 1 needs about 10 MiB and compresses container images within 5% of preset 6.
const COMPRESSION_LEVEL: u8 = 1;

/// Compress chunk content, keeping it uncompressed if compression does not help.
pub(crate) fn compress(data: &[u8]) -> StoreResult<(Vec<u8>, Option<CompressionFormat>)> {
    let mut compressed = Vec::new();
    let mut encoder = XzEncoder::new(COMPRESSION_LEVEL);
    encoder
        .process(data, &mut compressed)
        .whatever("unable to compress chunk")?;
    encoder
        .finalize(&mut compressed)
        .whatever("unable to compress chunk")?;
    if compressed.len() < data.len() {
        Ok((compressed, Some(CompressionFormat::Xz)))
    } else {
        Ok((data.to_vec(), None))
    }
}

/// Read a chunk file and check that its content has the expected hash.
pub(crate) fn read(
    path: &Path,
    compression: Option<CompressionFormat>,
    algorithm: HashAlgorithm,
    hash: &[u8],
) -> StoreResult<Vec<u8>> {
    let stored = fs::read(path).whatever_with(|_| format!("unable to read chunk {path:?}"))?;
    let data = match compression {
        Some(CompressionFormat::Xz) => {
            let mut data = Vec::new();
            let mut decoder = XzDecoder::new();
            decoder
                .process(&stored, &mut data)
                .and_then(|()| decoder.finalize(&mut data))
                .whatever_with(|_| format!("unable to decompress chunk {path:?}"))?;
            data
        }
        None => stored,
    };
    if algorithm.hash::<Box<[u8]>>(&data).raw() != hash {
        bail!("chunk {path:?} does not match its hash");
    }
    Ok(data)
}
