//! Block planning, verified acquisition, and fallback from stale local block indices.

use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::ops::Range;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use tracing::warn;

use crate::BundleResult;
use crate::block_encoding::block_index::BlockId;
use crate::block_encoding::block_index::RawBlockIndex;
use crate::block_encoding::block_index::encode_block_sizes;
use crate::block_encoding::block_table::BlockTable;
use crate::format;
use crate::format::stlv::Read as StlvRead;

use super::BundleProgress;
use super::PayloadTarget;
use super::ReaderOptions;
use super::block_provider::StoredBlock;
use super::block_provider::StoredBlockProvider;
use super::cursor::Cursor;
use super::range_fetcher::RangeFetcher;
use super::uncompress_bytes;
use super::validate_block_metadata_lengths;

/// Resolve blocks on the installation thread while range workers read ahead.
pub(crate) struct BlockFetcher<'source> {
    source: &'source mut Cursor,
    encoded_position: u64,
    plan: BlockPlan,
    ranges: Option<RangeFetcher>,
    next_block: usize,
    decoded: Vec<(NumBytes, NumBytes)>,
    decoded_size: NumBytes,
}

impl<'source> BlockFetcher<'source> {
    pub(crate) fn new(
        source: &'source mut Cursor,
        encoding: format::BlockEncoding,
        payload_size: NumBytes,
        provider: Option<&dyn StoredBlockProvider>,
        options: ReaderOptions,
    ) -> BundleResult<Self> {
        let access = source.range_source();
        let start = source.progress().bytes_read.raw;
        let plan = BlockPlan::new(encoding, start, payload_size.raw, provider)?;
        let ranges = access
            .map(|access| {
                RangeFetcher::new(
                    access,
                    plan.missing_ranges(options.max_range_size.get() as u64),
                    options,
                )
            })
            .transpose()?;
        Ok(Self {
            source,
            encoded_position: start,
            plan,
            ranges,
            next_block: 0,
            decoded: Vec::new(),
            decoded_size: NumBytes::ZERO,
        })
    }

    /// Return the next verified block; target reads resolve already written duplicates.
    #[tracing::instrument(level = "trace", skip_all)]
    pub(crate) fn next<T: PayloadTarget>(
        &mut self,
        target: &mut T,
    ) -> BundleResult<Option<FetchedBlock>> {
        let Some(block) = self.plan.blocks.get(self.next_block) else {
            return Ok(None);
        };
        let hash = &self.plan.hashes[self.next_block * self.plan.algorithm.hash_size()..]
            [..self.plan.algorithm.hash_size()];
        let (data, compressed) = match block {
            PlannedBlock::Copy(original) => {
                let (offset, size) = self.decoded[*original];
                let mut data = Vec::new();
                target.read_block(offset, size, &mut data)?;
                verify(self.plan.algorithm, hash, &data)?;
                (data, None)
            }
            PlannedBlock::Encoded { range, local } => {
                let local_data = local.as_ref().and_then(|local| {
                    match read_local(local).and_then(|data| {
                        verify(self.plan.algorithm, hash, &data)?;
                        Ok(data)
                    }) {
                        Ok(data) => Some(data),
                        Err(error) => {
                            warn!(block = self.next_block, %error, "stored block rejected, fetching bundle range");
                            None
                        }
                    }
                });
                let decoded = if let Some(data) = local_data {
                    if self.ranges.is_none() {
                        self.source.skip((range.end - range.start).into())?;
                    }
                    (data, None)
                } else if let Some(ranges) = &mut self.ranges {
                    let mut encoded = if local.is_some() {
                        ranges.fallback(range.clone())?
                    } else {
                        ranges.read(range.clone())?
                    };
                    let mut retries = 0;
                    loop {
                        let decoded = decode(self.plan.compression, encoded).and_then(|decoded| {
                            verify(self.plan.algorithm, hash, &decoded.0)?;
                            Ok(decoded)
                        });
                        match decoded {
                            Ok(decoded) => break decoded,
                            Err(error) if retries < 2 => {
                                warn!(block = self.next_block, %error, "downloaded block rejected, fetching replacement");
                                retries += 1;
                                encoded = ranges.fallback(range.clone())?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                } else {
                    let size = usize::try_from(range.end - range.start)
                        .whatever("encoded block does not fit into memory")?;
                    let mut encoded = vec![0; size];
                    self.source.read_exact(&mut encoded)?;
                    let decoded = decode(self.plan.compression, encoded)?;
                    verify(self.plan.algorithm, hash, &decoded.0)?;
                    decoded
                };
                self.encoded_position = range.end;
                decoded
            }
        };
        let size = data.byte_len();
        self.decoded.push((self.decoded_size, size));
        self.decoded_size += size;
        self.next_block += 1;
        Ok(Some(FetchedBlock {
            hash: hash.to_vec(),
            data,
            compressed: compressed.map(|bytes| {
                (
                    self.plan
                        .compression
                        .expect("only compressed payloads retain encoded block bytes"),
                    bytes,
                )
            }),
        }))
    }

    pub(crate) fn progress(&self) -> BundleProgress {
        let mut progress = self.source.progress();
        if self.ranges.is_some() {
            progress.bytes_read = self.encoded_position.into();
        }
        progress
    }

    /// Finish the worker lifetime and return the verified index in decoded coordinates.
    pub(crate) fn finish(mut self) -> BundleResult<format::BlockIndex> {
        if self.next_block != self.plan.blocks.len() {
            bail!("block fetcher did not finish the payload");
        }
        self.source.advance_to(self.plan.end)?;
        if let Some(ranges) = &mut self.ranges {
            ranges.finish();
        }
        let sizes = self
            .decoded
            .into_iter()
            .map(|(_, size)| u32::try_from(size.raw).whatever("decoded block is larger than 4 GiB"))
            .collect::<BundleResult<Vec<_>>>()?;
        Ok(format::BlockIndex {
            chunker: self.plan.chunker,
            hash_algorithm: self.plan.algorithm,
            block_hashes: format::Bytes {
                raw: self.plan.hashes,
            },
            block_sizes: format::Bytes {
                raw: encode_block_sizes(sizes.into_iter()),
            },
        })
    }
}

/// Verified block returned by [`BlockFetcher::next`].
pub(crate) struct FetchedBlock {
    /// Decoded block hash.
    pub(crate) hash: Vec<u8>,
    /// Decoded block bytes.
    pub(crate) data: Vec<u8>,
    /// Compressed bundle bytes of a block that was transferred from the bundle.
    pub(crate) compressed: Option<(CompressionFormat, Vec<u8>)>,
}

/// Encoded offsets are fixed before fetching; decoded offsets are produced in order.
struct BlockPlan {
    end: u64,
    blocks: Vec<PlannedBlock>,
    hashes: Vec<u8>,
    algorithm: HashAlgorithm,
    compression: Option<CompressionFormat>,
    chunker: rugix_chunker::ChunkerAlgorithm,
}

enum PlannedBlock {
    Encoded {
        range: Range<u64>,
        local: Option<StoredBlock>,
    },
    Copy(usize),
}

impl BlockPlan {
    fn new(
        encoding: format::BlockEncoding,
        start: u64,
        size: u64,
        provider: Option<&dyn StoredBlockProvider>,
    ) -> BundleResult<Self> {
        let hashes = match encoding.compression {
            Some(compression) => uncompress_bytes(compression, &encoding.block_hashes.raw)?,
            None => encoding.block_hashes.raw,
        };
        let sizes = encoding
            .block_sizes
            .map(|sizes| match encoding.compression {
                Some(compression) => uncompress_bytes(compression, &sizes.raw),
                None => Ok(sizes.raw),
            })
            .transpose()?;
        validate_block_metadata_lengths(
            hashes.len(),
            encoding.hash_algorithm.hash_size(),
            sizes.as_ref().map(Vec::len),
        )?;
        let fixed_size = match encoding.chunker {
            rugix_chunker::ChunkerAlgorithm::Fixed { block_size_kib } => {
                Some(u64::from(block_size_kib) * 1024)
            }
            rugix_chunker::ChunkerAlgorithm::Casync { .. } => None,
        };
        if sizes.is_none() && (fixed_size.is_none() || encoding.compression.is_some()) {
            bail!("variable or compressed blocks require encoded sizes");
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| reportify::whatever!("payload range overflow"))?;
        let index = RawBlockIndex::new(&hashes, encoding.hash_algorithm);
        let mut table = BlockTable::new();
        let mut blocks = Vec::new();
        let mut position = start;
        let mut size_index = 0;
        for (idx, hash) in hashes
            .chunks_exact(encoding.hash_algorithm.hash_size())
            .enumerate()
        {
            let fresh = table.insert_raw(&index, BlockId { raw: idx });
            if encoding.deduplicated && !fresh {
                let original = table
                    .get_raw(&index, hash)
                    .ok_or_else(|| reportify::whatever!("block table lost a duplicate"))?;
                blocks.push(PlannedBlock::Copy(original.raw));
                continue;
            }
            let length = if let Some(sizes) = &sizes {
                let bytes = sizes
                    .get(size_index * 4..size_index * 4 + 4)
                    .ok_or_else(|| {
                        reportify::whatever!("block-size metadata has too few entries")
                    })?;
                u64::from(u32::from_be_bytes(
                    bytes
                        .try_into()
                        .expect("the block-size slice has exactly four bytes"),
                ))
            } else {
                fixed_size
                    .expect("uncompressed fixed blocks have a size")
                    .min(end - position)
            };
            if length == 0 || length > end - position {
                bail!("encoded block size exceeds the payload or is zero");
            }
            size_index += 1;
            let next = position + length;
            let local = provider.and_then(|provider| provider.query(hash));
            blocks.push(PlannedBlock::Encoded {
                range: position..next,
                local,
            });
            position = next;
        }
        if position != end
            || sizes
                .as_ref()
                .is_some_and(|sizes| sizes.len() != size_index * 4)
        {
            bail!("encoded block sizes do not match the payload");
        }
        Ok(Self {
            end,
            blocks,
            hashes,
            algorithm: encoding.hash_algorithm,
            compression: encoding.compression,
            chunker: encoding.chunker,
        })
    }

    /// Merge physically adjacent missing bytes and split them into bounded requests.
    fn missing_ranges(&self, max_range_size: u64) -> Vec<Range<u64>> {
        let mut ranges: Vec<Range<u64>> = Vec::new();
        for block in &self.blocks {
            let PlannedBlock::Encoded { range, local: None } = block else {
                continue;
            };
            let mut start = range.start;
            while start < range.end {
                if let Some(last) = ranges.last_mut()
                    && last.end == start
                    && last.end - last.start < max_range_size
                {
                    let end = last.start.saturating_add(max_range_size).min(range.end);
                    last.end = end;
                    start = end;
                } else {
                    let end = start.saturating_add(max_range_size).min(range.end);
                    ranges.push(start..end);
                    start = end;
                }
            }
        }
        ranges
    }
}

fn read_local(block: &StoredBlock) -> BundleResult<Vec<u8>> {
    let mut file = File::open(&block.file).whatever("unable to open stored block")?;
    file.seek(SeekFrom::Start(block.offset.raw))
        .whatever("unable to seek stored block")?;
    let size = usize::try_from(block.size.raw).whatever("stored block does not fit into memory")?;
    let mut data = vec![0; size];
    std::io::Read::read_exact(&mut file, &mut data).whatever("unable to read stored block")?;
    Ok(decode(block.compression, data)?.0)
}

/// Decode block bytes, returning the decoded bytes and the compressed input, if any.
fn decode(
    compression: Option<CompressionFormat>,
    encoded: Vec<u8>,
) -> BundleResult<(Vec<u8>, Option<Vec<u8>>)> {
    match compression {
        Some(compression) => Ok((uncompress_bytes(compression, &encoded)?, Some(encoded))),
        None => Ok((encoded, None)),
    }
}

fn verify(algorithm: HashAlgorithm, expected: &[u8], data: &[u8]) -> BundleResult<()> {
    if algorithm.hash::<Box<[u8]>>(data).raw() != expected {
        bail!("invalid block hash");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::OpenOptions;
    use std::io;
    use std::io::Read;
    use std::num::NonZeroUsize;
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Condvar;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use byte_calc::NumBytes;
    use si_crypto_hashes::HashAlgorithm;
    use tempfile::TempDir;

    use crate::BundleResult;
    use crate::reader::BundleReader;
    use crate::reader::BundleSource;
    use crate::reader::RangeSource;
    use crate::reader::ReaderOptions;
    use crate::reader::SourceReader;
    use crate::reader::StoredBlock;
    use crate::reader::StoredBlockProvider;

    /// Real bundles exercise metadata, block acquisition, target reads, and framing.
    struct Fixture {
        directory: TempDir,
        bytes: Arc<[u8]>,
        payload: Vec<u8>,
        payload_range: Range<u64>,
    }

    impl Fixture {
        fn new(
            chunker: &str,
            compressed: bool,
            deduplicated: bool,
            mebibytes: usize,
            payloads: usize,
        ) -> Self {
            let directory = tempfile::tempdir().unwrap();
            fs::create_dir(directory.path().join("payloads")).unwrap();
            let mut payload = vec![0; mebibytes * 1024 * 1024];
            let mut state = 0x1234_5678_8765_4321_u64;
            for chunk in payload.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            if deduplicated {
                let repeated = payload[..256 * 1024].to_vec();
                payload[512 * 1024..768 * 1024].copy_from_slice(&repeated);
            }
            let compression = if compressed {
                ", compression = { type = \"xz\", level = 1 }"
            } else {
                ""
            };
            let mut manifest = String::from("update-type = \"full\"\n");
            for index in 0..payloads {
                fs::write(
                    directory.path().join(format!("payloads/{index}.img")),
                    &payload,
                )
                .unwrap();
                manifest.push_str(&format!(
                    "\n[[payloads]]\nfilename = \"{index}.img\"\ndelivery = {{ type = \"slot\", slot = \"slot-{index}\" }}\nblock-encoding = {{ chunker = \"{chunker}\", deduplicate = {deduplicated}{compression} }}\n"
                ));
            }
            fs::write(directory.path().join("rugix-bundle.toml"), manifest).unwrap();
            let bundle = directory.path().join("bundle.rugixb");
            crate::builder::pack(directory.path(), &bundle).unwrap();
            let bytes: Arc<[u8]> = fs::read(bundle).unwrap().into();
            let mut reader = BundleReader::start(
                BundleSource::StreamSource(Box::new(io::Cursor::new(bytes.to_vec()))),
                None,
            )
            .unwrap();
            let payload_reader = reader.next_payload().unwrap().unwrap();
            let length = payload_reader.remaining_data.raw;
            drop(payload_reader);
            let start = reader.progress().bytes_read.raw;
            drop(reader);
            Self {
                directory,
                bytes,
                payload,
                payload_range: start..start + length,
            }
        }

        fn decode(
            &self,
            source: BundleSource,
            provider: Option<&dyn StoredBlockProvider>,
        ) -> BundleResult<Vec<Vec<u8>>> {
            self.decode_with_options(source, provider, ReaderOptions::default())
        }

        fn decode_with_options(
            &self,
            source: BundleSource,
            provider: Option<&dyn StoredBlockProvider>,
            options: ReaderOptions,
        ) -> BundleResult<Vec<Vec<u8>>> {
            let total = NumBytes::new(self.bytes.len() as u64);
            let mut reader = BundleReader::start_with_options(source, None, options)?
                .with_size_hint(Some(total));
            let mut last_position = reader.progress().bytes_read;
            let mut decoded = Vec::new();
            while let Some(payload) = reader.next_payload()? {
                let output = self
                    .directory
                    .path()
                    .join(format!("output-{}", decoded.len()));
                let target = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&output)
                    .unwrap();
                let payload_end = payload.reader().progress().bytes_read + payload.remaining_data;
                let info = payload.decode_into(target, provider, &mut |progress| {
                    assert_eq!(progress.bytes_total, Some(total));
                    assert!(progress.bytes_read >= last_position);
                    assert!(progress.bytes_read <= payload_end);
                    last_position = progress.bytes_read;
                })?;
                assert!(reader.progress().bytes_read >= payload_end);
                last_position = reader.progress().bytes_read;
                assert_eq!(info.size.raw as usize, self.payload.len());
                assert!(info.block_index.is_some());
                decoded.push(fs::read(output).unwrap());
            }
            assert_eq!(reader.progress().bytes_read, total);
            Ok(decoded)
        }

        fn ranged(&self, fault: Fault) -> (BundleSource, Arc<TestState>) {
            let state = Arc::new(TestState {
                bytes: Arc::clone(&self.bytes),
                payload: self.payload_range.clone(),
                fault,
                corrupt: AtomicBool::new(false),
                requests: Mutex::new(Vec::new()),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                canceled: Mutex::new(false),
                changed: Condvar::new(),
            });
            (
                BundleSource::RangeSource(Arc::new(TestSource(Arc::clone(&state)))),
                state,
            )
        }
    }

    #[derive(Clone, Copy)]
    enum Fault {
        None,
        CorruptOnce,
        FailConcurrent,
    }

    struct TestState {
        bytes: Arc<[u8]>,
        payload: Range<u64>,
        fault: Fault,
        corrupt: AtomicBool,
        requests: Mutex<Vec<Range<u64>>>,
        active: AtomicUsize,
        peak: AtomicUsize,
        canceled: Mutex<bool>,
        changed: Condvar,
    }

    struct TestSource(Arc<TestState>);

    impl RangeSource for TestSource {
        fn size(&self) -> u64 {
            self.0.bytes.len() as u64
        }

        fn open_range(&self, range: Range<u64>) -> BundleResult<SourceReader> {
            self.0.requests.lock().unwrap().push(range.clone());
            let payload = range.start >= self.0.payload.start && range.end <= self.0.payload.end;
            if payload
                && matches!(self.0.fault, Fault::FailConcurrent)
                && range.start != self.0.payload.start
            {
                reportify::bail!("test range failed");
            }
            if payload {
                let active = self.0.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.0.peak.fetch_max(active, Ordering::SeqCst);
            }
            let corrupt = payload
                && matches!(self.0.fault, Fault::CorruptOnce)
                && !self.0.corrupt.swap(true, Ordering::SeqCst);
            Ok(Box::new(TestReader {
                state: Arc::clone(&self.0),
                position: range.start,
                range,
                payload,
                first_read: true,
                corrupt,
            }))
        }

        fn cancel(&self) {
            *self.0.canceled.lock().unwrap() = true;
            self.0.changed.notify_all();
        }
    }

    struct TestReader {
        state: Arc<TestState>,
        range: Range<u64>,
        position: u64,
        payload: bool,
        first_read: bool,
        corrupt: bool,
    }

    impl Read for TestReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first_read && self.payload {
                self.first_read = false;
                if matches!(self.state.fault, Fault::FailConcurrent) {
                    let mut canceled = self.state.canceled.lock().unwrap();
                    while !*canceled {
                        canceled = self.state.changed.wait(canceled).unwrap();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "test source canceled",
                    ));
                }
                let delay = if self.range.start == self.state.payload.start {
                    40
                } else {
                    5
                };
                std::thread::sleep(Duration::from_millis(delay));
            }
            let length = (self.range.end - self.position).min(buffer.len() as u64) as usize;
            buffer[..length].copy_from_slice(
                &self.state.bytes[self.position as usize..self.position as usize + length],
            );
            if self.corrupt && self.position == self.range.start && length > 0 {
                buffer[0] ^= 1
            }
            self.position += length as u64;
            Ok(length)
        }
    }

    impl Drop for TestReader {
        fn drop(&mut self) {
            if self.payload {
                self.state.active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    struct FirstBlock {
        file: PathBuf,
        hash: Vec<u8>,
    }

    impl StoredBlockProvider for FirstBlock {
        fn query(&self, hash: &[u8]) -> Option<StoredBlock> {
            (hash == self.hash).then(|| StoredBlock {
                file: self.file.clone(),
                offset: NumBytes::ZERO,
                size: NumBytes::kibibytes(64),
                compression: None,
            })
        }
    }

    /// Several ranges finish out of order while writes reconstruct the exact payload.
    #[test]
    fn concurrent_coalesced_ranges_preserve_order() {
        let fixture = Fixture::new("fixed-64", false, false, 6, 1);
        let (source, state) = fixture.ranged(Fault::None);
        assert_eq!(
            fixture.decode(source, None).unwrap(),
            vec![fixture.payload.clone()]
        );
        assert!(state.peak.load(Ordering::SeqCst) >= 2);
        let requests = state.requests.lock().unwrap();
        let payload_requests: Vec<_> = requests
            .iter()
            .filter(|range| {
                range.start >= fixture.payload_range.start && range.end <= fixture.payload_range.end
            })
            .collect();
        assert_eq!(payload_requests.len(), 6);
        assert!(
            payload_requests
                .iter()
                .all(|range| range.end - range.start == 1024 * 1024)
        );
    }

    /// Non-default worker and range limits also bound metadata and replacement
    /// requests while reconstructing blocks larger than a request.
    #[test]
    fn configured_limits_cover_split_blocks_and_fallback() {
        let fixture = Fixture::new("fixed-64", false, false, 1, 1);
        for (concurrency, range_size, fault) in [
            (1, 48 * 1024, Fault::None),
            (3, 4 * 1024, Fault::CorruptOnce),
        ] {
            let options = ReaderOptions {
                concurrency: NonZeroUsize::new(concurrency).unwrap(),
                max_range_size: NonZeroUsize::new(range_size).unwrap(),
            };
            let (source, state) = fixture.ranged(fault);
            assert_eq!(
                fixture.decode_with_options(source, None, options).unwrap(),
                vec![fixture.payload.clone()]
            );
            let peak = state.peak.load(Ordering::SeqCst);
            assert!(peak <= concurrency);
            if concurrency == 1 {
                assert_eq!(peak, 1);
            } else {
                assert!(peak >= 2);
                assert!(state.corrupt.load(Ordering::SeqCst));
            }
            assert!(
                state
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|range| range.end - range.start <= range_size as u64)
            );
        }
    }

    /// Unencoded payloads keep using the configured range size until their end,
    /// without reverting to small framing reads after the first range.
    #[test]
    fn unencoded_payload_uses_bounded_sequential_ranges() {
        let mut fixture = Fixture::new("fixed-64", false, false, 1, 1);
        let manifest_path = fixture.directory.path().join("rugix-bundle.toml");
        let mut manifest: crate::manifest::BundleManifest =
            toml::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest.payloads[0].block_encoding = None;
        fs::write(&manifest_path, toml::to_string(&manifest).unwrap()).unwrap();
        let bundle_path = fixture.directory.path().join("bundle.rugixb");
        crate::builder::pack(fixture.directory.path(), &bundle_path).unwrap();
        fixture.bytes = fs::read(bundle_path).unwrap().into();
        let mut metadata = BundleReader::start(
            BundleSource::StreamSource(Box::new(io::Cursor::new(fixture.bytes.to_vec()))),
            None,
        )
        .unwrap();
        let payload = metadata.next_payload().unwrap().unwrap();
        let start = payload.reader().progress().bytes_read.raw;
        fixture.payload_range = start..start + payload.remaining_data.raw;
        drop(payload);
        drop(metadata);

        let range_size = 128 * 1024;
        let options = ReaderOptions {
            max_range_size: NonZeroUsize::new(range_size).unwrap(),
            ..ReaderOptions::default()
        };
        let (source, state) = fixture.ranged(Fault::None);
        let mut reader = BundleReader::start_with_options(source, None, options).unwrap();
        let output = fixture.directory.path().join("unencoded-output");
        let target = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();
        let info = reader
            .next_payload()
            .unwrap()
            .unwrap()
            .decode_into(target, None, &mut |_| {})
            .unwrap();
        assert!(info.block_index.is_none());
        assert_eq!(fs::read(output).unwrap(), fixture.payload);
        assert!(reader.next_payload().unwrap().is_none());
        let requests = state.requests.lock().unwrap();
        assert!(
            requests
                .iter()
                .all(|range| range.end - range.start <= range_size as u64)
        );
        let payload_requests: Vec<_> = requests
            .iter()
            .filter(|range| {
                range.start >= fixture.payload_range.start && range.end <= fixture.payload_range.end
            })
            .collect();
        assert!(payload_requests.len() <= 9);
        assert!(
            payload_requests
                .iter()
                .take(7)
                .all(|range| range.end - range.start == range_size as u64)
        );
    }

    /// Compression, variable blocks, deduplication, and consecutive payloads share the
    /// cursor correctly.
    #[test]
    fn encoded_payloads_work_with_ranged_and_streaming_inputs() {
        for chunker in ["fixed-16", "casync-16"] {
            for compressed in [false, true] {
                let fixture = Fixture::new(chunker, compressed, true, 1, 2);
                let (source, _) = fixture.ranged(Fault::None);
                assert_eq!(
                    fixture.decode(source, None).unwrap(),
                    vec![fixture.payload.clone(); 2]
                );
                let stream =
                    BundleSource::StreamSource(Box::new(io::Cursor::new(fixture.bytes.to_vec())));
                assert_eq!(
                    fixture.decode(stream, None).unwrap(),
                    vec![fixture.payload.clone(); 2]
                );
                let file = fs::File::open(fixture.directory.path().join("bundle.rugixb")).unwrap();
                let seekable = BundleSource::from_seekable(file).unwrap();
                assert_eq!(
                    fixture.decode(seekable, None).unwrap(),
                    vec![fixture.payload.clone(); 2]
                );
            }
        }
    }

    /// Adding signatures preserves buffered payload bytes and all decoded payloads.
    #[test]
    fn signature_rewrites_preserve_payload_data() {
        let fixture = Fixture::new("fixed-64", false, true, 1, 2);
        let original = fixture.directory.path().join("bundle.rugixb");
        let signed = fixture.directory.path().join("signed.rugixb");
        let rotated = fixture.directory.path().join("rotated.rugixb");
        let expected_hash = crate::bundle_hash(&original).unwrap();
        crate::add_bundle_signature(&original, b"first signature".to_vec(), &signed).unwrap();
        crate::add_bundle_signature(&signed, b"second signature".to_vec(), &rotated).unwrap();
        assert_eq!(crate::bundle_hash(&rotated).unwrap(), expected_hash);
        let source = BundleSource::from_seekable(fs::File::open(&rotated).unwrap()).unwrap();
        let reader = BundleReader::start(source, Some(expected_hash)).unwrap();
        let signatures = &reader.signatures().unwrap().cms_signatures;
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0].raw, b"first signature");
        assert_eq!(signatures[1].raw, b"second signature");
        drop(reader);

        let source = BundleSource::from_seekable(fs::File::open(&rotated).unwrap()).unwrap();
        let mut reader = BundleReader::start(source, None).unwrap();
        for index in 0..2 {
            let output = fixture
                .directory
                .path()
                .join(format!("signed-output-{index}"));
            let target = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&output)
                .unwrap();
            reader
                .next_payload()
                .unwrap()
                .unwrap()
                .decode_into(target, None, &mut |_| {})
                .unwrap();
            assert_eq!(fs::read(output).unwrap(), fixture.payload);
        }
        assert!(reader.next_payload().unwrap().is_none());
    }

    /// A stale local block is fetched from its original offset while later ranges remain
    /// queued.
    #[test]
    fn rejected_local_block_uses_a_priority_fallback() {
        let fixture = Fixture::new("fixed-64", false, false, 6, 1);
        let file = fixture.directory.path().join("old.img");
        fs::write(&file, vec![0; 64 * 1024]).unwrap();
        let provider = FirstBlock {
            file,
            hash: HashAlgorithm::Sha512_256
                .hash::<Box<[u8]>>(&fixture.payload[..64 * 1024])
                .raw()
                .to_vec(),
        };
        let (source, state) = fixture.ranged(Fault::None);
        assert_eq!(
            fixture.decode(source, Some(&provider)).unwrap(),
            vec![fixture.payload.clone()]
        );
        assert!(
            state
                .requests
                .lock()
                .unwrap()
                .contains(&(fixture.payload_range.start..fixture.payload_range.start + 64 * 1024))
        );
    }

    /// A stream keeps the incoming bytes available until a local candidate is verified.
    #[test]
    fn rejected_local_block_does_not_discard_stream_bytes() {
        let fixture = Fixture::new("fixed-64", false, false, 1, 1);
        let file = fixture.directory.path().join("truncated.img");
        fs::write(&file, []).unwrap();
        let provider = FirstBlock {
            file,
            hash: HashAlgorithm::Sha512_256
                .hash::<Box<[u8]>>(&fixture.payload[..64 * 1024])
                .raw()
                .to_vec(),
        };
        let source = BundleSource::StreamSource(Box::new(io::Cursor::new(fixture.bytes.to_vec())));
        assert_eq!(
            fixture.decode(source, Some(&provider)).unwrap(),
            vec![fixture.payload.clone()]
        );
    }

    /// A corrupt downloaded block is reacquired without replaying already written blocks.
    #[test]
    fn rejected_downloaded_block_is_retried() {
        let fixture = Fixture::new("fixed-64", false, false, 6, 1);
        let (source, state) = fixture.ranged(Fault::CorruptOnce);
        assert_eq!(
            fixture.decode(source, None).unwrap(),
            vec![fixture.payload.clone()]
        );
        assert!(
            state
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|range| range.end - range.start == 64 * 1024)
        );
    }

    /// A later worker failure wakes an earlier blocked reader and retains the original
    /// error.
    #[test]
    fn worker_failure_cancels_other_readers() {
        let fixture = Fixture::new("fixed-64", false, false, 6, 1);
        let (source, state) = fixture.ranged(Fault::FailConcurrent);
        let error = fixture.decode(source, None).unwrap_err();
        assert!(format!("{error:?}").contains("test range failed"));
        assert!(*state.canceled.lock().unwrap());
    }
}
