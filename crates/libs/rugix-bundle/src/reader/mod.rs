//! Consume Rugix bundles and deliver verified payload bytes without staging a
//! complete bundle.
//!
//! [`BundleReader`] owns a [`BundleSource`] and lends one [`PayloadReader`] at a time.
//! [`PayloadTarget`] receives decoded output, [`StoredBlockProvider`] supplies local
//! reuse candidates, and [`BundleProgress`] reports logical consumption progress.
//!
//! # Consuming a Bundle
//!
//! Supply a [`BundleSource`] to [`BundleReader::start`], inspect its metadata, and
//! consume each [`PayloadReader`] through [`PayloadReader::decode_into`] or
//! [`PayloadReader::skip`] before requesting the next payload. Successful
//! consumption of the final payload also validates the closing bundle framing.
//!
//! ```
//! use std::fs::{File, OpenOptions};
//! use reportify::ResultExt;
//! use rugix_bundle::BundleResult;
//! use rugix_bundle::reader::{BundleReader, BundleSource};
//! # fn main() -> BundleResult<()> {
//! # let temporary = tempfile::tempdir().whatever("unable to create example directory")?;
//! # let directory = temporary.path();
//! # std::fs::create_dir(directory.join("payloads")).whatever("unable to create payload directory")?;
//! # std::fs::write(directory.join("payloads/example.img"), b"example payload").whatever("unable to write example payload")?;
//! # std::fs::write(directory.join("rugix-bundle.toml"), r#"
//! # update-type = "full"
//! # [[payloads]]
//! # filename = "example.img"
//! # delivery = { type = "slot", slot = "example" }
//! # block-encoding = { chunker = "fixed-64" }
//! # "#).whatever("unable to write example manifest")?;
//! # let bundle_path = directory.join("example.rugixb");
//! # let expected_hash = rugix_bundle::builder::pack(directory, &bundle_path)?;
//! # let output_directory = directory;
//! let source = BundleSource::from_seekable(
//!     File::open(bundle_path).whatever("unable to open bundle")?,
//! )?;
//! let mut bundle = BundleReader::start(source, Some(expected_hash))?;
//!
//! while let Some(payload) = bundle.next_payload()? {
//!     let target = OpenOptions::new()
//!         .create(true).truncate(true).read(true).write(true)
//!         .open(output_directory.join(format!("payload-{}.img", payload.idx())))
//!         .whatever("unable to open payload target")?;
//!     let info = payload.decode_into(target, None, &mut |progress| {
//!         println!("consumed {}", progress.bytes_read);
//!     })?;
//!     println!("installed {}", info.size);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! The expected header hash must come from a trusted source. Passing `None`
//! checks consistency against the hashes declared in the bundle; callers can
//! authenticate the header by verifying [`BundleReader::signatures`] before
//! consuming any payload. Signature verification and installation policy belong
//! to the caller.
//!
//! # Sources and Ownership
//!
//! [`BundleSource::RangeSource`] owns a shareable [`RangeSource`]. It opens
//! independent readers for half-open encoded byte ranges; concurrent reads keep
//! separate positions. [`BundleSource::StreamSource`] owns one forward reader.
//! [`BundleSource::from_seekable`] adapts files and other seekable inputs by
//! serializing seek/read pairs while preserving each range reader's position.
//!
//! The bundle reader owns its source and its private buffered parser position.
//! Sequential reading and skipping are implementation details of [`format::stlv`].
//! Payload acquisition obtains range access internally, independently of framing.
//! HTTP support belongs in a source backend: its connection pool, capability
//! probe, transport retries, and traffic counters stay outside this crate.
//!
//! # Reader Pipeline
//!
//! Block-encoded payload consumption proceeds through these stages:
//!
//! 1. **Parse and validate metadata.** The reader checks the payload header against its
//!    hash in the bundle header. Block hashes, compression, and encoded sizes describe
//!    how payload bytes must be interpreted.
//! 2. **Plan acquisition.** Encoded intervals are fixed before fetching starts. Physical
//!    sizes must exactly cover the payload. A [`StoredBlockProvider`] supplies local
//!    candidates; deduplicated entries refer to earlier output. Consecutive missing bytes
//!    are combined into requests bounded by [`ReaderOptions::max_range_size`] (1 MiB by
//!    default).
//! 3. **Fetch ahead.** Up to [`ReaderOptions::concurrency`] blocking worker threads (four
//!    by default) acquire independent ranges while the installation thread handles
//!    earlier blocks. Each request has a private result slot, so responses can finish in
//!    any order.
//! 4. **Resolve and verify the next block.** The installation thread verifies local
//!    candidates, decompresses downloaded bytes, and checks decoded block hashes. A
//!    rejected local candidate requests its original encoded interval through a priority
//!    queue. Rejected downloads can request two replacements. Duplicate blocks are read
//!    from previously written target offsets and verified.
//! 5. **Write in order.** Only a verified decoded block is passed to
//!    [`PayloadTarget::write`]. The same bytes update the payload hash and the decoded
//!    block index. Writing, hashing, decompression, and target reads stay on the
//!    installation thread while workers continue downloading.
//! 6. **Finish consumption.** The parser resumes at the encoded payload end. The reader
//!    checks the complete decoded payload hash, finalizes the target, and validates
//!    closing framing before returning [`DecodedPayloadInfo`].
//!
//! A forward stream follows the same logical order with sequential acquisition.
//! Local candidates are verified before their original stream bytes are drained,
//! so rejected candidates can still use those incoming bytes. Stream corruption
//! fails consumption because an earlier interval cannot be requested again.
//!
//! A payload without block encoding is copied sequentially and checked against its
//! complete payload hash before target finalization. Per-block verification
//! requires a block encoding; an installer can enforce that requirement before
//! calling `decode_into`.
//!
//! # Progress, Bounds, and Failures
//!
//! [`BundleProgress`] reports the logical encoded position reached after writes
//! and an optional total source length. It does not count overlapping downloads
//! or replacement requests. [`BundleReader::with_size_hint`] supplies a known
//! transport length for a forward stream.
//!
//! [`BundleReader::start_with_options`] accepts [`ReaderOptions`] to tune concurrency
//! and the maximum range size. Lookahead retains at most `concurrency` responses
//! plus one separate fallback response, each bounded by `max_range_size`. Defaults
//! retain at most four 1 MiB responses plus one 1 MiB fallback response. Metadata,
//! the current encoded and decoded block, and codec workspace are additional.
//! Large encoded blocks are assembled from several bounded requests.
//!
//! The first worker failure stops scheduling and cancels the source. An
//! unfinished fetcher clears queued jobs and joins its workers. Successful
//! consumption joins workers without canceling the source, allowing subsequent
//! payloads to be read. Backends must support cancellation or bound blocking I/O
//! so shutdown can finish. A consumption error aborts the operation; target writes
//! already completed remain the caller's responsibility.
//!
//! A [`PayloadTarget`] supplies ordered writes, optional reads for deduplication,
//! and finalization. The implementation for [`std::fs::File`] supports target
//! reads and flushes and synchronizes the file during finalization. Boot selection,
//! rollback policy, signature validation, and application activation belong to
//! the installer.

use std::fs::File;
use std::io::Seek;
use std::io::Write;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use reportify::whatever;
use rugix_compression::ByteProcessor;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;

use crate::BUNDLE_HEADER_SIZE_LIMIT;
use crate::BundleResult;
use crate::PAYLOAD_HEADER_SIZE_LIMIT;
use crate::SIGNATURES_SIZE_LIMIT;
use crate::format::Signatures;
use crate::format::decode::decode_slice;
use crate::format::stlv::AtomHead;
use crate::format::stlv::Read as StlvRead;
use crate::format::stlv::Tag;
use crate::format::stlv::read_atom_head;
use crate::format::stlv::skip;
use crate::format::stlv::write_atom_head;
use crate::format::tags;
use crate::format::{self};

mod block_fetcher;
mod block_provider;
mod cursor;
mod options;
mod range_fetcher;
mod source;

#[doc(inline)]
pub use block_provider::StoredBlock;
#[doc(inline)]
pub use block_provider::StoredBlockProvider;
#[doc(inline)]
pub use options::ReaderOptions;
#[doc(inline)]
pub use source::BundleSource;
#[doc(inline)]
pub use source::RangeSource;
#[doc(inline)]
pub use source::SourceReader;

use block_fetcher::BlockFetcher;
use cursor::Cursor;

/// Own a bundle source and consume its verified payloads in order.
pub struct BundleReader {
    cursor: Cursor,
    options: ReaderOptions,
    header: format::BundleHeader,
    header_raw: Vec<u8>,
    signatures: Option<Signatures>,
    next_payload: usize,
    finished: bool,
}

impl BundleReader {
    /// Own the input, parse its header, and optionally verify the expected header hash.
    pub fn start(source: BundleSource, header_hash: Option<HashDigest>) -> BundleResult<Self> {
        Self::start_with_options(source, header_hash, ReaderOptions::default())
    }

    /// Start consumption with explicit range concurrency and size limits.
    ///
    /// Limits apply to framing and payload reads from range sources. Forward
    /// streams remain sequential. Invalid response-buffer sizes return an error.
    pub fn start_with_options(
        source: BundleSource,
        header_hash: Option<HashDigest>,
        options: ReaderOptions,
    ) -> BundleResult<Self> {
        options.validate()?;
        let mut source = Cursor::new(source, options.max_range_size);
        let _ = expect_start(&mut source, tags::BUNDLE)?;
        let mut bundle_header = Vec::new();
        let header_head = skip_until_start(&mut source, tags::BUNDLE_HEADER)?;
        read_into_vec(
            &mut source,
            &mut bundle_header,
            header_head,
            BUNDLE_HEADER_SIZE_LIMIT,
        )?;
        if let Some(digest) = header_hash
            && digest.algorithm().hash(&bundle_header) != digest
        {
            bail!("invalid header hash");
        }
        let header = decode_slice::<format::BundleHeader>(&bundle_header)?;
        let signatures = read_optional_metadata(&mut source)?;
        // At this point, we are in the payloads section.
        Ok(Self {
            cursor: source,
            options,
            header,
            signatures,
            header_raw: bundle_header,
            next_payload: 0,
            finished: false,
        })
    }

    /// Supply a transport's known length for progress on a forward stream.
    pub fn with_size_hint(mut self, total: Option<NumBytes>) -> Self {
        self.cursor.set_size_hint(total);
        self
    }

    /// Logical parser position, distinct from actual transport traffic.
    pub fn progress(&self) -> BundleProgress {
        self.cursor.progress()
    }

    /// Decoded bundle metadata, including the ordered payload index.
    pub fn header(&self) -> &format::BundleHeader {
        &self.header
    }

    /// Original encoded header bytes used for hashing and signature verification.
    pub fn header_raw(&self) -> &[u8] {
        &self.header_raw
    }

    /// Hash the original header with the selected algorithm.
    pub fn header_hash(&self, algorithm: HashAlgorithm) -> HashDigest {
        algorithm.hash(&self.header_raw)
    }

    /// Embedded signatures for the caller to authenticate before payload consumption.
    pub fn signatures(&self) -> Option<&Signatures> {
        self.signatures.as_ref()
    }

    /// Parse the next payload header, checking its declared header hash.
    ///
    /// Consume or skip the returned payload before requesting another. A result of
    /// `None` also verifies that all declared payloads and closing framing were read.
    pub fn next_payload(&mut self) -> BundleResult<Option<PayloadReader<'_>>> {
        if self.next_payload >= self.header.payload_index.len() {
            self.finish_payloads()?;
            return Ok(None);
        }
        let this_payload = self.next_payload;
        self.next_payload += 1;
        let entry = &self.header.payload_index[this_payload];
        let _ = expect_start(&mut self.cursor, tags::PAYLOAD)?;
        let header_atom = skip_until_start(&mut self.cursor, tags::PAYLOAD_HEADER)?;
        let mut header_bytes = Vec::new();
        read_into_vec(
            &mut self.cursor,
            &mut header_bytes,
            header_atom,
            PAYLOAD_HEADER_SIZE_LIMIT,
        )?;
        if self
            .header
            .hash_algorithm
            .hash::<Box<[u8]>>(&header_bytes)
            .raw()
            != entry.header_hash.raw
        {
            bail!("invalid payload header hash");
        }
        let remaining_data = skip_until_value(&mut self.cursor, tags::PAYLOAD_DATA)?;
        Ok(Some(PayloadReader {
            idx: this_payload,
            reader: self,
            header: decode_slice(&header_bytes)?,
            remaining_data,
        }))
    }

    fn finish_payloads(&mut self) -> BundleResult<()> {
        if self.finished {
            return Ok(());
        }
        skip_until_end(&mut self.cursor, tags::PAYLOADS)?;
        skip_until_end(&mut self.cursor, tags::BUNDLE)?;
        if read_atom_head(&mut self.cursor)?.is_some() {
            bail!("bundle contains trailing atoms after the root segment");
        }
        self.finished = true;
        Ok(())
    }
}

/// Position reached while consuming a bundle.
#[derive(Debug, Clone, Copy)]
pub struct BundleProgress {
    /// Logical encoded position reached by completed writes or framing reads.
    pub bytes_read: NumBytes,
    /// Source length, if provided by the backend or a size hint.
    pub bytes_total: Option<NumBytes>,
}

/// Read optional bundle metadata advancing the source to the payload section.
pub(crate) fn read_optional_metadata(
    source: &mut dyn StlvRead,
) -> BundleResult<Option<Signatures>> {
    let mut signatures = None;
    loop {
        let head = expect_atom_head(source)?;
        match head.tag() {
            tags::PAYLOADS if head.is_start() => break,
            tags::SIGNATURES if head.is_start() => {
                if signatures.is_some() {
                    bail!("multiple signature segments");
                }
                let mut bundle_signatures = Vec::new();
                read_into_vec(source, &mut bundle_signatures, head, SIGNATURES_SIZE_LIMIT)?;
                signatures = Some(decode_slice(&bundle_signatures)?);
            }
            _ if tags::is_required(head.tag()) => {
                bail!("found unexpected required tag {}", head.tag());
            }
            _ => skip(source, head)?,
        }
    }
    Ok(signatures)
}

/// One pending payload, borrowing its bundle until consumed or skipped.
#[must_use = "consume or skip the payload before reading the next one"]
pub struct PayloadReader<'r> {
    idx: usize,
    reader: &'r mut BundleReader,
    header: format::PayloadHeader,
    remaining_data: NumBytes,
}

impl PayloadReader<'_> {
    /// The containing bundle reader and its metadata.
    pub fn reader(&self) -> &BundleReader {
        self.reader
    }

    /// Position of this payload in the bundle's ordered index.
    pub fn idx(&self) -> usize {
        self.idx
    }

    /// Verified payload metadata describing its block encoding.
    pub fn header(&self) -> &format::PayloadHeader {
        &self.header
    }

    /// Delivery metadata and decoded payload hash from the bundle index.
    pub fn entry(&self) -> &format::PayloadEntry {
        &self.reader.header().payload_index[self.idx]
    }

    /// Discard this payload's encoded bytes and validate its closing framing.
    ///
    /// Skipping does not verify the decoded payload hash. Streams drain the bytes;
    /// range sources advance the private parser position without downloading them.
    pub fn skip(self) -> BundleResult<()> {
        self.reader.cursor.skip(self.remaining_data)?;
        skip_until_end(&mut self.reader.cursor, tags::PAYLOAD)?;
        if self.reader.next_payload >= self.reader.header.payload_index.len() {
            self.reader.finish_payloads()?;
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> BundleResult<usize> {
        let max_chunk = buf
            .byte_len()
            .min(self.remaining_data)
            .expect_usize("clamped to an in-memory buffer's own length, always fits into usize");
        if max_chunk == 0 {
            return Ok(0);
        }
        let read = self.reader.cursor.read(&mut buf[..max_chunk])?;
        self.remaining_data -=
            NumBytes::expect_from_usize(read, "bytes actually read always fit into u64");
        Ok(read)
    }

    /// Resolve decoded bytes, write them in order, and return verified payload metadata.
    ///
    /// Block-encoded payloads are verified before each write. Local block candidates
    /// are read through `provider`; rejected candidates fall back to bundle bytes.
    /// Progress is reported after writes. The target is finalized after complete
    /// payload-hash verification, followed by closing-framing validation.
    ///
    /// Payloads without block encoding are streamed with whole-payload verification
    /// before finalization. Any failure aborts consumption; earlier writes can remain.
    pub fn decode_into<T: PayloadTarget, F: FnMut(&BundleProgress)>(
        mut self,
        mut target: T,
        provider: Option<&dyn StoredBlockProvider>,
        progress: &mut F,
    ) -> BundleResult<DecodedPayloadInfo> {
        let mut buffer = vec![0; 8192];
        let mut payload_hasher = self.reader.header.hash_algorithm.hasher();
        let mut bytes_written = NumBytes::ZERO;
        let block_index = if let Some(block_encoding) = self.header.block_encoding {
            let mut fetcher = BlockFetcher::new(
                &mut self.reader.cursor,
                block_encoding,
                self.remaining_data,
                provider,
                self.reader.options,
            )?;
            while let Some(block) = fetcher.next(&mut target)? {
                target.write(&block)?;
                payload_hasher.update(&block);
                bytes_written += block.byte_len();
                progress(&fetcher.progress());
            }
            self.remaining_data = NumBytes::ZERO;
            Some(fetcher.finish()?)
        } else {
            // The next chunk is the whole payload.
            self.reader
                .cursor
                .hint_sequential_bytes(self.remaining_data);
            loop {
                let read = self.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                target.write(&buffer[..read])?;
                payload_hasher.update(&buffer[..read]);
                bytes_written +=
                    NumBytes::expect_from_usize(read, "bytes actually read always fit into u64");
                progress(&self.reader.progress());
            }
            None
        };
        if self.remaining_data != NumBytes::ZERO {
            bail!(
                "payload contains {} trailing encoded bytes",
                self.remaining_data.raw
            );
        }
        let payload_hash = payload_hasher.finalize();
        if payload_hash.raw() != self.reader.header.payload_index[self.idx].file_hash.raw {
            bail!("payload hash mismatch");
        }
        target.finalize()?;
        skip_until_end(&mut self.reader.cursor, tags::PAYLOAD)?;
        if self.reader.next_payload >= self.reader.header.payload_index.len() {
            self.reader.finish_payloads()?;
        }
        Ok(DecodedPayloadInfo {
            hash: payload_hash,
            size: bytes_written,
            block_index,
        })
    }
}

/// Verified metadata for a fully consumed and finalized payload.
pub struct DecodedPayloadInfo {
    /// Hash of the complete decoded payload.
    pub hash: HashDigest,
    /// Total decoded bytes written to the target.
    pub size: NumBytes,
    /// Verified block index of the decoded payload, when included in the bundle.
    pub block_index: Option<format::BlockIndex>,
}

/// Ordered output for decoded payload blocks and optional reads for deduplication.
///
/// Targets that support deduplication must read previously written bytes at offsets
/// relative to the beginning of the decoded payload. The file implementation uses
/// file offset zero as that beginning.
pub trait PayloadTarget: Sized {
    /// Write every byte in the supplied block before returning success.
    fn write(&mut self, bytes: &[u8]) -> BundleResult<()>;

    /// Replace `buffer` with exactly `size` previously written bytes at `offset`.
    ///
    /// The default implementation rejects deduplicated payloads.
    #[expect(unused_variables)]
    fn read_block(
        &mut self,
        offset: NumBytes,
        size: NumBytes,
        buffer: &mut Vec<u8>,
    ) -> BundleResult<()> {
        bail!("target does not support reading blocks");
    }

    /// Complete output after payload verification. Files flush and synchronize here.
    fn finalize(self) -> BundleResult<()> {
        Ok(())
    }
}

impl PayloadTarget for File {
    fn write(&mut self, bytes: &[u8]) -> BundleResult<()> {
        self.write_all(bytes).whatever("unable to write to target")
    }

    fn read_block(
        &mut self,
        offset: NumBytes,
        size: NumBytes,
        buffer: &mut Vec<u8>,
    ) -> BundleResult<()> {
        let current_position = self
            .stream_position()
            .whatever("unable to get writing position")?;
        self.seek(std::io::SeekFrom::Start(offset.raw))
            .whatever("unable to seek")?;
        buffer.resize(
            usize::try_from(size).whatever("block size does not fit into usize")?,
            0,
        );
        std::io::Read::read_exact(self, buffer).whatever("unable to read")?;
        self.seek(std::io::SeekFrom::Start(current_position))
            .whatever("unable to seek")?;
        Ok(())
    }

    fn finalize(mut self) -> BundleResult<()> {
        self.flush().whatever("unable to flush payload target")?;
        self.sync_all()
            .whatever("unable to synchronize payload target")
    }
}

/// Read next segment or value into vector.
pub(crate) fn read_into_vec(
    source: &mut dyn StlvRead,
    output: &mut Vec<u8>,
    head: AtomHead,
    limit: NumBytes,
) -> BundleResult<()> {
    read_into_vec_at_depth(source, output, head, limit, 0)
}

fn read_into_vec_at_depth(
    source: &mut dyn StlvRead,
    output: &mut Vec<u8>,
    head: AtomHead,
    limit: NumBytes,
    depth: usize,
) -> BundleResult<()> {
    const MAX_NESTING_DEPTH: usize = 64;
    if depth > MAX_NESTING_DEPTH {
        bail!("STLV nesting depth exceeds {MAX_NESTING_DEPTH}");
    }
    write_atom_head(output, head).whatever("unable to buffer STLV atom")?;
    match head {
        AtomHead::Value { length, .. } => {
            if output.byte_len() + length < limit {
                let offset = output.len();
                let length = usize::try_from(length.raw)
                    .whatever("STLV value length does not fit into memory")?;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| whatever!("STLV value length overflows memory size"))?;
                output.resize(end, 0);
                source
                    .read_exact(&mut output[offset..])
                    .whatever("unable to read value")?;
            } else {
                bail!("value too long");
            }
        }
        AtomHead::Start { tag: start_tag } => loop {
            let inner = expect_atom_head(source)?;
            match inner {
                atom @ AtomHead::End { tag } if tag == start_tag => {
                    write_atom_head(output, atom).whatever("unable to buffer STLV atom")?;
                    break;
                }
                atom => {
                    read_into_vec_at_depth(source, output, atom, limit, depth + 1)?;
                }
            }
        },
        AtomHead::End { tag } => {
            bail!("unbalanced segment end with tag {tag}");
        }
    }
    Ok(())
}

/// Skip atoms until reaching a segment start with the given tag.
#[track_caller]
pub(crate) fn skip_until_start(source: &mut dyn StlvRead, tag: Tag) -> BundleResult<AtomHead> {
    loop {
        let head = expect_atom_head(source)?;
        if head.is_start() && head.tag() == tag {
            break Ok(head);
        }
        if tags::is_required(head.tag()) {
            bail!("found unexpected required tag {}", head.tag());
        }
        skip(source, head)?;
    }
}

/// Skip atoms until reaching a segment end with the given tag.
#[track_caller]
pub(crate) fn skip_until_end(source: &mut dyn StlvRead, tag: Tag) -> BundleResult<()> {
    loop {
        let head = expect_atom_head(source)?;
        if head.is_end() && head.tag() == tag {
            break Ok(());
        }
        if tags::is_required(head.tag()) {
            bail!("found unexpected required tag {}", head.tag());
        }
        skip(source, head)?;
    }
}

/// Skip atoms until reaching a value with the given tag.
#[track_caller]
pub(crate) fn skip_until_value(source: &mut dyn StlvRead, tag: Tag) -> BundleResult<NumBytes> {
    loop {
        let head = expect_atom_head(source)?;
        if let AtomHead::Value {
            tag: value_tag,
            length,
        } = head
            && value_tag == tag
        {
            break Ok(length);
        }
        if tags::is_required(head.tag()) {
            bail!("found unexpected required tag {}", head.tag());
        }
        skip(source, head)?;
    }
}

/// Expect a segment start.
#[track_caller]
pub(crate) fn expect_start(source: &mut dyn StlvRead, tag: Tag) -> BundleResult<AtomHead> {
    match expect_atom_head(source)? {
        atom @ AtomHead::Start { tag: start_tag, .. } if start_tag == tag => Ok(atom),
        atom => bail!("expected start of {tag}, found {atom:?}"),
    }
}

/// Expect the head of an atom.
#[track_caller]
pub(crate) fn expect_atom_head(source: &mut dyn StlvRead) -> BundleResult<AtomHead> {
    read_atom_head(source)
        .and_then(|head| head.ok_or_else(|| whatever!("unexpected end of bundle, expected atom")))
}

fn validate_block_metadata_lengths(
    block_hash_bytes: usize,
    hash_size: usize,
    block_size_bytes: Option<usize>,
) -> BundleResult<()> {
    if !block_hash_bytes.is_multiple_of(hash_size) {
        bail!("block-hash metadata length is not a multiple of the hash size");
    }
    if block_size_bytes.is_some_and(|length| !length.is_multiple_of(4)) {
        bail!("block-size metadata length is not a multiple of four");
    }
    Ok(())
}

fn uncompress_bytes(format: CompressionFormat, bytes: &[u8]) -> BundleResult<Vec<u8>> {
    uncompress_bytes_with_limit(format, bytes, PAYLOAD_HEADER_SIZE_LIMIT.raw as usize)
}

fn uncompress_bytes_with_limit(
    format: CompressionFormat,
    bytes: &[u8],
    limit: usize,
) -> BundleResult<Vec<u8>> {
    struct BoundedVecWriter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for BoundedVecWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other(
                    "decompressed bundle metadata exceeds size limit",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    match format {
        CompressionFormat::Xz => {
            let mut decoder = rugix_compression::XzDecoder::new();
            let mut output = BoundedVecWriter {
                bytes: Vec::new(),
                limit,
            };
            decoder
                .process(bytes, &mut output)
                .whatever("unable to decompress bundle metadata")?;
            decoder
                .finalize(&mut output)
                .whatever("unable to finalize bundle metadata decompression")?;
            Ok(output.bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use byte_calc::NumBytes;
    use si_crypto_hashes::HashAlgorithm;

    use crate::format;
    use crate::format::stlv::AtomHead;
    use crate::format::stlv::write_atom_head;
    use crate::format::stlv::write_segment_end;
    use crate::format::stlv::write_segment_start;
    use crate::format::tags;

    use super::BundleReader;
    use super::BundleSource;
    use super::uncompress_bytes;
    use super::uncompress_bytes_with_limit;
    use super::validate_block_metadata_lengths;

    fn stream(bytes: &[u8]) -> BundleSource {
        BundleSource::StreamSource(Box::new(std::io::Cursor::new(bytes.to_vec())))
    }

    fn empty_header() -> format::BundleHeader {
        format::BundleHeader {
            manifest: None,
            is_incremental: false,
            hash_algorithm: HashAlgorithm::Sha256,
            components: None,
            payload_index: Vec::new(),
        }
    }

    #[test]
    fn bundle_reader_requires_the_bundle_root_segment() {
        let mut bytes = Vec::new();
        write_segment_start(&mut bytes, tags::BUNDLE_HEADER).unwrap();
        bytes.extend(format::encode::to_vec(&empty_header(), tags::BUNDLE_HEADER));
        write_segment_start(&mut bytes, tags::PAYLOADS).unwrap();

        assert!(BundleReader::start(stream(&bytes), None).is_err());
    }

    #[test]
    fn bundle_reader_requires_each_payload_segment() {
        let payload_header = format::PayloadHeader {
            block_encoding: None,
        };
        let header_bytes = format::encode::to_vec(&payload_header, tags::PAYLOAD_HEADER);
        let hash_algorithm = HashAlgorithm::Sha256;
        let entry = format::PayloadEntry {
            type_slot: None,
            type_execute: None,
            type_app_file: None,
            type_app_archive: None,
            header_hash: format::Bytes {
                raw: hash_algorithm
                    .hash::<Box<[u8]>>(&header_bytes)
                    .raw()
                    .to_vec(),
            },
            file_hash: format::Bytes {
                raw: hash_algorithm.hash::<Box<[u8]>>(&[]).raw().to_vec(),
            },
            delta_encoding: None,
        };
        let mut bytes = Vec::new();
        write_segment_start(&mut bytes, tags::PAYLOAD_HEADER).unwrap();
        bytes.extend(header_bytes);
        write_atom_head(
            &mut bytes,
            AtomHead::Value {
                tag: tags::PAYLOAD_DATA,
                length: NumBytes::ZERO,
            },
        )
        .unwrap();
        let mut header = empty_header();
        header.payload_index.push(entry);
        let mut reader = BundleReader {
            cursor: super::Cursor::new(
                stream(&bytes),
                super::ReaderOptions::default().max_range_size,
            ),
            options: super::ReaderOptions::default(),
            header,
            header_raw: Vec::new(),
            signatures: None,
            next_payload: 0,
            finished: false,
        };

        assert!(reader.next_payload().is_err());
    }

    #[test]
    fn malformed_compressed_metadata_returns_an_error() {
        assert!(uncompress_bytes(rugix_compression::CompressionFormat::Xz, b"not xz").is_err());
    }

    #[test]
    fn block_metadata_lengths_must_be_exact() {
        assert!(validate_block_metadata_lengths(64, 32, Some(8)).is_ok());
        assert!(validate_block_metadata_lengths(63, 32, Some(8)).is_err());
        assert!(validate_block_metadata_lengths(64, 32, Some(7)).is_err());
    }

    #[test]
    fn bundle_reader_rejects_more_payloads_than_the_header_declares() {
        let mut bytes = Vec::new();
        write_segment_start(&mut bytes, tags::BUNDLE).unwrap();
        bytes.extend(format::encode::to_vec(&empty_header(), tags::BUNDLE_HEADER));
        write_segment_start(&mut bytes, tags::PAYLOADS).unwrap();
        write_segment_start(&mut bytes, tags::PAYLOAD).unwrap();
        write_segment_end(&mut bytes, tags::PAYLOAD).unwrap();
        write_segment_end(&mut bytes, tags::PAYLOADS).unwrap();
        write_segment_end(&mut bytes, tags::BUNDLE).unwrap();

        let mut reader = BundleReader::start(stream(&bytes), None).unwrap();
        assert!(reader.next_payload().is_err());
    }

    #[test]
    fn optional_tags_are_skipped_but_unknown_required_tags_are_rejected() {
        fn bundle_with_metadata(tag: crate::format::stlv::Tag) -> Vec<u8> {
            let mut bytes = Vec::new();
            write_segment_start(&mut bytes, tags::BUNDLE).unwrap();
            bytes.extend(format::encode::to_vec(&empty_header(), tags::BUNDLE_HEADER));
            write_atom_head(
                &mut bytes,
                AtomHead::Value {
                    tag,
                    length: NumBytes::ZERO,
                },
            )
            .unwrap();
            write_segment_start(&mut bytes, tags::PAYLOADS).unwrap();
            write_segment_end(&mut bytes, tags::PAYLOADS).unwrap();
            write_segment_end(&mut bytes, tags::BUNDLE).unwrap();
            bytes
        }

        let optional = crate::format::stlv::Tag::from_bytes([0x80, 1, 2, 3]);
        let required = crate::format::stlv::Tag::from_bytes([0x01, 1, 2, 3]);
        let bytes = bundle_with_metadata(optional);
        assert!(BundleReader::start(stream(&bytes), None).is_ok());
        let bytes = bundle_with_metadata(required);
        assert!(BundleReader::start(stream(&bytes), None).is_err());
    }

    #[test]
    fn decompressed_metadata_has_a_hard_size_limit() {
        use rugix_compression::ByteProcessor;

        let mut compressed = Vec::new();
        let mut encoder = rugix_compression::XzEncoder::new(1);
        encoder.process(&[0; 128], &mut compressed).unwrap();
        encoder.finalize(&mut compressed).unwrap();
        assert!(
            uncompress_bytes_with_limit(rugix_compression::CompressionFormat::Xz, &compressed, 64,)
                .is_err()
        );
    }

    #[test]
    fn malformed_and_truncated_bundle_corpus_returns_errors() {
        fn read_all(bytes: &[u8]) -> crate::BundleResult<()> {
            let mut reader = BundleReader::start(stream(bytes), None)?;
            while let Some(payload) = reader.next_payload()? {
                payload.skip()?;
            }
            Ok(())
        }

        let mut root_only = Vec::new();
        write_segment_start(&mut root_only, tags::BUNDLE).unwrap();

        let mut missing_closing_segments = Vec::new();
        write_segment_start(&mut missing_closing_segments, tags::BUNDLE).unwrap();
        missing_closing_segments
            .extend(format::encode::to_vec(&empty_header(), tags::BUNDLE_HEADER));
        write_segment_start(&mut missing_closing_segments, tags::PAYLOADS).unwrap();

        for malformed in [
            Vec::new(),
            vec![0x01, 0x02],
            root_only,
            missing_closing_segments,
        ] {
            assert!(read_all(&malformed).is_err(), "accepted {malformed:02x?}");
        }
    }
}
