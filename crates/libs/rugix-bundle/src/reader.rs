use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;

use block_provider::StoredBlockProvider;
use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use reportify::whatever;
use rugix_compression::ByteProcessor;
use rugix_compression::CompressionFormat;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use tracing::error;
use tracing::trace;
use tracing::warn;

use crate::BUNDLE_HEADER_SIZE_LIMIT;
use crate::BundleResult;
use crate::PAYLOAD_HEADER_SIZE_LIMIT;
use crate::SIGNATURES_SIZE_LIMIT;
use crate::block_encoding::block_index::BlockId;
use crate::block_encoding::block_index::RawBlockIndex;
use crate::block_encoding::block_table::BlockTable;
use crate::format::Signatures;
use crate::format::decode::decode_slice;
use crate::format::stlv::AtomHead;
use crate::format::stlv::Tag;
use crate::format::stlv::read_atom_head;
use crate::format::stlv::skip;
use crate::format::stlv::write_atom_head;
use crate::format::tags;
use crate::format::{self};
use crate::source::BundleSource;

pub mod block_provider;

pub struct BundleReader<S> {
    source: S,
    header: format::BundleHeader,
    header_raw: Vec<u8>,
    signatures: Option<Signatures>,
    next_payload: usize,
}

impl<S: BundleSource> BundleReader<S> {
    pub fn start(mut source: S, header_hash: Option<HashDigest>) -> BundleResult<Self> {
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
            source,
            header,
            signatures,
            header_raw: bundle_header,
            next_payload: 0,
        })
    }

    pub fn header(&self) -> &format::BundleHeader {
        &self.header
    }

    pub fn header_raw(&self) -> &[u8] {
        &self.header_raw
    }

    pub fn header_hash(&self, algorithm: HashAlgorithm) -> HashDigest {
        algorithm.hash(&self.header_raw)
    }

    pub fn signatures(&self) -> Option<&Signatures> {
        self.signatures.as_ref()
    }

    pub fn next_payload(&mut self) -> BundleResult<Option<PayloadReader<'_, S>>> {
        if self.next_payload >= self.header.payload_index.len() {
            return Ok(None);
        }
        let this_payload = self.next_payload;
        self.next_payload += 1;
        let entry = &self.header.payload_index[this_payload];
        let _ = expect_start(&mut self.source, tags::PAYLOAD)?;
        let header_atom = skip_until_start(&mut self.source, tags::PAYLOAD_HEADER)?;
        let mut header_bytes = Vec::new();
        read_into_vec(
            &mut self.source,
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
        let remaining_data = skip_until_value(&mut self.source, tags::PAYLOAD_DATA)?;
        Ok(Some(PayloadReader {
            idx: this_payload,
            reader: self,
            header: decode_slice(&header_bytes)?,
            remaining_data,
        }))
    }
}

/// Read optional bundle metadata advancing the source to the payload section.
pub fn read_optional_metadata(source: &mut dyn BundleSource) -> BundleResult<Option<Signatures>> {
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

pub struct PayloadReader<'r, S> {
    idx: usize,
    reader: &'r mut BundleReader<S>,
    header: format::PayloadHeader,
    remaining_data: NumBytes,
}

impl<'r, S: BundleSource> PayloadReader<'r, S> {
    pub fn reader(&self) -> &BundleReader<S> {
        self.reader
    }

    pub fn idx(&self) -> usize {
        self.idx
    }

    pub fn header(&self) -> &format::PayloadHeader {
        &self.header
    }

    pub fn entry(&self) -> &format::PayloadEntry {
        &self.reader.header().payload_index[self.idx]
    }

    pub fn skip(self) -> BundleResult<()> {
        self.reader.source.skip(self.remaining_data)?;
        skip_until_end(&mut self.reader.source, tags::PAYLOAD)?;
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
        let read = self.reader.source.read(&mut buf[..max_chunk])?;
        self.remaining_data -=
            NumBytes::expect_from_usize(read, "bytes actually read always fit into u64");
        Ok(read)
    }

    pub fn decode_into<T: PayloadTarget, F: FnMut(&S)>(
        mut self,
        mut target: T,
        provider: Option<&dyn StoredBlockProvider>,
        progress: &mut F,
    ) -> BundleResult<DecodedPayloadInfo> {
        let mut buffer = vec![0; 8192];
        let mut payload_hasher = self.reader.header.hash_algorithm.hasher();
        let mut bytes_written = NumBytes::ZERO;
        if let Some(block_encoding) = self.header.block_encoding {
            let mut block_index_raw = block_encoding.block_hashes.raw;
            if let Some(format) = block_encoding.compression {
                block_index_raw = uncompress_bytes(format, &block_index_raw);
            }
            let block_sizes = block_encoding.block_sizes.map(|block_sizes| {
                let mut block_sizes = block_sizes.raw;
                if let Some(format) = block_encoding.compression {
                    block_sizes = uncompress_bytes(format, &block_sizes);
                }
                let mut decoded_sizes = Vec::new();
                for chunk in block_sizes.chunks_exact(4) {
                    decoded_sizes.push(u32::from_be_bytes(chunk.try_into().unwrap()))
                }
                decoded_sizes
            });
            let fixed_block_size = match block_encoding.chunker {
                rugix_chunker::ChunkerAlgorithm::Casync { .. } => None,
                rugix_chunker::ChunkerAlgorithm::Fixed { block_size_kib } => {
                    Some((block_size_kib as u32) * 1024)
                }
            };
            if fixed_block_size.is_none() && block_sizes.is_none() {
                bail!("variable-size index needs block sizes")
            }
            let raw_index = RawBlockIndex::new(&block_index_raw, block_encoding.hash_algorithm);
            let mut table = BlockTable::new();
            let mut current_target_offset = NumBytes::ZERO;
            let num_blocks = block_index_raw.len() / block_encoding.hash_algorithm.hash_size();
            let mut target_offsets = Vec::<NumBytes>::with_capacity(num_blocks);
            let mut target_sizes = Vec::<NumBytes>::with_capacity(num_blocks);
            let mut next_size_idx = 0;

            for (idx, block_hash) in block_index_raw
                .chunks_exact(block_encoding.hash_algorithm.hash_size())
                .enumerate()
            {
                let block_id = BlockId { raw: idx };
                let is_fresh = table.insert_raw(&raw_index, block_id);
                let first_idx = table.get_raw(&raw_index, block_hash).unwrap();
                // Get the data, afterwards buffer should contain the uncompressed block.
                if is_fresh || !block_encoding.deduplicated {
                    // We need to read the block from the source.
                    // Determine the size of the block in the encoding.
                    let block_size = (block_sizes
                        .as_ref()
                        .map(|sizes| sizes[next_size_idx])
                        .or(fixed_block_size)
                        .unwrap() as u64)
                        .min(self.remaining_data.raw);
                    next_size_idx += 1;
                    let mut block_available = false;
                    if let Some(stored_block) = provider.and_then(|p| p.query(block_hash)) {
                        trace!(
                            block_idx = idx,
                            block_size_bundle = block_size,
                            stored_block_file = ?stored_block.file,
                            stored_block_offset = stored_block.offset.raw,
                            stored_block_size = stored_block.size.raw,
                            "using stored block from provider"
                        );
                        buffer.resize(
                            usize::try_from(stored_block.size)
                                .whatever("stored block size does not fit into usize")?,
                            0,
                        );
                        let mut source_file = std::fs::File::open(&stored_block.file)
                            .whatever("unable to open file")?;
                        source_file
                            .seek(std::io::SeekFrom::Start(stored_block.offset.raw))
                            .whatever("unable to seek")?;
                        source_file
                            .read_exact(&mut buffer)
                            .whatever("unable to read block")?;
                        // At this point, we have the uncompressed block in the buffer.
                        let hash_found = block_encoding.hash_algorithm.hash::<Box<[u8]>>(&buffer);
                        if hash_found.raw() != block_hash {
                            warn!(
                                block_idx = idx,
                                hash_expected = block_hash,
                                hash_found = hash_found.raw(),
                                "invalid block hash, reading from source instead"
                            );
                        } else {
                            // We already have the block, let's skip it.
                            self.reader.source.skip(block_size.into())?;
                            self.remaining_data -= block_size;
                            block_available = true;
                        }
                    }
                    if !block_available {
                        buffer.resize(block_size.try_into().unwrap(), 0);
                        self.reader.source.hint_next_chunk(block_size.into());
                        self.reader.source.read_exact(&mut buffer)?;
                        self.remaining_data -= buffer.byte_len();
                        if let Some(format) = block_encoding.compression {
                            buffer = uncompress_bytes(format, &buffer);
                        }
                        trace!(
                            block_idx = idx,
                            block_size = buffer.len(),
                            block_size_bundle = block_size,
                            "using block from bundle"
                        );
                        // At this point, we have the uncompressed block in the buffer.
                        let hash_found = block_encoding.hash_algorithm.hash::<Box<[u8]>>(&buffer);
                        if hash_found.raw() != block_hash {
                            error!(
                                block_idx = idx,
                                hash_expected = block_hash,
                                hash_found = hash_found.raw(),
                                "invalid block hash"
                            );
                            bail!("invalid block hash of block {idx} of size {}", buffer.len());
                        }
                    }
                } else {
                    // The block has been deduplicated, read from target.
                    assert!(first_idx.raw < idx);
                    let offset = target_offsets[first_idx.raw];
                    let size = target_sizes[first_idx.raw];
                    trace!(
                        block_idx = idx,
                        block_offset = offset.raw,
                        block_size = size.raw,
                        "using deduplicated block from target"
                    );
                    target.read_block(offset, size, &mut buffer)?;
                    // At this point, we have the uncompressed block in the buffer.
                    let hash_found = block_encoding.hash_algorithm.hash::<Box<[u8]>>(&buffer);
                    if hash_found.raw() != block_hash {
                        error!(
                            block_idx = idx,
                            hash_expected = block_hash,
                            hash_found = hash_found.raw(),
                            "invalid block hash"
                        );
                        bail!("invalid block hash of block {idx} of size {}", buffer.len());
                    }
                }
                target_offsets.push(current_target_offset);
                target_sizes.push(buffer.byte_len());
                current_target_offset += buffer.byte_len();
                target.write(&buffer)?;
                bytes_written += buffer.byte_len();
                payload_hasher.update(&buffer);
                progress(&self.reader.source);
            }
        } else {
            // The next chunk is the whole payload.
            self.reader.source.hint_next_chunk(self.remaining_data);
            loop {
                let read = self.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                target.write(&buffer[..read])?;
                payload_hasher.update(&buffer[..read]);
                bytes_written +=
                    NumBytes::expect_from_usize(read, "bytes actually read always fit into u64");
                progress(&self.reader.source);
            }
        }
        let payload_hash = payload_hasher.finalize();
        if payload_hash.raw() != self.reader.header.payload_index[self.idx].file_hash.raw {
            bail!("payload hash mismatch");
        }
        target.finalize()?;
        skip_until_end(&mut self.reader.source, tags::PAYLOAD)?;
        Ok(DecodedPayloadInfo {
            hash: payload_hash,
            size: bytes_written,
        })
    }
}

pub struct DecodedPayloadInfo {
    pub hash: HashDigest,
    pub size: NumBytes,
}

pub trait PayloadTarget: Sized {
    fn write(&mut self, bytes: &[u8]) -> BundleResult<()>;

    #[expect(unused_variables)]
    fn read_block(
        &mut self,
        offset: NumBytes,
        size: NumBytes,
        buffer: &mut Vec<u8>,
    ) -> BundleResult<()> {
        bail!("target does not support reading blocks");
    }

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
        self.read_exact(buffer).whatever("unable to read")?;
        self.seek(std::io::SeekFrom::Start(current_position))
            .whatever("unable to seek")?;
        Ok(())
    }
}

/// Read next segment or value into vector.
pub fn read_into_vec(
    source: &mut dyn BundleSource,
    output: &mut Vec<u8>,
    head: AtomHead,
    limit: NumBytes,
) -> BundleResult<()> {
    write_atom_head(output, head).unwrap();
    match head {
        AtomHead::Value { length, .. } => {
            if output.byte_len() + length < limit {
                source.hint_next_chunk(length);
                let offset = output.len();
                output.resize(offset + length.raw as usize, 0);
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
                    write_atom_head(output, atom).unwrap();
                    break;
                }
                atom => {
                    read_into_vec(source, output, atom, limit)?;
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
pub fn skip_until_start(source: &mut dyn BundleSource, tag: Tag) -> BundleResult<AtomHead> {
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
pub fn skip_until_end(source: &mut dyn BundleSource, tag: Tag) -> BundleResult<()> {
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
pub fn skip_until_value(source: &mut dyn BundleSource, tag: Tag) -> BundleResult<NumBytes> {
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
pub fn expect_start(source: &mut dyn BundleSource, tag: Tag) -> BundleResult<AtomHead> {
    match expect_atom_head(source)? {
        atom @ AtomHead::Start { tag: start_tag, .. } if start_tag == tag => Ok(atom),
        atom => bail!("expected start of {tag}, found {atom:?}"),
    }
}

/// Expect the head of an atom.
#[track_caller]
pub fn expect_atom_head(source: &mut dyn BundleSource) -> BundleResult<AtomHead> {
    read_atom_head(source)
        .and_then(|head| head.ok_or_else(|| whatever!("unexpected end of bundle, expected atom")))
}

/// Expect a segment start.
#[track_caller]
pub fn expect_value(source: &mut dyn BundleSource, tag: Tag) -> BundleResult<NumBytes> {
    match expect_atom_head(source)? {
        AtomHead::Value {
            tag: value_tag,
            length,
        } if value_tag == tag => Ok(length),
        atom => bail!("expected value of {tag}, found {atom:?}"),
    }
}

fn uncompress_bytes(format: CompressionFormat, bytes: &[u8]) -> Vec<u8> {
    match format {
        CompressionFormat::Xz => {
            let mut decoder = rugix_compression::XzDecoder::new();
            let mut output = Vec::new();
            decoder.process(bytes, &mut output).unwrap();
            decoder.finalize(&mut output).unwrap();
            output
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
    use crate::format::stlv::write_segment_start;
    use crate::format::tags;
    use crate::source::from_slice;

    use super::BundleReader;

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

        assert!(BundleReader::start(from_slice(&bytes), None).is_err());
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
            source: from_slice(&bytes),
            header,
            header_raw: Vec::new(),
            signatures: None,
            next_payload: 0,
        };

        assert!(reader.next_payload().is_err());
    }
}
