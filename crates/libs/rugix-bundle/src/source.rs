//! Infrastructure for pluggable bundle sources.
//!
//! [Bundle sources][BundleSource] must provide functionality for reading byte slices and
//! for skipping a certain number of bytes. Skipping could be implemented by reading
//! the bytes that should be skipped. Reads should be buffered, as we are reading small
//! slices at a time. In Rugix Ctrl, we will implement a bundle source for streaming via
//! HTTP using range queries for efficient skipping.

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{self};
use std::marker::PhantomData;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::ResultExt;
use reportify::bail;
use si_crypto_hashes::HashAlgorithm;
use si_crypto_hashes::HashDigest;
use si_crypto_hashes::Hasher;

use crate::BundleResult;

/// Dyn-compatible streaming bundle source.
pub trait BundleSource {
    /// Read some bytes from the source into the given slice, returning how many bytes
    /// were read.
    ///
    /// A return value of `0` indicates the end of the bundle.
    fn read(&mut self, slice: &mut [u8]) -> BundleResult<usize>;

    /// Skip the given number of bytes.
    fn skip(&mut self, length: NumBytes) -> BundleResult<()>;

    /// Hint the size of the next chunk we are going to read to the source.
    #[expect(unused_variables)]
    fn hint_next_chunk(&mut self, length: NumBytes) {}

    /// Read an exact number of bytes into the provided slice.
    fn read_exact(&mut self, mut slice: &mut [u8]) -> BundleResult<()> {
        while !slice.is_empty() {
            let read = self.read(slice)?;
            if read == 0 {
                bail!("unexpected end of bundle");
            }
            slice = &mut slice[read..];
        }
        Ok(())
    }

    fn bytes_read(&self) -> Option<NumBytes> {
        None
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        None
    }
}

impl<S: BundleSource + ?Sized> BundleSource for &mut S {
    fn read(&mut self, slice: &mut [u8]) -> BundleResult<usize> {
        (**self).read(slice)
    }

    fn skip(&mut self, length: NumBytes) -> BundleResult<()> {
        (**self).skip(length)
    }

    fn read_exact(&mut self, slice: &mut [u8]) -> BundleResult<()> {
        (**self).read_exact(slice)
    }

    fn bytes_read(&self) -> Option<NumBytes> {
        (**self).bytes_read()
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        (**self).bytes_total()
    }
}

impl<S: BundleSource + ?Sized> BundleSource for Box<S> {
    fn read(&mut self, slice: &mut [u8]) -> BundleResult<usize> {
        (**self).read(slice)
    }

    fn skip(&mut self, length: NumBytes) -> BundleResult<()> {
        (**self).skip(length)
    }

    fn read_exact(&mut self, slice: &mut [u8]) -> BundleResult<()> {
        (**self).read_exact(slice)
    }

    fn bytes_read(&self) -> Option<NumBytes> {
        (**self).bytes_read()
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        (**self).bytes_total()
    }
}

/// Bundle source backed by an arbitrary [buffered reader][BufRead].
pub struct ReaderSource<R, S> {
    /// Underlying reader.
    reader: R,
    /// Bytes read.
    bytes_read: NumBytes,
    /// Total bytes.
    bytes_total: Option<NumBytes>,
    /// [`Skip`] implementation to use.
    _phantom_skip: PhantomData<S>,
}

impl<R, S: Skip<R>> ReaderSource<R, S> {
    /// Create a source from the provided reader.
    pub fn new(mut reader: R) -> Self {
        let total_bytes = S::bytes_total(&mut reader);
        Self {
            reader,
            bytes_read: NumBytes::ZERO,
            bytes_total: total_bytes,
            _phantom_skip: PhantomData,
        }
    }

    /// Convert the source back into the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: Read, S: Skip<BufReader<R>>> ReaderSource<BufReader<R>, S> {
    /// Create a source from the provided unbuffered reader.
    pub fn from_unbuffered(reader: R) -> Self {
        Self::new(BufReader::new(reader))
    }
}

impl<R: BufRead, S: Skip<R>> BundleSource for ReaderSource<R, S> {
    fn bytes_read(&self) -> Option<NumBytes> {
        Some(self.bytes_read)
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        self.bytes_total
    }

    fn read(&mut self, slice: &mut [u8]) -> BundleResult<usize> {
        let read = self
            .reader
            .read(slice)
            .whatever("unable to read from bundle")?;
        self.bytes_read += read as u64;
        Ok(read)
    }

    fn skip(&mut self, length: NumBytes) -> BundleResult<()> {
        S::skip(&mut self.reader, length).whatever("unable to skip bytes in reader")?;
        self.bytes_read += length.raw;
        Ok(())
    }
}

/// Trait for skipping bytes from a reader.
pub trait Skip<R> {
    /// Total number of bytes.
    fn bytes_total(reader: &mut R) -> Option<NumBytes>;

    /// Skip the given number of bytes.
    fn skip(reader: &mut R, skip: NumBytes) -> io::Result<()>;
}

/// Skip bytes by reading.
pub struct SkipRead(());

impl<R: BufRead> Skip<R> for SkipRead {
    fn bytes_total(_: &mut R) -> Option<NumBytes> {
        None
    }

    fn skip(reader: &mut R, mut skip: NumBytes) -> io::Result<()> {
        while skip > 0 {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let consume = buffer.byte_len().min(skip);
            reader.consume(consume.raw as usize);
            skip -= consume;
        }
        Ok(())
    }
}

/// Skip bytes by seeking.
pub struct SkipSeek(());

impl<R: Seek> Skip<R> for SkipSeek {
    fn bytes_total(reader: &mut R) -> Option<NumBytes> {
        let current_position = reader.stream_position().ok()?;
        let end_position = reader.seek(SeekFrom::End(0)).ok()?;
        reader.seek(SeekFrom::Start(current_position)).ok()?;
        Some(NumBytes::from(end_position - current_position))
    }

    fn skip(reader: &mut R, skip: NumBytes) -> io::Result<()> {
        let skip = i64::try_from(skip.raw)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "skip is too large"))?;
        reader.seek_relative(skip)
    }
}

/// Bundle source backed by a [local file][File].
pub type FileSource = ReaderSource<BufReader<File>, SkipSeek>;

/// Bundle source backed by an in-memory slice.
pub type SliceSource<'s> = ReaderSource<io::Cursor<&'s [u8]>, SkipSeek>;

/// Create a [`SliceSource`] from a slice.
pub fn from_slice<'s, S: AsRef<[u8]>>(slice: &'s S) -> SliceSource<'s> {
    SliceSource::new(io::Cursor::new(slice.as_ref()))
}

/// Hashes a bundle source or a part of it.
///
/// Wraps a source and passes all data through a hash algorithm.
pub struct SourceHasher<S> {
    /// Underlying hasher.
    hasher: Option<Hasher>,
    /// Underlying source.
    source: S,
}

impl<S> SourceHasher<S> {
    /// Create an new source hasher.
    pub fn new(source: S, algorithm: Option<HashAlgorithm>) -> Self {
        Self {
            hasher: algorithm.map(HashAlgorithm::hasher),
            source,
        }
    }

    /// Convert back to the underlying source.
    pub fn into_inner(self) -> S {
        self.source
    }

    /// Return the underlying source and the computed hash.
    pub fn finalize(self) -> (S, Option<HashDigest>) {
        (self.source, self.hasher.map(Hasher::finalize))
    }
}

impl<S: BundleSource> BundleSource for SourceHasher<S> {
    fn read(&mut self, slice: &mut [u8]) -> BundleResult<usize> {
        let read = self.source.read(slice)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(&slice[..read]);
        }
        Ok(read)
    }

    fn skip(&mut self, length: byte_calc::NumBytes) -> BundleResult<()> {
        if self.hasher.is_some() {
            // We need to include the bytes that should be skipped in the hash. We use
            // a small buffer on the stack to read through the skipped bytes.
            let mut remaining = length;
            let mut buffer = [0; 256];
            while remaining > 0 {
                let chunk = remaining.raw.min(256) as usize;
                let read = self.read(&mut buffer[..chunk])?;
                if read == 0 {
                    bail!("unexpected end of bundle");
                }
                remaining -= read as u64;
            }
            Ok(())
        } else {
            self.source.skip(length)
        }
    }

    fn bytes_read(&self) -> Option<NumBytes> {
        self.source.bytes_read()
    }

    fn bytes_total(&self) -> Option<NumBytes> {
        self.source.bytes_total()
    }
}
