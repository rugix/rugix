//! Reading stored files.

use std::io;
use std::io::Read;

use crate::chunk;
use crate::layout::Layout;
use crate::layout::StoreLock;
use crate::object::Object;

/// Reads the content of a stored file, verifying every chunk.
pub struct ObjectReader {
    layout: Layout,
    _lock: Option<StoreLock>,
    object: Object,
    next_chunk: usize,
    buffer: Vec<u8>,
    position: usize,
}

impl ObjectReader {
    pub(crate) fn new(layout: Layout, lock: Option<StoreLock>, object: Object) -> Self {
        Self {
            layout,
            _lock: lock,
            object,
            next_chunk: 0,
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Load the next chunk into the buffer, returning `false` at the end.
    fn load_next_chunk(&mut self) -> io::Result<bool> {
        let Some((hash, size)) = self.object.chunk(self.next_chunk) else {
            return Ok(false);
        };
        let algorithm = self.object.algorithm();
        let (path, compression) = self.layout.find_chunk(algorithm, hash).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("chunk {} is missing", hex::encode(hash)),
            )
        })?;
        let data = chunk::read(&path, compression, algorithm, hash)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))?;
        if data.len() as u64 != u64::from(size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk {} has an unexpected size", hex::encode(hash)),
            ));
        }
        self.buffer = data;
        self.position = 0;
        self.next_chunk += 1;
        Ok(true)
    }
}

impl Read for ObjectReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.position == self.buffer.len() {
            if !self.load_next_chunk()? {
                return Ok(0);
            }
        }
        let available = &self.buffer[self.position..];
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        self.position += count;
        Ok(count)
    }
}
