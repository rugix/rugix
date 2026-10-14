//! Functionality for dividing byte streams into blocks.

use std::error::Error;
use std::str::FromStr;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use casync::CasyncChunker;
use casync::CasyncChunkerOptions;
use serde::de::Unexpected;
use serde::Deserialize;

pub mod casync;

#[derive(Debug)]
pub struct InvalidOptionsError {
    wrapped: Box<dyn Send + Error>,
}

impl std::fmt::Display for InvalidOptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.wrapped.fmt(f)
    }
}

impl Error for InvalidOptionsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.wrapped)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidChunkerAlgorithmError {
    reason: &'static str,
}

impl std::fmt::Display for InvalidChunkerAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

impl Error for InvalidChunkerAlgorithmError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChunkerAlgorithm {
    Casync { avg_block_size_kib: u16 },
    Fixed { block_size_kib: u16 },
}

impl ChunkerAlgorithm {
    pub fn is_fixed(&self) -> bool {
        matches!(self, Self::Fixed { .. })
    }

    pub fn chunker(&self) -> Result<AnyChunker, InvalidOptionsError> {
        match self {
            ChunkerAlgorithm::Casync { avg_block_size_kib } => Ok(AnyChunker::Casync(
                casync::CasyncChunker::new(CasyncChunkerOptions::avg(NumBytes::kibibytes(
                    (*avg_block_size_kib).into(),
                )))
                .map_err(|error| InvalidOptionsError {
                    wrapped: Box::new(error),
                })?,
            )),
            ChunkerAlgorithm::Fixed { block_size_kib } => Ok(AnyChunker::Fixed(
                FixedSizeChunker::new(NumBytes::kibibytes((*block_size_kib).into())),
            )),
        }
    }
}

impl std::fmt::Display for ChunkerAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkerAlgorithm::Casync { avg_block_size_kib } => {
                write!(f, "casync-{avg_block_size_kib}")
            }
            ChunkerAlgorithm::Fixed { block_size_kib } => {
                write!(f, "fixed-{block_size_kib}")
            }
        }
    }
}

impl FromStr for ChunkerAlgorithm {
    type Err = InvalidChunkerAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((kind, options)) = s.split_once('-') {
            match kind {
                "fixed" => Ok(Self::Fixed {
                    block_size_kib: options.parse().map_err(|_| InvalidChunkerAlgorithmError {
                        reason: "invalid options for fixed chunker",
                    })?,
                }),
                "casync" => Ok(Self::Casync {
                    avg_block_size_kib: options.parse().map_err(|_| {
                        InvalidChunkerAlgorithmError {
                            reason: "invalid options for casync chunker",
                        }
                    })?,
                }),
                _ => Err(InvalidChunkerAlgorithmError {
                    reason: "invalid algorithm kind",
                }),
            }
        } else {
            Err(InvalidChunkerAlgorithmError {
                reason: "missing `-` delimiter",
            })
        }
    }
}

sidex::types::impl_text!(ChunkerAlgorithm);

impl serde::Serialize for ChunkerAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChunkerAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        string.parse().map_err(|_| {
            serde::de::Error::invalid_value(Unexpected::Str(&string), &"chunker algorithm")
        })
    }
}

#[derive(Debug)]
pub enum AnyChunker {
    Fixed(FixedSizeChunker),
    Casync(CasyncChunker),
}

impl Chunker for AnyChunker {
    fn scan(&mut self, bytes: &[u8]) -> Option<usize> {
        match self {
            AnyChunker::Fixed(chunker) => chunker.scan(bytes),
            AnyChunker::Casync(chunker) => chunker.scan(bytes),
        }
    }
}

/// Trait for chunking byte streams into blocks.
pub trait Chunker {
    /// Scan for the next block boundary and return it.
    ///
    /// The function returns an offset of the chunk into the provided slice.
    fn scan(&mut self, bytes: &[u8]) -> Option<usize>;

    /// Iterator over the chunks of a byte slice.
    fn chunks(mut self, mut bytes: &[u8]) -> impl Iterator<Item = &[u8]>
    where
        // We put this bound here to make the trait dyn-compatible.
        Self: Sized,
    {
        std::iter::from_fn(move || {
            if bytes.is_empty() {
                None
            } else if let Some(offset) = self.scan(bytes) {
                let chunk = &bytes[..offset];
                bytes = &bytes[offset..];
                Some(chunk)
            } else {
                let chunk = bytes;
                bytes = &[];
                Some(chunk)
            }
        })
    }
}

/// [`Chunker`] for fixed size blocks.
#[derive(Debug, Clone)]
pub struct FixedSizeChunker {
    /// Block size.
    block_size: NumBytes,
    /// Remaining bytes of the current block.
    remaining: NumBytes,
}

impl FixedSizeChunker {
    /// Create a new fixed size chunker.
    pub fn new(block_size: NumBytes) -> Self {
        assert_ne!(block_size, 0, "block size must not be zero");
        Self {
            block_size,
            remaining: block_size,
        }
    }
}

impl Chunker for FixedSizeChunker {
    fn scan(&mut self, bytes: &[u8]) -> Option<usize> {
        let take = self.remaining.min(bytes.byte_len());
        self.remaining -= take;
        if self.remaining == 0 {
            self.remaining = self.block_size;
            Some(take.raw as usize)
        } else {
            None
        }
    }
}
