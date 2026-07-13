//! *Structured Tag-Length-Value* (STLV) encoding.
//!
//! The STLV encoding specified and implemented here serves as the basis for Rugix Ctrl's
//! bundle format. It has been designed to facilitate streaming, random accesses, and
//! forward as well as backward compatibility of bundles.
//!
//!
//! # STLV Streams
//!
//! An STLV *stream* is a sequence of STLV *atoms*. Each atom consists of a *tag*, an
//! *indicator* byte, and optionally of a *length* and a *value*:
//!
//! ```plain
//! <atom>  ::=  <tag> <indicator> [<length>] [<value>]
//! ```
//!
//! We refer to the byte sequence of an atom without the value as the *atom head*.
//!
//! The tag has a fixed size of four bytes. Tags have an application-defined
//! interpretation and can be freely chosen. In particular, applications may encode
//! additional information into tags, e.g., whether an atom may be ignored.
//!
//! The first bit of the indicator byte indicates whether the atom is a *value* atom:
//!
//! ```plain
//!  7 6 5 4 3 2 1 0
//!  |
//!  \-- IS_VALUE
//! ```
//!
//! If the atom is a value atom, i.e., if the `IS_VALUE` bit is set, then the remaining
//! seven bits (partially) encode the length of the value. Otherwise, the atom is a
//! *segmentation* atom and the second bit indicates whether the atom *starts* or *ends*
//! a *segment*:
//!
//! ```plain
//!  7 6 5 4 3 2 1 0
//!    |
//!    \-- IS_START
//! ```
//!
//! In this case, the remaining six bits must be zero.
//!
//! ### Value Atoms
//!
//! Value atoms are typically used to encode primitive values such as integers and
//! strings. The STLV encoding makes no assumptions about values and treats them as raw
//! byte sequences. It is up to the application to further interpret values.
//!
//! The length of the value in bytes is the sum of the length encoded in the indicator and
//! the subsequent optional length. If the length encoded in the indicator is 127
//! (`0b111_1111`), then the optional length must be present. Otherwise, the indicator
//! must be directly followed by the value. The optional length is encoded as a
//! variable-length integer using a typical base 128 encoding where the first bit of a
//! byte indicates whether a byte follows and the remaining seven bits are a base 128
//! digit.
//!
//! ### Segmentation Atoms
//!
//! Segmentation atoms are used to structure a stream. They neither have a length nor a
//! value. Every segmentation atom starting a segment should eventually be followed by a
//! segmentation atom, with the same tag, ending the segment. As a result, an STLV stream
//! describes a tree whose nodes are labeled with tags and whose leaves are values.
//!
//!
//! # API and Example
//!
//! This module provides low-level functions for reading and writing STLV streams.
//!
//! ```rust
//! # use rugix_bundle::format::stlv::{
//! #   read_atom_head, skip, write_atom_head, write_segment_start,
//! #   write_segment_end, write_value, Tag, AtomHead
//! # };
//! #
//! use std::io::{self, Write, Read};
//!
//! use rugix_bundle::source::{BundleSource, from_slice};
//!
//! const SEGMENT_TAG: Tag = Tag::from_bytes([0xAA, 0xBB, 0xCC, 0xDD]);
//! const VALUE_TAG: Tag = Tag::from_bytes([0x44, 0x33, 0x22, 0x11]);
//!
//! let mut buffer = io::Cursor::new(Vec::new());
//!
//! write_segment_start(&mut buffer, SEGMENT_TAG);
//! let value = "Hello World!";
//! write_value(&mut buffer, VALUE_TAG, value.as_bytes());
//! write_segment_end(&mut buffer, SEGMENT_TAG);
//!
//! let mut source = from_slice(buffer.get_ref());
//! assert_eq!(
//!     read_atom_head(&mut source).unwrap(),
//!     Some(AtomHead::start(SEGMENT_TAG))
//! );
//! let Some(AtomHead::Value {
//!     tag: VALUE_TAG,
//!     length,
//! }) = read_atom_head(&mut source).unwrap()
//! else {
//!     panic!("segment should contain a value");
//! };
//! let mut value_buffer = vec![0; length.raw as usize];
//! source.read_exact(&mut value_buffer);
//! assert_eq!(value_buffer, value.as_bytes());
//! assert_eq!(
//!     read_atom_head(&mut source).unwrap(),
//!     Some(AtomHead::end(SEGMENT_TAG))
//! );
//! assert_eq!(
//!     read_atom_head(&mut source).unwrap(),
//!     None
//! );
//!
//! let mut source = from_slice(buffer.get_ref());
//! let head = read_atom_head(&mut source).unwrap().unwrap();
//! skip(&mut source, head).unwrap();
//! assert_eq!(source.into_inner().position(), buffer.get_ref().len() as u64);
//! ```
//!
//! ##### ❗️ Important Notes
//!
//! Readers and writers should be buffered as we are performing small reads and writes.
//!
//!
//! # Advantageous Properties
//!
//! STLV streams as specified here have several advantageous properties:
//!
//! - STLV streams can be parsed generically without knowing any of the tags and the
//!   interpretation of values.
//! - STLV streams can be streamed atom by atom and without knowing the size of segments
//!   beforehand.
//! - STLV streams are compositional; an STLV stream can be inserted between any two
//!   atoms.
//! - Unknown value atoms and segments can be skipped by readers enabling forward
//!   compatibility.
//! - Being binary, STLV streams can be more compact than text-based formats such as JSON
//!   or XML.
//! - STLV streams allow for the detection of truncated and invalid inputs.

use std::fmt;
use std::io::Write;
use std::io::{self};

use console::style;

use byte_calc::ByteLen;
use byte_calc::NumBytes;
use reportify::bail;

use crate::BundleResult;
use crate::source::BundleSource;

/// Tag size (4 bytes).
pub const TAG_SIZE: usize = 4;

/// Bit mask for the `IS_VALUE` bit.
const IS_VALUE_MASK: u8 = 1 << 7;
/// Bit mask for the `IS_START` bit.
const IS_START_MASK: u8 = 1 << 6;

/// Tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    /// Bytes of the tag.
    bytes: [u8; TAG_SIZE],
}

impl Tag {
    /// Construct a tag from the given bytes.
    pub const fn from_bytes(bytes: [u8; TAG_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the [`u32`] representation of the tag.
    pub const fn as_u32(self) -> u32 {
        u32::from_be_bytes(self.bytes)
    }

    /// Returns the byte representation of the tag.
    pub const fn as_bytes(self) -> [u8; TAG_SIZE] {
        self.bytes
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:08x}", self.as_u32()))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("Tag({:08x})", self.as_u32()))
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8; TAG_SIZE]> for Tag {
    fn as_ref(&self) -> &[u8; TAG_SIZE] {
        &self.bytes
    }
}

/// In-memory representation of an atom head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum AtomHead {
    /// Head of a value atom.
    Value {
        /// Tag of the atom.
        tag: Tag,
        /// Total length of the value.
        length: NumBytes,
    },
    /// Head of an opening segmentation atom.
    Start {
        /// Tag of the atom.
        tag: Tag,
    },
    /// Head of a closing segmentation atom.
    End {
        /// Tag of the atom.
        tag: Tag,
    },
}

impl AtomHead {
    /// Create an atom head for a value atom.
    pub const fn value(tag: Tag, length: NumBytes) -> Self {
        Self::Value { tag, length }
    }

    /// Create an atom head for an opening segmentation atom.
    pub const fn start(tag: Tag) -> Self {
        Self::Start { tag }
    }

    /// Create an atom head for a closing segmentation atom.
    pub const fn end(tag: Tag) -> Self {
        Self::End { tag }
    }

    /// Returns whether the atom is a value atom.
    pub const fn is_value(self) -> bool {
        matches!(self, AtomHead::Value { .. })
    }

    /// Returns whether the atom is a segmentation atom.
    pub const fn is_segment(self) -> bool {
        !self.is_value()
    }

    /// Returns whether the atom is an opening segmentation atom.
    pub const fn is_start(self) -> bool {
        matches!(self, AtomHead::Start { .. })
    }

    /// Returns whether the atom is a closing segmentation atom.
    pub const fn is_end(self) -> bool {
        matches!(self, AtomHead::End { .. })
    }

    /// The tag of the atom.
    pub const fn tag(self) -> Tag {
        match self {
            AtomHead::Value { tag, .. } => tag,
            AtomHead::Start { tag } => tag,
            AtomHead::End { tag } => tag,
        }
    }

    /// Compute the size of the atom head in bytes.
    pub const fn head_size(self) -> NumBytes {
        let mut size = TAG_SIZE as u64;
        size += 1;
        match self {
            AtomHead::Value { length, .. } if length.raw >= 127 => {
                size += compute_varint_size(length.raw - 127) as u64;
            }
            _ => { /* nothing to do */ }
        }
        NumBytes::new(size)
    }

    /// Compute the size of the entire atom in bytes.
    pub const fn atom_size(self) -> NumBytes {
        let mut size = self.head_size().raw;
        match self {
            AtomHead::Value { length, .. } => {
                size += length.raw;
            }
            _ => { /* nothing to do */ }
        }
        NumBytes::new(size)
    }
}

/// Write the head of an atom to the provided writer.
///
/// ❗️ The provided writer should be buffered as we are performing small writes.
pub fn write_atom_head(writer: &mut dyn Write, head: AtomHead) -> io::Result<()> {
    match head {
        AtomHead::Value { tag, length } => {
            write_tag(writer, tag)?;
            write_byte(writer, IS_VALUE_MASK | (length.raw.min(127) as u8))?;
            if length >= 127 {
                write_varint(writer, length.raw - 127)?;
            }
        }
        AtomHead::Start { tag } => {
            write_tag(writer, tag)?;
            write_byte(writer, IS_START_MASK)?;
        }
        AtomHead::End { tag } => {
            write_tag(writer, tag)?;
            write_byte(writer, 0)?;
        }
    }
    Ok(())
}

/// Write a value with the given tag to the given writer.
pub fn write_value(writer: &mut dyn Write, tag: Tag, value: &[u8]) -> io::Result<()> {
    write_atom_head(writer, AtomHead::value(tag, value.byte_len()))?;
    writer.write_all(value)
}

/// Write an opening segmentation atom to the given writer.
pub fn write_segment_start(writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
    write_atom_head(writer, AtomHead::start(tag))
}

/// Write a closing segmentation atom to the given writer.
pub fn write_segment_end(writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
    write_atom_head(writer, AtomHead::end(tag))
}

/// Read the head of the next atom from the provided source.
pub fn read_atom_head(source: &mut dyn BundleSource) -> BundleResult<Option<AtomHead>> {
    let Some(tag) = read_tag(source)? else {
        return Ok(None);
    };
    let indicator = read_byte(source)?;
    if indicator & IS_VALUE_MASK != 0 {
        let mut length = u64::from(indicator & !IS_VALUE_MASK);
        if length == 127 {
            length += read_varint(source)?;
        }
        Ok(Some(AtomHead::Value {
            tag,
            length: NumBytes::new(length),
        }))
    } else {
        if indicator & !IS_VALUE_MASK & !IS_START_MASK != 0 {
            bail!("non-zero segmentation atom indicator bits");
        }
        if indicator & IS_START_MASK != 0 {
            Ok(Some(AtomHead::Start { tag }))
        } else {
            Ok(Some(AtomHead::End { tag }))
        }
    }
}

/// Skip a value atom or segment given an atom head.
///
/// The atom head must indicate a value atom or open a segment.
pub fn skip(source: &mut dyn BundleSource, head: AtomHead) -> BundleResult<()> {
    match head {
        AtomHead::Value { length, .. } => {
            source.skip(length)?;
            Ok(())
        }
        AtomHead::Start { tag: open_tag } => {
            const MAX_NESTING_DEPTH: usize = 64;
            let mut open_segments = vec![open_tag];
            while let Some(head) = read_atom_head(source)? {
                match head {
                    AtomHead::Value { length, .. } => source.skip(length)?,
                    AtomHead::Start { tag } => {
                        if open_segments.len() >= MAX_NESTING_DEPTH {
                            bail!("STLV nesting depth exceeds {MAX_NESTING_DEPTH}");
                        }
                        open_segments.push(tag);
                    }
                    AtomHead::End { tag } => {
                        let expected = open_segments
                            .pop()
                            .expect("the initial open segment remains until completion");
                        if tag != expected {
                            bail!("unbalanced segment end {tag}; expected {expected}");
                        }
                        if open_segments.is_empty() {
                            return Ok(());
                        }
                    }
                }
            }
            bail!("unexpected end of bundle while reading segment {open_tag}")
        }
        AtomHead::End { tag } => {
            bail!("cannot skip unbalanced closing segment atom with tag {tag}")
        }
    }
}

/// Resolver for tag names used for pretty printing.
pub trait TagNameResolver {
    /// Resolve the name of the given tag.
    fn resolve(&self, tag: Tag) -> Option<&str>;
}

/// Read and pretty print the structure of an STLV stream to stderr.
pub fn pretty_print(
    source: &mut dyn BundleSource,
    resolver: Option<&dyn TagNameResolver>,
) -> BundleResult<()> {
    let mut indent = 0;
    while let Some(head) = read_atom_head(source)? {
        match head {
            AtomHead::Value { tag, length } => {
                const MAX_LENGTH: NumBytes = NumBytes::new(64);
                // Size is at most 64 and should fit into usize.
                let buffer = &mut [0; 64][..length.min(MAX_LENGTH).raw as usize];
                source.read_exact(buffer)?;
                if length > MAX_LENGTH {
                    source.skip(length - MAX_LENGTH)?;
                }
                eprintln!(
                    "{:indent$}{} [{:.2}] = \"{}\"",
                    "",
                    style(DisplayTag { resolver, tag }).for_stderr().green(),
                    style(length).for_stderr().blue(),
                    style(DisplayBytes {
                        bytes: buffer,
                        limit: 64,
                        truncated: length > 64,
                    })
                    .for_stderr()
                    .black()
                );
            }
            AtomHead::Start { tag } => {
                eprintln!(
                    "{:indent$}<{}",
                    "",
                    style(DisplayTag { resolver, tag }).for_stderr().cyan()
                );
                indent += 2;
            }
            AtomHead::End { tag } => {
                indent = indent.saturating_sub(2);
                eprintln!(
                    "{:indent$}{}>",
                    "",
                    style(DisplayTag { resolver, tag }).for_stderr().cyan()
                );
            }
        }
    }
    Ok(())
}

/// Auxiliary struct for displaying tags.
struct DisplayTag<'r> {
    /// Tag to display.
    tag: Tag,
    /// Optional resolver for tag names.
    resolver: Option<&'r dyn TagNameResolver>,
}

impl fmt::Display for DisplayTag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.resolver {
            Some(resolver) => fmt::Write::write_fmt(
                f,
                format_args!(
                    "{} ({})",
                    resolver.resolve(self.tag).unwrap_or("UNKNOWN"),
                    self.tag
                ),
            ),
            None => fmt::Display::fmt(&self.tag, f),
        }
    }
}

/// Auxiliary struct for displaying bytes.
#[derive(Debug)]
struct DisplayBytes<T> {
    /// Bytes to display.
    bytes: T,
    /// Soft character limit.
    limit: usize,
    /// Whether the bytes have already been truncated.
    truncated: bool,
}

impl<T: AsRef<[u8]>> fmt::Display for DisplayBytes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut remaining = self.limit;
        let mut truncated = self.truncated;
        for &byte in self.bytes.as_ref() {
            if remaining == 0 {
                truncated = true;
                break;
            }
            for c in std::ascii::escape_default(byte) {
                fmt::Write::write_char(f, c as char)?;
                remaining = remaining.saturating_sub(1);
            }
        }
        if truncated {
            fmt::Write::write_str(f, " ...")?;
        }
        Ok(())
    }
}

/// Read a single byte.
fn read_byte(source: &mut dyn BundleSource) -> BundleResult<u8> {
    let mut buf = [0; 1];
    source.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// Read a [`Tag`].
fn read_tag(source: &mut dyn BundleSource) -> BundleResult<Option<Tag>> {
    let mut buf = [0; TAG_SIZE];
    let mut tail = buf.as_mut_slice();
    while !tail.is_empty() {
        let bytes_read = source.read(tail)?;
        if bytes_read == 0 {
            if tail.len() != TAG_SIZE {
                bail!("unexpected end of bundle while reading tag");
            }
            return Ok(None);
        }
        tail = &mut tail[bytes_read..];
    }
    Ok(Some(Tag::from_bytes(buf)))
}

/// Read a variable-length integer.
fn read_varint(source: &mut dyn BundleSource) -> BundleResult<u64> {
    let mut integer = 0u64;
    loop {
        let byte = read_byte(source)?;
        match integer.checked_shl(7) {
            Some(shifted) => {
                integer = shifted | u64::from(byte & 0b0111_1111);
                if byte & 0b1000_0000 == 0 {
                    if integer > u64::MAX / 2 {
                        // This guarantees that the integer also fits into `i64`.
                        bail!("variable-length integer exceeds 63 bits");
                    } else {
                        break Ok(integer);
                    }
                }
                if integer == 0 {
                    bail!("invalid zero digit in variable-length integer");
                }
            }
            None => {
                bail!("variable-length integer exceeds 64 bits")
            }
        }
    }
}

/// Write a single byte.
fn write_byte(writer: &mut dyn Write, byte: u8) -> io::Result<()> {
    writer.write_all(&[byte])
}

/// Write a [`Tag`].
fn write_tag(writer: &mut dyn Write, tag: Tag) -> io::Result<()> {
    writer.write_all(tag.as_ref())
}

/// Write a variable-length integer.
///
/// # Panics
///
/// Panics in case the integer does not fit into 63 bits.
fn write_varint(writer: &mut dyn Write, integer: u64) -> io::Result<()> {
    assert!(integer <= u64::MAX / 2, "integer must fit into 63-bits");
    let mut shift = (compute_varint_size(integer) - 1) * 7;
    loop {
        // After masking, the integer fits into `u8`.
        let digit = ((integer >> shift) & 0b0111_1111) as u8;
        if shift > 0 {
            shift -= 7;
            write_byte(writer, digit | 0b1000_0000)?;
        } else {
            break write_byte(writer, digit);
        }
    }
}

/// Compute the size of a variable-length integer in bytes.
const fn compute_varint_size(integer: u64) -> usize {
    // This is at most 64 and should therefore fit into `usize`.
    let bits = (64 - integer.leading_zeros()) as usize;
    if bits == 0 { 1 } else { bits.div_ceil(7) }
}

#[cfg(test)]
mod tests {
    use std::io;

    use byte_calc::NumBytes;

    use crate::source::from_slice;

    use super::*;

    #[test]
    pub fn test_varint_encoding() {
        fn test_roundtrip(integer: u64) {
            let mut buffer = io::Cursor::new(vec![]);
            write_varint(&mut buffer, integer).unwrap();
            buffer.set_position(0);
            let mut source = from_slice(buffer.get_ref());
            assert_eq!(read_varint(&mut source).unwrap(), integer);
        }
        for integer in [0, 1, 0x7f - 1, 0x7f, 0x7f + 1, u64::MAX / 2] {
            test_roundtrip(integer);
        }
        // Invalid zero digit.
        assert!(read_varint(&mut from_slice(&[128, 0])).is_err());
        // Overflow.
        assert!(read_varint(&mut from_slice(&[0xff; 10])).is_err());
    }

    #[test]
    pub fn test_atom_head_encoding() {
        fn test_roundtrip(head: AtomHead) {
            let mut buffer = io::Cursor::new(vec![]);
            write_atom_head(&mut buffer, head).unwrap();
            buffer.set_position(0);
            assert_eq!(
                read_atom_head(&mut from_slice(buffer.get_ref()))
                    .unwrap()
                    .unwrap(),
                head
            );
        }
        test_roundtrip(AtomHead::start(Tag::from_bytes([0x99, 0x88, 0x77, 0x66])));
        test_roundtrip(AtomHead::end(Tag::from_bytes([0x99, 0x88, 0x77, 0x66])));
        for length in [0, 1, 0x7f - 1, 0x7f, 0x7f + 1, u64::MAX / 2] {
            test_roundtrip(AtomHead::Value {
                tag: Tag::from_bytes([0x99, 0x88, 0x77, 0x66]),
                length: NumBytes::new(length),
            })
        }
        // Empty buffer.
        assert_eq!(read_atom_head(&mut from_slice(&[])).unwrap(), None);
        // Truncated buffer.
        assert!(read_atom_head(&mut from_slice(&[0x99, 0x88])).is_err());
    }

    #[test]
    fn skip_rejects_unbalanced_and_excessively_nested_segments() {
        const ROOT: Tag = Tag::from_bytes([1, 2, 3, 4]);
        const OTHER: Tag = Tag::from_bytes([4, 3, 2, 1]);

        let mut unbalanced = Vec::new();
        write_segment_start(&mut unbalanced, ROOT).unwrap();
        write_segment_end(&mut unbalanced, OTHER).unwrap();
        let mut source = from_slice(&unbalanced);
        let head = read_atom_head(&mut source).unwrap().unwrap();
        assert!(skip(&mut source, head).is_err());

        let mut nested = Vec::new();
        for _ in 0..65 {
            write_segment_start(&mut nested, ROOT).unwrap();
        }
        for _ in 0..65 {
            write_segment_end(&mut nested, ROOT).unwrap();
        }
        let mut source = from_slice(&nested);
        let head = read_atom_head(&mut source).unwrap().unwrap();
        assert!(skip(&mut source, head).is_err());
    }
}
