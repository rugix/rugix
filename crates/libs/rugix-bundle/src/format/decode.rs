//! High-level data structure decoding API.

use reportify::ErrorExt;
use reportify::bail;

use byte_calc::NumBytes;

use crate::BundleResult;
use crate::source::BundleSource;
use crate::source::ReaderSource;
use crate::source::SkipRead;

use super::stlv::AtomHead;
use super::stlv::Tag;
use super::stlv::read_atom_head;

/// Decoder for data structures from STLV streams.
///
/// To prevent streams with excessively large values or structures from leading to
/// out-of-memory issues or overflowing the stack, each decoder has limits for the depth
/// of data structures and the maximal number of bytes it is willing to decode. If you
/// decode multiple data structures with the same decoder, the size limit is _not_ reset,
/// i.e., all structures count towards the same limit.
///
/// This could probably be improved to get better compile-time guarantees.
pub struct Decoder<S> {
    /// Underlying bundle source.
    source: S,
    /// Remaining depth until the limit is reached.
    remaining_depth: usize,
    /// Remaining bytes until the limit is reached.
    remaining_bytes: NumBytes,
    /// Length of the current value.
    value_length: Option<NumBytes>,
}

impl<S: BundleSource> Decoder<S> {
    /// Construct a new decoder from the provided source with the given limits.
    pub fn new(source: S, max_depth: usize, max_size: NumBytes) -> Self {
        Self {
            source,
            remaining_depth: max_depth,
            remaining_bytes: max_size,
            value_length: None,
        }
    }

    /// Construct a new decoder from the provided source with default limits.
    ///
    /// The default depth limit is `32` and the default size limit is `64KiB`.
    pub fn with_default_limits(source: S) -> Self {
        Self::new(source, 32, NumBytes::kibibytes(64))
    }

    /// Convert back into source.
    pub fn into_inner(self) -> S {
        self.source
    }

    /// Decode a data structure.
    pub fn decode<T: Decode>(&mut self) -> BundleResult<T> {
        let atom = self.next_atom_head()?;
        T::decode(self, atom)
    }

    /// Read the next atom head.
    pub fn next_atom_head(&mut self) -> BundleResult<AtomHead> {
        if self.value_length.is_some() {
            bail!("need to read or skip the current value before reading the next atom");
        }
        let Some(head) = read_atom_head(&mut self.source)? else {
            bail!("unexpected end of bundle");
        };
        self.check_and_subtract_size(head.atom_size())?;
        match head {
            AtomHead::Start { .. } => {
                if self.remaining_depth > 0 {
                    self.remaining_depth -= 1;
                } else {
                    bail!("depth limit reached");
                }
            }
            AtomHead::End { .. } => {
                self.remaining_depth += 1;
            }
            AtomHead::Value { length, .. } => {
                self.value_length = Some(length);
            }
        }
        Ok(head)
    }

    /// Read the current value.
    pub fn read_value(&mut self) -> BundleResult<Vec<u8>> {
        let length = self
            .value_length
            .take()
            .ok_or_else(|| reportify::whatever!("no current value to read"))?;
        self.check_and_subtract_size(length)?;
        let mut buffer = vec![
            0;
            usize::try_from(length.raw).map_err(|_| reportify::whatever!(
                "value length does not fit into memory"
            ))?
        ];
        self.source.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    /// Read the current value into an array.
    pub fn read_value_array<const N: usize>(&mut self) -> BundleResult<[u8; N]> {
        let length = self
            .value_length
            .take()
            .ok_or_else(|| reportify::whatever!("no current value to read"))?;
        self.check_and_subtract_size(length)?;
        if N as u64 != length.raw {
            bail!("invalid value length, expected {N}");
        }
        let mut buffer = [0; N];
        self.source.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    /// Skip current value or segment.
    pub fn skip(&mut self, atom: AtomHead) -> BundleResult<()> {
        match atom {
            AtomHead::Value { .. } => self.skip_value(),
            AtomHead::Start { tag } => self.skip_segment(tag),
            AtomHead::End { tag } => bail!("unbalanced segment end with tag {tag}"),
        }
    }

    /// Skip the current value.
    pub fn skip_value(&mut self) -> BundleResult<()> {
        let length = self
            .value_length
            .take()
            .ok_or_else(|| reportify::whatever!("no current value to skip"))?;
        self.source.skip(length)
    }

    /// Skip the current segment.
    pub fn skip_segment(&mut self, tag: Tag) -> BundleResult<()> {
        loop {
            let head = self.next_atom_head()?;
            match head {
                AtomHead::Value { .. } => {
                    self.skip_value()?;
                }
                AtomHead::Start { tag } => {
                    self.skip_segment(tag)?;
                }
                AtomHead::End { tag: end_tag } if end_tag == tag => {
                    return Ok(());
                }
                AtomHead::End { tag } => bail!("unbalanced segment end with tag {tag}"),
            }
        }
    }

    /// Check the size limit and subtract the given size from it.
    fn check_and_subtract_size(&mut self, size: NumBytes) -> BundleResult<()> {
        if self.remaining_bytes < size {
            self.remaining_bytes = NumBytes::ZERO;
            bail!("size limit reached");
        }
        self.remaining_bytes -= size;
        Ok(())
    }
}

pub fn decode_slice<T: Decode>(slice: &[u8]) -> BundleResult<T> {
    let source = ReaderSource::<_, SkipRead>::new(slice);
    let mut decoder = Decoder::new(source, 32, NumBytes::new(u64::MAX));
    decoder.decode()
}

pub trait Decode: Sized {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self>;

    #[expect(unused_variables)]
    fn continue_decode<S: BundleSource>(
        &mut self,
        decoder: &mut Decoder<S>,
        atom: AtomHead,
    ) -> BundleResult<()> {
        bail!(
            "unexpected atom {atom:?}, cannot continue decoding for {}",
            std::any::type_name::<Self>()
        )
    }

    fn initial_value() -> Option<Self> {
        None
    }
}

impl Decode for String {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        match atom {
            AtomHead::Value { .. } => String::from_utf8(decoder.read_value()?)
                .map_err(|error| error.whatever("unable to read string from bundle")),
            _ => bail!("unable to decode string from segment"),
        }
    }
}

impl Decode for bool {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, _: AtomHead) -> BundleResult<Self> {
        match decoder.read_value_array::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => bail!("invalid boolean"),
        }
    }
}

impl Decode for NumBytes {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        Ok(NumBytes::new(u64::decode(decoder, atom)?))
    }
}

macro_rules! impl_decode_for_int {
    ($($int:ty),*) => {
        $(
            impl Decode for $int {
                fn decode<S: BundleSource>(decoder: &mut Decoder<S>, _: AtomHead) -> BundleResult<Self> {
                    Ok(Self::from_be_bytes(decoder.read_value_array()?))
                }
            }
        )*
    };
}

impl_decode_for_int! { i8, u8, i16, u16, i32, u32, i64, u64, i128, u128 }

impl<T: Decode> Decode for Option<T> {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        Ok(Some(T::decode(decoder, atom)?))
    }

    fn continue_decode<S: BundleSource>(
        &mut self,
        decoder: &mut Decoder<S>,
        atom: AtomHead,
    ) -> BundleResult<()> {
        match self {
            Some(value) => value.continue_decode(decoder, atom)?,
            None => *self = Some(T::decode(decoder, atom)?),
        }
        Ok(())
    }

    fn initial_value() -> Option<Self> {
        Some(T::initial_value())
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode<S: BundleSource>(decoder: &mut Decoder<S>, atom: AtomHead) -> BundleResult<Self> {
        Ok(vec![T::decode(decoder, atom)?])
    }

    fn continue_decode<S: BundleSource>(
        &mut self,
        decoder: &mut Decoder<S>,
        atom: AtomHead,
    ) -> BundleResult<()> {
        self.push(T::decode(decoder, atom)?);
        Ok(())
    }

    fn initial_value() -> Option<Self> {
        Some(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use byte_calc::NumBytes;

    use super::Decoder;
    use crate::format::stlv::Tag;
    use crate::format::stlv::write_value;
    use crate::source::from_slice;

    #[test]
    fn invalid_decoder_call_order_returns_errors() {
        let empty = Vec::<u8>::new();
        let mut decoder = Decoder::new(from_slice(&empty), 4, NumBytes::new(1024));
        assert!(decoder.read_value().is_err());
        assert!(decoder.read_value_array::<1>().is_err());
        assert!(decoder.skip_value().is_err());

        let mut encoded = Vec::new();
        write_value(&mut encoded, Tag::from_bytes(*b"TEST"), b"value").unwrap();
        let mut decoder = Decoder::new(from_slice(&encoded), 4, NumBytes::new(1024));
        let _ = decoder.next_atom_head().unwrap();
        assert!(decoder.next_atom_head().is_err());
        assert_eq!(decoder.read_value().unwrap(), b"value");
    }
}
