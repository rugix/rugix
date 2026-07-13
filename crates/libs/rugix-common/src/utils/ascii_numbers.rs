//! Helpers for converting ASCII numbers within constant functions.

use thiserror::Error;

use super::const_helpers::const_try;

/// Case for conversions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Case {
    /// Uppercase.
    Upper,
    /// Lowercase.
    Lower,
}

/// Error indicating an invalid ASCII digit.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum InvalidDigit {
    /// Byte at position is not a digit.
    #[error("invalid byte at position {pos}")]
    InvalidByte { pos: usize },
    /// Byte at position has wrong case.
    #[error("invalid character case at position {pos}")]
    InvalidCase { pos: usize },
}

impl InvalidDigit {
    /// Position of the error.
    pub const fn position(&self) -> usize {
        match self {
            InvalidDigit::InvalidByte { pos } => *pos,
            InvalidDigit::InvalidCase { pos } => *pos,
        }
    }
}

/// Parse a decimal ASCII digit.
pub const fn parse_ascii_decimal_digit(digit: u8, pos: usize) -> Result<u8, InvalidDigit> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        _ => Err(InvalidDigit::InvalidByte { pos }),
    }
}

/// Parse a hexadecimal ASCII digit.
pub const fn parse_ascii_hex_digit(
    hex: u8,
    pos: usize,
    case: Option<Case>,
) -> Result<u8, InvalidDigit> {
    match hex {
        b'0'..=b'9' => Ok(hex - b'0'),
        b'a'..=b'f' => {
            if matches!(case, Some(Case::Upper)) {
                Err(InvalidDigit::InvalidCase { pos })
            } else {
                Ok(hex - b'a' + 10)
            }
        }
        b'A'..=b'F' => {
            if matches!(case, Some(Case::Lower)) {
                Err(InvalidDigit::InvalidCase { pos })
            } else {
                Ok(hex - b'A' + 10)
            }
        }
        _ => Err(InvalidDigit::InvalidByte { pos }),
    }
}

/// Parse a hexadecimal ASCII byte.
pub const fn parse_ascii_hex_byte(
    hex: [u8; 2],
    pos: usize,
    case: Option<Case>,
) -> Result<u8, InvalidDigit> {
    let first = const_try!(parse_ascii_hex_digit(hex[0], pos, case));
    let second = const_try!(parse_ascii_hex_digit(hex[1], pos + 1, case));
    Ok(first << 4 | second)
}

/// Convert a digit between `0` and `15` to its hexadecimal ASCII representation.
///
/// Panics in case the digit is not in the interval between `0` and `15`.
pub const fn digit_to_ascii_hex(digit: u8, case: Case) -> u8 {
    match digit {
        0..=9 => b'0' + digit,
        10..=15 => match case {
            Case::Upper => digit - 10 + b'A',
            Case::Lower => digit - 10 + b'a',
        },
        _ => panic!("digit cannot be encoded as hexadecimal ASCII digit"),
    }
}

/// Convert a byte to its hexadecimal ASCII representation.
pub const fn byte_to_ascii_hex(byte: u8, case: Case) -> [u8; 2] {
    [
        digit_to_ascii_hex(byte >> 4, case),
        digit_to_ascii_hex(byte & 0x0F, case),
    ]
}

/// Converts a sequence of bytes to its hexadecimal ASCII representation.
pub fn bytes_to_ascii_hex(bytes: &[u8], case: Case) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let [first, second] = byte_to_ascii_hex(*byte, case);
        hex.push(first as char);
        hex.push(second as char);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_encoding() {
        assert_eq!(digit_to_ascii_hex(0, Case::Lower), b'0');
        assert_eq!(digit_to_ascii_hex(10, Case::Lower), b'a');
        assert_eq!(digit_to_ascii_hex(15, Case::Upper), b'F');
    }

    #[test]
    pub fn test_decoding() {
        assert_eq!(parse_ascii_hex_digit(b'0', 0, None).unwrap(), 0x0);
        assert_eq!(parse_ascii_hex_digit(b'a', 0, None).unwrap(), 0xa);
        assert_eq!(parse_ascii_hex_digit(b'F', 0, None).unwrap(), 0xF);
        assert_eq!(parse_ascii_hex_byte(*b"a2", 0, None).unwrap(), 0xa2);
    }
}
