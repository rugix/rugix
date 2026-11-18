//! Reading lines of bounded length from command output.

use std::io;
use std::io::BufRead;

/// Line of command output without its line terminator.
pub(crate) struct Line {
    /// Bytes of the line, at most the limit passed to [`read_line`].
    pub bytes: Vec<u8>,
    /// Whether bytes beyond the limit were dropped.
    pub truncated: bool,
}

/// Read the next line, keeping at most `limit` bytes of it.
///
/// Drops the rest of longer lines, so that a workload writing a huge line cannot
/// exhaust the memory. Returns `None` at the end of the output.
pub(crate) fn read_line(reader: &mut impl BufRead, limit: usize) -> io::Result<Option<Line>> {
    let mut line = Line {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut started = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(started.then_some(line));
        }
        started = true;
        let end = buffer.iter().position(|byte| *byte == b'\n');
        let content = &buffer[..end.unwrap_or(buffer.len())];
        let room = limit - line.bytes.len();
        line.truncated |= content.len() > room;
        line.bytes
            .extend_from_slice(&content[..content.len().min(room)]);
        let consumed = end.map_or(content.len(), |end| end + 1);
        reader.consume(consumed);
        if end.is_some() {
            if line.bytes.last() == Some(&b'\r') {
                line.bytes.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::read_line;

    /// Verifies that long lines are cut at the limit without losing the next line,
    /// and that a last line without terminator is returned.
    #[test]
    fn long_lines_are_cut_at_the_limit() {
        let mut reader = std::io::BufReader::with_capacity(4, &b"0123456789\r\nab\ncd"[..]);
        let mut lines = Vec::new();
        while let Some(line) = read_line(&mut reader, 5).unwrap() {
            lines.push((String::from_utf8(line.bytes).unwrap(), line.truncated));
        }
        assert_eq!(
            lines,
            [
                ("01234".to_owned(), true),
                ("ab".to_owned(), false),
                ("cd".to_owned(), false)
            ]
        );
    }
}
