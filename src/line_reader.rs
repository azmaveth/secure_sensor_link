//! Reading newline-delimited input with a hard cap on line length.
//!
//! `BufRead::lines` would buffer a line of any length. Here a line longer
//! than the cap is skipped to its newline without being stored, so memory
//! stays bounded whatever arrives on stdin.

use std::io::{self, BufRead};

use crate::frame::MAX_FRAME_LEN;

/// Longest line kept: the hex of the largest possible frame plus room for
/// the JSON around it. Every valid command fits.
pub const MAX_LINE_LEN: usize = 2 * MAX_FRAME_LEN + 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Text(String),
    TooLong,
    NotUtf8,
}

pub struct BoundedLines<R> {
    reader: R,
    max_len: usize,
}

impl<R: BufRead> BoundedLines<R> {
    pub fn new(reader: R, max_len: usize) -> Self {
        Self { reader, max_len }
    }

    /// The next line without its `\n` (or `\r\n`), or `None` at end of input.
    pub fn next_line(&mut self) -> io::Result<Option<Line>> {
        let mut line = Vec::new();
        let mut too_long = false;
        let mut read_any = false;
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(chunk) => chunk,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if chunk.is_empty() {
                if !read_any {
                    return Ok(None);
                }
                break;
            }
            read_any = true;
            let newline = chunk.iter().position(|&b| b == b'\n');
            let part = &chunk[..newline.unwrap_or(chunk.len())];
            if !too_long {
                if line.len() + part.len() > self.max_len {
                    too_long = true;
                    line = Vec::new();
                } else {
                    line.extend_from_slice(part);
                }
            }
            let used = part.len() + usize::from(newline.is_some());
            self.reader.consume(used);
            if newline.is_some() {
                break;
            }
        }
        if too_long {
            return Ok(Some(Line::TooLong));
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(Some(String::from_utf8(line).map_or(Line::NotUtf8, Line::Text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(input: &[u8], max: usize, capacity: usize) -> Vec<Line> {
        let reader = io::BufReader::with_capacity(capacity, input);
        let mut lines = BoundedLines::new(reader, max);
        let mut out = Vec::new();
        while let Some(line) = lines.next_line().unwrap() {
            out.push(line);
        }
        out
    }

    fn text(s: &str) -> Line {
        Line::Text(s.into())
    }

    #[test]
    fn splits_lines_across_small_buffers() {
        for capacity in [1, 2, 3, 64] {
            assert_eq!(
                all(b"ab\ncd\r\n\nlast", 10, capacity),
                vec![text("ab"), text("cd"), text(""), text("last")]
            );
        }
    }

    #[test]
    fn overlong_line_is_skipped_and_reading_continues() {
        for capacity in [1, 4, 64] {
            assert_eq!(
                all(b"12345\nabcdefgh\nok\n", 5, capacity),
                vec![text("12345"), Line::TooLong, text("ok")]
            );
        }
    }

    #[test]
    fn invalid_utf8_is_reported() {
        assert_eq!(all(b"\xff\xfe\nok", 10, 8), vec![Line::NotUtf8, text("ok")]);
    }
}
