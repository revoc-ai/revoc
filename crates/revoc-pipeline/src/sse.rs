//! Incremental Server-Sent Events parser (SPEC.md §12).
//!
//! Upstream bytes arrive in arbitrary TCP-sized pieces: one event can span
//! several chunks and one chunk can hold several events. [`SseParser`] keeps
//! the unterminated tail between calls so every event is seen exactly once,
//! whole, regardless of how the stream was split. Line endings may be `\n`,
//! `\r\n` or `\r` (WHATWG event-stream format).

use revoc_core::RevocError;

/// One dispatched SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event:` field, if the event had one.
    pub event: Option<String>,
    /// All `data:` lines joined with `\n`.
    pub data: String,
}

impl SseEvent {
    /// Serialise the event back to wire format.
    pub fn to_wire(&self) -> String {
        let mut out = String::with_capacity(self.data.len() + 16);
        if let Some(ev) = &self.event {
            out.push_str("event: ");
            out.push_str(ev);
            out.push('\n');
        }
        for line in self.data.split('\n') {
            out.push_str("data: ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
        out
    }
}

/// Stateful parser: feed it chunks with [`SseParser::push`], then call
/// [`SseParser::finish`] at end of stream.
#[derive(Debug)]
pub struct SseParser {
    buf: Vec<u8>,
    max_buffered: usize,
    event: Option<String>,
    data: Vec<String>,
    has_data: bool,
}

impl SseParser {
    /// Create a parser that refuses to buffer more than `max_buffered` bytes
    /// of a single unterminated line or event.
    pub fn new(max_buffered: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_buffered,
            event: None,
            data: Vec::new(),
            has_data: false,
        }
    }

    /// Feed one chunk; returns every event completed by it.
    ///
    /// # Errors
    /// [`RevocError::RequestParse`] when a line is not UTF-8 or the pending
    /// event exceeds the buffer limit.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, RevocError> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        let mut start = 0;
        let mut i = 0;
        while i < self.buf.len() {
            let b = self.buf[i];
            if b == b'\n' || b == b'\r' {
                // A trailing `\r` may be the first half of `\r\n`: wait for more.
                if b == b'\r' && i + 1 == self.buf.len() {
                    break;
                }
                let line_end = i;
                i += if b == b'\r' && self.buf[i + 1] == b'\n' {
                    2
                } else {
                    1
                };
                let line = std::str::from_utf8(&self.buf[start..line_end])
                    .map_err(|_| RevocError::RequestParse("SSE line is not UTF-8".into()))?
                    .to_owned();
                start = i;
                if let Some(ev) = self.process_line(&line) {
                    events.push(ev);
                }
            } else {
                i += 1;
            }
        }
        self.buf.drain(..start);
        let pending = self.buf.len() + self.data.iter().map(String::len).sum::<usize>();
        if pending > self.max_buffered {
            return Err(RevocError::RequestParse(format!(
                "SSE event exceeds {} bytes",
                self.max_buffered
            )));
        }
        Ok(events)
    }

    /// Flush at end of stream: a final event that lacked its blank line is
    /// still dispatched.
    ///
    /// # Errors
    /// [`RevocError::RequestParse`] when the unterminated tail is not UTF-8.
    pub fn finish(&mut self) -> Result<Option<SseEvent>, RevocError> {
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let line = std::str::from_utf8(&rest)
                .map_err(|_| RevocError::RequestParse("SSE line is not UTF-8".into()))?
                .trim_end_matches('\r')
                .to_owned();
            if let Some(ev) = self.process_line(&line) {
                return Ok(Some(ev));
            }
        }
        Ok(self.dispatch())
    }

    fn process_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return None; // comment / keep-alive
        }
        let (field, value) = match line.find(':') {
            Some(p) => {
                let v = &line[p + 1..];
                (&line[..p], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (line, ""),
        };
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => {
                self.data.push(value.to_owned());
                self.has_data = true;
            }
            _ => {} // id, retry and unknown fields carry no content
        }
        None
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        let event = self.event.take();
        if !self.has_data {
            return None;
        }
        self.has_data = false;
        Some(SseEvent {
            event,
            data: std::mem::take(&mut self.data).join("\n"),
        })
    }
}

/// Parse a complete SSE body in one call.
///
/// # Errors
/// As [`SseParser::push`].
pub fn parse_all(body: &[u8], max_buffered: usize) -> Result<Vec<SseEvent>, RevocError> {
    let mut p = SseParser::new(max_buffered);
    let mut events = p.push(body)?;
    events.extend(p.finish()?);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 1 << 20;

    #[test]
    fn event_split_across_chunks_is_reassembled() {
        let mut p = SseParser::new(MAX);
        assert!(p.push(b"data: {\"a\":").expect("push").is_empty());
        let evs = p.push(b"1}\n\ndata: x\n").expect("push");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"a\":1}");
        let last = p.push(b"\n").expect("push");
        assert_eq!(last[0].data, "x");
    }

    #[test]
    fn crlf_and_cr_line_endings() {
        let evs = parse_all(b"event: e\r\ndata: 1\r\n\r\ndata: 2\r\r", MAX).expect("parse");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event.as_deref(), Some("e"));
        assert_eq!(evs[1].data, "2");
    }

    #[test]
    fn crlf_split_between_chunks() {
        let mut p = SseParser::new(MAX);
        assert!(p.push(b"data: a\r").expect("push").is_empty());
        assert!(p.push(b"\n\r").expect("push").is_empty());
        let evs = p.push(b"\n").expect("push");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "a");
    }

    #[test]
    fn multiline_data_comments_and_unterminated_tail() {
        let evs = parse_all(b": ping\ndata: a\ndata: b\n\ndata: tail", MAX).expect("parse");
        assert_eq!(evs[0].data, "a\nb");
        assert_eq!(evs[1].data, "tail");
    }

    #[test]
    fn oversized_event_is_an_error() {
        let mut p = SseParser::new(8);
        assert!(p.push(b"data: 0123456789").is_err());
    }

    #[test]
    fn round_trips_through_wire_format() {
        let ev = SseEvent {
            event: Some("x".into()),
            data: "a\nb".into(),
        };
        assert_eq!(
            parse_all(ev.to_wire().as_bytes(), MAX).expect("parse"),
            vec![ev]
        );
    }
}
