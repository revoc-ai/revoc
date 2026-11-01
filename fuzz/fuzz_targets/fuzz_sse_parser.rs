//! Fuzz the incremental SSE parser used by stream governance.
//!
//! Invariant: however the upstream bytes are split into chunks, the parser
//! yields exactly the events it yields for the whole body at once. A split
//! that changed the events would let content slip past the governor.
#![no_main]

use libfuzzer_sys::fuzz_target;
use revoc_pipeline::sse::{parse_all, SseParser};

const MAX: usize = 1 << 16;

fuzz_target!(|input: &[u8]| {
    // First byte picks the chunk sizes; the rest is the stream body.
    let Some((&seed, body)) = input.split_first() else {
        return;
    };
    // Keep inputs under the buffer limit: the chunked parser checks the
    // limit after every chunk, the whole-body parse only once.
    if body.len() >= MAX {
        return;
    }
    let whole = parse_all(body, MAX);

    let mut parser = SseParser::new(MAX);
    let mut events = Vec::new();
    let mut failed = false;
    let mut rest = body;
    let mut step = usize::from(seed % 7) + 1;
    while !rest.is_empty() {
        let n = step.min(rest.len());
        let (chunk, tail) = rest.split_at(n);
        rest = tail;
        step = step % 7 + 1;
        match parser.push(chunk) {
            Ok(evs) => events.extend(evs),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    if !failed {
        match parser.finish() {
            Ok(ev) => events.extend(ev),
            Err(_) => failed = true,
        }
    }

    match whole {
        Ok(expected) if !failed => assert_eq!(events, expected),
        // Invalid UTF-8 or an oversized event must fail both ways. (A line
        // split mid-codepoint is only rejected once the line is complete, so
        // the error is the same either way.)
        Err(_) => assert!(failed),
        Ok(_) => panic!("chunked parse failed where whole-body parse succeeded"),
    }

    // Every event must survive a wire round trip unchanged.
    if let Ok(expected) = parse_all(body, MAX) {
        for ev in expected {
            let again = parse_all(ev.to_wire().as_bytes(), MAX).expect("re-parse");
            assert_eq!(again, vec![ev]);
        }
    }
});
