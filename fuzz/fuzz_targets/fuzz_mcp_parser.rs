#![no_main]

use libfuzzer_sys::fuzz_target;
use revoc_core::McpRawRequest;

fuzz_target!(|data: &[u8]| {
    // Must never panic regardless of input — invalid JSON or malformed requests
    // must produce a parse error, not a crash.
    let result: Result<McpRawRequest, _> = serde_json::from_slice(data);
    let _ = result;
});
