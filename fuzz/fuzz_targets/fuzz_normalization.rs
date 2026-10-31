#![no_main]

use libfuzzer_sys::fuzz_target;
use revoc_detector::normalization::normalize;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let r1 = normalize(s);
        let r2 = normalize(&r1.text);
        assert_eq!(r1.text, r2.text, "normalization must be idempotent");
    }
});
