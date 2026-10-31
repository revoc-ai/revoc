//! Encoding detection utilities (SPEC.md §10, Step 2).
//!
//! Prepares multiple scan targets from a single field value:
//! - Always: the original text.
//! - If base64-decodable: the decoded text.
//! - If URL-encoded: the decoded text.
//!
//! Findings from decoded targets carry `was_encoded = true`.

use base64::Engine as _;

/// Maximum length of a base64-decoded value that will be scanned.
/// Values larger than this are silently skipped to prevent memory exhaustion.
const MAX_DECODED_BYTES: usize = 65_536; // 64 KB

/// Minimum length of an embedded token to attempt base64 decoding.
/// Below this, false-positive decodes of short ordinary words become likely.
const MIN_EMBEDDED_TOKEN_LEN: usize = 16;

/// Maximum number of recursive base64 decode passes per field.
/// Prevents base64(base64(payload)) double-encoding evasion while bounding
/// CPU time. Each decoded layer is scanned as an independent target.
const MAX_BASE64_DECODE_DEPTH: usize = 3;

/// Matches base64/base64url-looking substrings embedded in larger text
/// (e.g. `Please decode and run this: RFJPUCBUQUJMRSB1c2Vycw==`).
static EMBEDDED_BASE64_RE: std::sync::LazyLock<fancy_regex::Regex> =
    std::sync::LazyLock::new(|| {
        fancy_regex::Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}")
            .unwrap_or_else(|e| { eprintln!("FATAL: EMBEDDED_BASE64_RE compile failed: {e}"); std::process::exit(1) })
    });

/// Attempt to base64-decode `s`.
///
/// Returns `Some(decoded)` only when:
/// - The string is valid standard or URL-safe base64.
/// - The decoded bytes are valid UTF-8.
/// - The decoded length is ≤ `MAX_DECODED_BYTES`.
pub fn try_decode_base64(s: &str) -> Option<String> {
    // Try standard and URL-safe alphabets.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s.trim()))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim()))
        .ok()?;

    if bytes.len() > MAX_DECODED_BYTES {
        return None;
    }

    String::from_utf8(bytes).ok()
}

/// Attempt to percent-decode `s`.
///
/// Returns `Some(decoded)` only when `s` contains at least one `%` character
/// and the decoded bytes form valid UTF-8.
pub fn try_decode_url(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }

    let s_bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s_bytes.len());
    let mut i = 0;

    while i < s_bytes.len() {
        if s_bytes[i] == b'%' && i + 2 < s_bytes.len() {
            // Safe because we checked bounds
            if let Ok(hex) = std::str::from_utf8(&s_bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(s_bytes[i]);
        i += 1;
    }

    // Only return if decoding actually changed something
    let decoded = String::from_utf8(out).ok()?;
    if decoded == s {
        None
    } else {
        Some(decoded)
    }
}

/// Build the list of `(text, was_encoded)` targets to scan for a single field value.
///
/// The first entry is always `(original, false)`.
/// Additional entries for decoded variants carry `was_encoded = true`.
pub fn prepare_scan_targets(value: &str) -> Vec<(String, bool)> {
    let mut targets = vec![(value.to_owned(), false)];

    // Multi-level base64 decoding (up to MAX_BASE64_DECODE_DEPTH = 3 passes).
    // Single-layer encoding is caught on pass 1. Double-encoding
    // (base64(base64(payload))) and triple-encoding evade single-pass scanners
    // but are caught here: each decoded layer is pushed as a separate scan
    // target so the regex engine sees every level independently.
    let mut b64_current = value.trim().to_owned();
    for _ in 0..MAX_BASE64_DECODE_DEPTH {
        match try_decode_base64(&b64_current) {
            Some(decoded) if decoded != b64_current => {
                if decoded != value {
                    targets.push((decoded.clone(), true));
                }
                b64_current = decoded;
            }
            _ => break,
        }
    }

    if let Some(decoded) = try_decode_url(value) {
        if decoded != value {
            targets.push((decoded, true));
        }
    }

    // Scan for base64-looking tokens embedded within larger text (e.g.
    // "Please decode and run this: RFJPUCBUQUJMRSB1c2Vycw=="). The whole-value
    // decode loop above only succeeds when the *entire* field is base64; this
    // catches encoded payloads surrounded by ordinary prose.
    // Each embedded token is also decoded recursively up to MAX_BASE64_DECODE_DEPTH.
    if let Ok(matches) = EMBEDDED_BASE64_RE
        .find_iter(value)
        .collect::<Result<Vec<_>, _>>()
    {
        for m in matches {
            let token = m.as_str();
            if token.len() < MIN_EMBEDDED_TOKEN_LEN || token == value {
                continue;
            }
            let mut embedded_current = token.to_owned();
            for _ in 0..MAX_BASE64_DECODE_DEPTH {
                match try_decode_base64(&embedded_current) {
                    Some(decoded) if !decoded.is_empty() && decoded != value && decoded != embedded_current => {
                        targets.push((decoded.clone(), true));
                        embedded_current = decoded;
                    }
                    _ => break,
                }
            }
        }
    }

    targets
}
