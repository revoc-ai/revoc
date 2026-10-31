//! D8 — Unicode normalization before every detection pass (SPEC.md §9 D8).
//!
//! Must be called on every text field **before** any regex detection.
//! `normalize()` is guaranteed idempotent:
//! `normalize(normalize(x)).text == normalize(x).text`

use unicode_normalization::UnicodeNormalization;

/// Output of the normalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedText {
    /// Normalized text, safe for regex scanning.
    pub text: String,
    /// `true` if normalization changed the input — signals a possible evasion attempt.
    pub was_modified: bool,
}

/// Zero-width characters stripped in Step 2 (7 chars).
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // Zero Width Space
    '\u{200C}', // Zero Width Non-Joiner
    '\u{200D}', // Zero Width Joiner
    '\u{FEFF}', // BOM / Zero Width No-Break Space
    '\u{00AD}', // Soft Hyphen
    '\u{2060}', // Word Joiner
    '\u{180E}', // Mongolian Vowel Separator
];

/// BIDI / RTLO override characters stripped in Step 3 (9 chars).
const BIDI_OVERRIDES: &[char] = &[
    '\u{202E}', // Right-to-Left Override
    '\u{202D}', // Left-to-Right Override
    '\u{202A}', // Left-to-Right Embedding
    '\u{202B}', // Right-to-Left Embedding
    '\u{202C}', // Pop Directional Formatting
    '\u{2066}', // Left-to-Right Isolate
    '\u{2067}', // Right-to-Left Isolate
    '\u{2068}', // First Strong Isolate
    '\u{2069}', // Pop Directional Isolate
];

/// Normalize `text` before regex detection (SPEC.md §9 D8).
///
/// Performs five steps in order:
/// 1. **NFKC** — converts fullwidth/halfwidth chars, ligatures, and
///    compatibility equivalents to their standard ASCII/Unicode forms
///    (e.g. `ＤＲＯＰTable` → `DROPTable`).
/// 2. **Zero-width removal** — strips 7 invisible chars (`U+200B` etc.).
/// 3. **RTLO/BIDI removal** — strips 9 bidirectional override chars
///    (`U+202E` etc.).
/// 4. **Control char removal** — strips non-printable control characters
///    while preserving `\n`, `\r`, and `\t`.  Control chars between two word
///    characters are replaced with a space (prevents `DROP\x00TABLE` → `DROPTABLE`
///    word-boundary bypass; produces `DROP TABLE` instead).
/// 5. **NFKC re-pass** — restores canonical combining-class order after
///    Steps 2–4 may have made adjacent combining characters (e.g. U+05B6
///    CCC=30 and U+20EE CCC=220) out of order by removing the CCC=0
///    control chars that previously separated them.
///
/// **Why the re-pass guarantees idempotency**: `normalize(normalize(x))`
/// = `NFKC(filter(NFKC(filter(NFKC(x)))))`. Since `NFKC(NFKC(y)) = NFKC(y)`
/// and `filter` is stable on already-filtered output, the whole expression
/// collapses to `NFKC(filter(NFKC(x))) = normalize(x)`. ∎
pub fn normalize(text: &str) -> NormalizedText {
    // Step 1: NFKC normalization
    let s1: String = text.nfkc().collect();

    // Step 1.5: Undo RTLO (U+202E) spans by reversing their content back to
    // logical reading order, e.g. "\u{202E}sresu ELBAT PORD\u{202C}" becomes
    // "DROP TABLE users". RTLO only changes *display* order — the underlying
    // characters are stored reversed — so a regex pass on the raw string
    // would never see "DROP TABLE". This neutralizes that evasion before the
    // override markers themselves are stripped in Step 3.
    let s1b = reverse_rtlo_spans(&s1);

    // Step 2: Zero-width character removal
    let s2: String = s1b.chars().filter(|c| !ZERO_WIDTH.contains(c)).collect();

    // Step 3: RTLO/BIDI override character removal
    let s3: String = s2.chars().filter(|c| !BIDI_OVERRIDES.contains(c)).collect();

    // Step 4: Non-printable control character removal (preserve \n \r \t).
    // Control characters that appear *between* two word characters (letter,
    // digit, or underscore) are replaced with a single space instead of being
    // dropped. Without this, "DROP\x00TABLE" collapses to "DROPTABLE" which
    // evades word-boundary-anchored DDL regexes (`DROP\s+TABLE`). Replacing
    // the NUL with a space produces "DROP TABLE" and the pattern fires as
    // intended. Control chars that are NOT between word chars (e.g. leading
    // or trailing NUL, NUL adjacent to punctuation or whitespace) are dropped.
    let chars4: Vec<char> = s3.chars().collect();
    let mut s4_chars: Vec<char> = Vec::with_capacity(chars4.len());
    for (i, &c) in chars4.iter().enumerate() {
        if !c.is_control() || matches!(c, '\n' | '\r' | '\t') {
            s4_chars.push(c);
        } else {
            let prev_is_word = i > 0
                && (chars4[i - 1].is_alphanumeric() || chars4[i - 1] == '_');
            let next_is_word = i + 1 < chars4.len()
                && (chars4[i + 1].is_alphanumeric() || chars4[i + 1] == '_');
            if prev_is_word && next_is_word {
                s4_chars.push(' ');
            }
            // Otherwise drop: leading/trailing control chars or those adjacent
            // to whitespace/punctuation do not bridge word boundaries.
        }
    }
    let s4: String = s4_chars.into_iter().collect();

    // Step 5: Re-apply NFKC to restore canonical combining-class order.
    // Removing CCC=0 control/zero-width chars in Steps 2–4 can leave adjacent
    // combining characters (non-zero CCC) out of canonical order.  A second
    // NFKC pass sorts them back, making the function provably idempotent.
    let result: String = s4.nfkc().collect();

    NormalizedText {
        was_modified: result != text,
        text: result,
    }
}

/// Reverse the content of every `U+202E` (RTLO) ... `U+202C` (PDF) span back
/// to logical reading order. Unmatched `U+202E` (no following `U+202C`)
/// reverses to the end of the string. The `U+202E`/`U+202C` markers
/// themselves are dropped here; any other BIDI overrides are left for the
/// later filter step.
///
/// Idempotent: a string with no `U+202E` is returned unchanged, and the
/// output of this function never contains `U+202E`.
fn reverse_rtlo_spans(s: &str) -> String {
    if !s.contains('\u{202E}') {
        return s.to_owned();
    }

    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\u{202E}' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '\u{202C}' {
                j += 1;
            }
            let mut span: Vec<char> = chars[i + 1..j].to_vec();
            span.reverse();
            out.extend(span);
            // Skip the trailing PDF marker too, if present.
            i = if j < chars.len() { j + 1 } else { j };
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }

    out.into_iter().collect()
}
