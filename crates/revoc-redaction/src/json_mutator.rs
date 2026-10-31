// In-place JSON body mutation preserving structure.
//
// Applies byte-offset span replacements to string fields inside a JSON value,
// then re-serializes. Field paths use the notation:
// - `messages[0].content`
// - `choices[0].message.content`
// - `tool_call.arguments.query`

use std::cmp::Reverse;

use revoc_core::RevocError;

// ── SpanReplacement ───────────────────────────────────────────────────────────

/// A single span replacement to apply to a JSON string field.
#[derive(Debug, Clone)]
pub struct SpanReplacement {
    /// Start byte offset within the (unescaped) string value (inclusive).
    pub start: usize,
    /// End byte offset within the (unescaped) string value (exclusive).
    pub end: usize,
    /// The text that replaces `original[start..end]`.
    pub replacement: String,
}

// ── apply_span_redactions ─────────────────────────────────────────────────────

/// Apply all span replacements to the JSON body and return the mutated bytes.
///
/// Steps:
/// 1. Parse `body` as a JSON value.
/// 2. For each `(field_path, replacements)`, navigate to the field.
/// 3. Sort replacements by `start` **descending** (so earlier offsets remain valid
///    as we apply from the end).
/// 4. Apply each replacement to the string value.
/// 5. Re-serialize the modified value.
///
/// # Errors
/// Returns [`RevocError::Redaction`] if the body is not valid JSON.
/// Returns [`RevocError::Redaction`] if a replacement produces invalid UTF-8.
pub fn apply_span_redactions(
    body: &[u8],
    redactions: &[(String, Vec<SpanReplacement>)],
) -> Result<Vec<u8>, RevocError> {
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| RevocError::Redaction(format!("Body is not valid JSON: {e}")))?;

    for (field_path, replacements) in redactions {
        if replacements.is_empty() {
            continue;
        }

        let Some(field_value) = navigate_json_path(&mut value, field_path) else {
            // Field not found in this body — skip silently
            continue;
        };

        let serde_json::Value::String(ref mut text) = field_value else {
            // Target is not a string — skip
            continue;
        };

        // Sort descending by start so earlier offsets remain stable
        let mut sorted = replacements.clone();
        sorted.sort_by_key(|b| Reverse(b.start));

        for rep in &sorted {
            let len = text.len();
            let start = rep.start.min(len);
            let end = rep.end.min(len);
            if start >= end {
                continue;
            }
            // Ensure we don't split a UTF-8 character
            // Clamp to nearest char boundary
            let start = clamp_to_char_boundary(text, start);
            let end = clamp_to_char_boundary(text, end);
            text.replace_range(start..end, &rep.replacement);
        }
    }

    serde_json::to_vec(&value).map_err(RevocError::Serialization)
}

/// Clamp `idx` to the nearest valid UTF-8 char boundary at or before `idx`.
fn clamp_to_char_boundary(s: &str, idx: usize) -> usize {
    let idx = idx.min(s.len());
    // Walk backwards until we're at a char boundary
    let mut i = idx;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Read the text at a given field path (immutable — used for extracting original
/// values before mutation for hashing).
pub fn get_field_text<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a str> {
    navigate_json_path_ref(root, path)?.as_str()
}

/// Re-serialize `body` with the string value at each of `field_paths` replaced
/// by its D8-normalized form (SPEC.md §9 D8 — NFKC + zero-width + RTLO/BIDI +
/// control-char removal).
///
/// Detection spans for findings with `was_normalized = true` are byte offsets
/// into the *normalized* text, not the original field text (e.g. zero-width
/// characters are stripped before regex scanning, so byte offsets shift). To
/// keep span-based redaction consistent and UTF-8-safe, fields containing such
/// findings must be normalized in the body *before* `apply_span_redactions` is
/// called against the same offsets.
///
/// Fields not present, not strings, or already equal to their normalized form
/// are left unchanged. Idempotent: normalizing an already-normalized field is a
/// no-op (per [`revoc_detector::normalize`]'s idempotence guarantee).
///
/// # Errors
/// Returns [`RevocError::Redaction`] if `body` is not valid JSON.
pub fn normalize_body_fields(body: &[u8], field_paths: &[String]) -> Result<Vec<u8>, RevocError> {
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| RevocError::Redaction(format!("Body is not valid JSON: {e}")))?;

    for path in field_paths {
        if let Some(serde_json::Value::String(s)) = navigate_json_path(&mut value, path) {
            let n = revoc_detector::normalize(s);
            if n.was_modified {
                *s = n.text;
            }
        }
    }

    serde_json::to_vec(&value).map_err(RevocError::Serialization)
}

// ── Path navigation ───────────────────────────────────────────────────────────

/// Navigate a dot-separated path with optional array indices.
///
/// Handles paths like `messages[0].content`, `choices[1].message.content`,
/// `tool_call.arguments.query`.
fn navigate_json_path<'a>(
    root: &'a mut serde_json::Value,
    path: &str,
) -> Option<&'a mut serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = navigate_segment_mut(current, segment)?;
    }
    Some(current)
}

/// Immutable version of [`navigate_json_path`].
fn navigate_json_path_ref<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = navigate_segment_ref(current, segment)?;
    }
    Some(current)
}

fn navigate_segment_mut<'a>(
    node: &'a mut serde_json::Value,
    segment: &str,
) -> Option<&'a mut serde_json::Value> {
    if let Some(bracket) = segment.find('[') {
        let key = &segment[..bracket];
        let mut current = if key.is_empty() {
            node
        } else {
            node.get_mut(key)?
        };
        // Process all [N] index accesses in this segment
        let mut rest = &segment[bracket..];
        while rest.starts_with('[') {
            let close = rest.find(']')?;
            let idx: usize = rest[1..close].parse().ok()?;
            current = current.get_mut(idx)?;
            rest = &rest[close + 1..];
        }
        Some(current)
    } else {
        node.get_mut(segment)
    }
}

fn navigate_segment_ref<'a>(
    node: &'a serde_json::Value,
    segment: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(bracket) = segment.find('[') {
        let key = &segment[..bracket];
        let mut current = if key.is_empty() { node } else { node.get(key)? };
        let mut rest = &segment[bracket..];
        while rest.starts_with('[') {
            let close = rest.find(']')?;
            let idx: usize = rest[1..close].parse().ok()?;
            current = current.get(idx)?;
            rest = &rest[close + 1..];
        }
        Some(current)
    } else {
        node.get(segment)
    }
}
