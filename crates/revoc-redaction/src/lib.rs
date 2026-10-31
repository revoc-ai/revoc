//! Redaction engine for REVOC — removes, masks, or hashes sensitive entities
//! found by the detection pipeline before responses reach the client.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// JSON mutation utilities for applying span-based redactions to request and response bodies.
pub mod json_mutator;
pub mod redactor;
pub mod strategy;

pub use json_mutator::{apply_span_redactions, normalize_body_fields, SpanReplacement};
pub use redactor::RevocRedactor;
pub use strategy::{strategy_for, RedactionStrategy};

#[cfg(test)]
mod tests;
