//! Compiled detection patterns for all four categories.
//!
//! All patterns use `fancy_regex::Regex` to support lookahead / lookbehind
//! where needed (e.g. SSN exclusions). Patterns are compiled once via
//! `once_cell::sync::Lazy` and reused across all requests.

pub mod financial;
pub mod pii;
pub mod secrets;
pub mod security;
