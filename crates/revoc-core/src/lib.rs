//! Core types, traits, and error definitions for the REVOC AI Governance Gateway.
//!
//! This crate sits at the root of the dependency graph — every other REVOC crate
//! depends on it. It defines the shared vocabulary: [`RevocError`], all wire
//! types ([`Finding`], [`PolicyDecision`], [`CallerContext`], etc.), the
//! [`McpBlockResponse`] JSON-RPC envelope, and the three async traits
//! ([`DetectionStage`], [`PolicyEngine`], [`Redactor`]) that the upper crates
//! implement.
//!
//! # Safety
//! `#![forbid(unsafe_code)]` is enforced on this crate; no `unsafe` block may
//! appear anywhere in the source.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod traits;
pub mod types;

// ── Flat re-exports ───────────────────────────────────────────────────────────

pub use error::RevocError;

pub use types::decision::{
    Action, CallerContext, ChatMessage, EnforcementMode, PolicyDecision, PolicyEngineMode,
    PolicyInput, PolicyRuleTier, RequestType, SessionState, TokenUsage,
};
pub use types::finding::{
    DetectionTier, Finding, FindingType, PiiEntityType, Severity, TextSpan,
};
pub use types::mcp::{
    McpBlockResponse, McpMethod, McpRawRequest, McpToolCall, ToolManifestFinding,
};
pub use types::openai::RevocErrorResponse;
pub use traits::{DetectionStage, InspectionInput, PolicyEngine, Redactor};
