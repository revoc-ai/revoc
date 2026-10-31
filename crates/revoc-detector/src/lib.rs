//! Detection engine for the REVOC AI Governance Gateway.
//!
//! Build order: `normalization` → `encoding` → `patterns` → `regex_detector`
//! → `manifest_analyzer` → `engine`.
//!
//! All stages implement the [`revoc_core::DetectionStage`] trait.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod encoding;
pub mod engine;
pub mod enrichers;
pub mod http_plugin;
pub mod manifest_analyzer;
pub mod normalization;
pub mod onnx_detector;
pub mod patterns;
pub mod regex_detector;

#[cfg(test)]
mod tests;

pub use engine::DetectionEngine;
pub use manifest_analyzer::{analyze_tools_list, ManifestAnalysisResult, ManifestFinding};
pub use normalization::{normalize, NormalizedText};
pub use regex_detector::{extract_all_text_fields, RegexDetector};
