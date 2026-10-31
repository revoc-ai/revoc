//! Detection pipeline orchestrator and finding deduplication for REVOC.
//!
//! The pipeline runs all detection stages (via [`revoc_detector::DetectionEngine`]),
//! deduplicates overlapping findings, and returns a sorted [`PipelineResult`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod deduplication;
pub mod pipeline;

pub use deduplication::deduplicate;
pub use pipeline::{Pipeline, PipelineResult};

#[cfg(test)]
mod tests;
