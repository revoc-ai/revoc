//! Detection engine — orchestrates all detection stages in parallel.

use std::sync::Arc; // still needed for stages: Vec<Arc<dyn DetectionStage>>
use std::time::Duration;

use futures::future::join_all;
use tokio::time::timeout;
use tracing::warn;

use revoc_config::Config;
use revoc_core::{DetectionStage, Finding, InspectionInput, RevocError};
use revoc_telemetry::RevocMetrics;

use crate::{
    http_plugin::HttpDetectionPlugin,
    onnx_detector::OnnxDetector,
    regex_detector::RegexDetector,
};

/// Default per-detection timeout used by [`DetectionEngine::detect_with_timeout`].
const DEFAULT_DETECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Orchestrates all active detection stages.
pub struct DetectionEngine {
    stages: Vec<Arc<dyn DetectionStage>>,
    #[allow(dead_code)]
    metrics: &'static RevocMetrics,
}

impl DetectionEngine {
    /// Build a `DetectionEngine` from a full [`Config`].
    ///
    /// Always includes [`RegexDetector`].
    /// Adds [`OnnxDetector`] when `cfg.detection.onnx_enabled` is `true`
    /// (logs a warning and continues on failure).
    /// Adds an [`HttpDetectionPlugin`] for each configured HTTP plugin.
    ///
    /// # Errors
    /// Returns [`RevocError::Configuration`] only for unrecoverable errors.
    pub fn new(cfg: &Config, metrics: &'static RevocMetrics) -> Result<Self, RevocError> {
        let mut stages: Vec<Arc<dyn DetectionStage>> = vec![Arc::new(RegexDetector)];

        if cfg.detection.onnx_enabled {
            match OnnxDetector::try_new(
                &cfg.detection.onnx_model_path,
                &cfg.detection.onnx_tokenizer_path,
            ) {
                Ok(d) => stages.push(Arc::new(d)),
                Err(e) => warn!(error = %e, "ONNX detector unavailable — continuing without it"),
            }
        }

        for plugin_cfg in &cfg.detection.http_plugins {
            if plugin_cfg.enabled {
                stages.push(Arc::new(HttpDetectionPlugin::new(
                    &plugin_cfg.name,
                    &plugin_cfg.url,
                    plugin_cfg.timeout_ms,
                )));
            }
        }

        Ok(Self { stages, metrics })
    }

    /// Build a minimal engine suitable for tests and fuzz targets.
    ///
    /// Contains only [`RegexDetector`] using the global metrics singleton.
    pub fn new_for_testing() -> Self {
        Self {
            stages: vec![Arc::new(RegexDetector)],
            metrics: RevocMetrics::global(),
        }
    }

    /// Run all detection stages concurrently and collect findings.
    ///
    /// Stage errors are logged as warnings; the stage's findings are skipped.
    /// The returned list is sorted by severity (descending).
    pub async fn detect(&self, input: &InspectionInput) -> Vec<Finding> {
        let futures: Vec<_> = self
            .stages
            .iter()
            .map(|stage| {
                let stage = Arc::clone(stage);
                let input = input.clone();
                async move { stage.detect(&input).await }
            })
            .collect();

        let results = join_all(futures).await;
        let mut findings: Vec<Finding> = Vec::new();

        for result in results {
            match result {
                Ok(f) => findings.extend(f),
                Err(e) => warn!(error = %e, "Detection stage error — skipping"),
            }
        }

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    /// Run detection with a per-call timeout.
    ///
    /// Returns `vec![]` and logs a warning when the timeout is exceeded.
    pub async fn detect_with_timeout(
        &self,
        input: &InspectionInput,
        time_limit: Duration,
    ) -> Vec<Finding> {
        if let Ok(findings) = timeout(time_limit, self.detect(input)).await {
            findings
        } else {
            warn!(
                timeout_ms = time_limit.as_millis(),
                "Detection timed out — returning empty findings"
            );
            vec![]
        }
    }

    /// Run detection with the default 8-second timeout.
    pub async fn detect_default_timeout(&self, input: &InspectionInput) -> Vec<Finding> {
        self.detect_with_timeout(input, DEFAULT_DETECT_TIMEOUT).await
    }
}
