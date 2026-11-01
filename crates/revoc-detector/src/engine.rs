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
    http_plugin::HttpDetectionPlugin, onnx_detector::OnnxDetector, regex_detector::RegexDetector,
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

    /// Build an engine from an explicit list of stages (custom plugins,
    /// fault-injection tests).
    pub fn from_stages(stages: Vec<Arc<dyn DetectionStage>>) -> Self {
        Self {
            stages,
            metrics: RevocMetrics::global(),
        }
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
    /// Stage errors are logged as warnings and that stage's findings are
    /// skipped. Use [`Self::detect_checked`] where a missing stage must fail
    /// the request. The returned list is sorted by severity (descending).
    pub async fn detect(&self, input: &InspectionInput) -> Vec<Finding> {
        self.run_stages(input).await.0
    }

    /// Run all stages; returns the findings and the number of stages that errored.
    async fn run_stages(&self, input: &InspectionInput) -> (Vec<Finding>, usize) {
        let futures: Vec<_> = self
            .stages
            .iter()
            .map(|stage| {
                let stage = Arc::clone(stage);
                let input = input.clone();
                async move { (stage.name(), stage.detect(&input).await) }
            })
            .collect();

        let results = join_all(futures).await;
        let mut findings: Vec<Finding> = Vec::new();
        let mut failed = 0usize;

        for (name, result) in results {
            match result {
                Ok(f) => findings.extend(f),
                Err(e) => {
                    failed += 1;
                    warn!(stage = name, error = %e, "Detection stage error");
                }
            }
        }

        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        (findings, failed)
    }

    /// Run every stage and fail if any stage errored.
    ///
    /// # Errors
    /// Returns [`RevocError::Detection`] naming how many stages failed, so the
    /// caller can fail closed instead of treating partial results as clean.
    pub async fn detect_checked(
        &self,
        input: &InspectionInput,
    ) -> Result<Vec<Finding>, RevocError> {
        let (findings, failed) = self.run_stages(input).await;
        if failed > 0 {
            return Err(RevocError::Detection(format!(
                "{failed} detection stage(s) failed"
            )));
        }
        Ok(findings)
    }

    /// Run detection with a per-call timeout.
    ///
    /// # Errors
    /// Returns [`RevocError::Detection`] when the timeout is exceeded or any
    /// stage fails. Never returns an empty "clean" result in place of a scan.
    pub async fn detect_with_timeout(
        &self,
        input: &InspectionInput,
        time_limit: Duration,
    ) -> Result<Vec<Finding>, RevocError> {
        if let Ok(result) = timeout(time_limit, self.detect_checked(input)).await {
            result
        } else {
            warn!(timeout_ms = time_limit.as_millis(), "Detection timed out");
            Err(RevocError::Detection(format!(
                "detection timed out after {}ms",
                time_limit.as_millis()
            )))
        }
    }

    /// Run detection with the default 8-second timeout.
    ///
    /// # Errors
    /// See [`Self::detect_with_timeout`].
    pub async fn detect_default_timeout(
        &self,
        input: &InspectionInput,
    ) -> Result<Vec<Finding>, RevocError> {
        self.detect_with_timeout(input, DEFAULT_DETECT_TIMEOUT)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use revoc_core::{CallerContext, DetectionTier, RequestType};

    #[derive(Debug)]
    struct FailingStage;
    #[async_trait]
    impl DetectionStage for FailingStage {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn tier(&self) -> DetectionTier {
            DetectionTier::HttpPlugin
        }
        async fn detect(&self, _input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
            Err(RevocError::Detection("injected failure".into()))
        }
    }

    #[derive(Debug)]
    struct SlowStage;
    #[async_trait]
    impl DetectionStage for SlowStage {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn tier(&self) -> DetectionTier {
            DetectionTier::HttpPlugin
        }
        async fn detect(&self, _input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(Vec::new())
        }
    }

    fn input() -> InspectionInput {
        InspectionInput {
            request_id: "t".into(),
            request_type: RequestType::LlmRequest,
            raw_body: bytes::Bytes::from_static(b"{}"),
            parsed_messages: None,
            mcp_call: None,
            caller: CallerContext::default(),
            governance_depth: 0,
        }
    }

    #[tokio::test]
    async fn failed_stage_is_an_error_not_clean() {
        let engine =
            DetectionEngine::from_stages(vec![Arc::new(RegexDetector), Arc::new(FailingStage)]);
        let res = engine
            .detect_with_timeout(&input(), Duration::from_secs(1))
            .await;
        assert!(matches!(res, Err(RevocError::Detection(_))));
    }

    #[tokio::test]
    async fn timeout_is_an_error_not_clean() {
        let engine = DetectionEngine::from_stages(vec![Arc::new(SlowStage)]);
        let res = engine
            .detect_with_timeout(&input(), Duration::from_millis(20))
            .await;
        assert!(matches!(res, Err(RevocError::Detection(_))));
    }

    #[tokio::test]
    async fn healthy_stages_return_ok() {
        let engine = DetectionEngine::new_for_testing();
        let res = engine
            .detect_with_timeout(&input(), Duration::from_secs(1))
            .await;
        assert!(res.is_ok());
    }
}
