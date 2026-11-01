# SPEC.md — REVOC v1.0 Design Specification
## Runtime Execution Validation & Observability Control

> The design source of truth for REVOC. Every type, behavior, security property
> and invariant is defined here. Code and doc comments cite it as `SPEC.md §N`.

---

## SECTION 1 — IDENTITY

| Field | Value |
|---|---|
| **Product** | REVOC — Runtime Execution Validation & Observability Control |
| **Domain** | revoc.io |
| **License** | Apache 2.0 |
| **Rust** | 1.80.0 (pinned) |
| **Python** | 3.12+ |
| **Node** | 20+ |
| **Proxy image** | `ghcr.io/revoc-ai/revoc:latest` |
| **ML image** | `ghcr.io/revoc-ai/revoc:latest-ml` |
| **Python SDK** | `revoc-sdk` |
| **Node SDK** | `@revoc-io/sdk` |
| **Admin package** | `revoc-gateway` |

---

## SECTION 2 — CORE PROMISE

```python
# Before
client = OpenAI(api_key="sk-...")

# After — 30 rules active, dashboard at :3000, full audit
client = OpenAI(api_key="sk-...", base_url="http://revoc:8080")
```

Zero-code-change via environment variable:
```bash
export REVOC_BASE_URL=http://revoc:8080
# All existing code now governed. No source changes.
```

**Three deployment tiers:**
- **Tier 1 (single container):** `docker run -p 8080:8080 -p 3000:3000 ghcr.io/revoc-ai/revoc:latest`
- **Tier 2 (team):** docker compose — adds Postgres + Redis
- **Tier 3 (enterprise):** Helm — HA, OPA sidecar, OTel, autoscaling

---

## SECTION 3 — 15 NON-NEGOTIABLE PRINCIPLES

Violation of any principle is a bug, not a trade-off.

1. Zero governance code in application code — proxy is 100% out-of-band
2. P95 proxy overhead < 10ms, P99 < 25ms — benchmarked not aspirational
3. Rust-native detection — no external HTTP in Tier 1/Tier 2 detection hot path
4. Bidirectional governance — every direction, every protocol, every modality
5. **Normalize before detect** — NFKC + zero-width removal before every regex pass (Rule D8)
6. **Max governance depth 10** — prevents infinite agent recursion (Rule D9)
7. Fail-closed — `fail_open = false` is non-negotiable in production
8. **Upstream error transparency** — 4xx/5xx forwarded verbatim, NEVER wrapped in RevocErrorResponse
9. No PII in logs or audit values — store entity type + field + position, NEVER content
10. **Emergency kill-switch** — stops all traffic across all instances within 50ms (Rule D11)
11. X-Revoc-Dashboard on every response — non-negotiable developer trust header
12. X-Revoc-Timing on every response — prevents blaming REVOC for slow upstreams
13. **Tool manifest analysis** — tools/list responses analyzed before reaching AI (Rule D10)
14. **Security rules always win** — Tier 3 security cannot be overridden by custom allow (Rule D12)
15. No unsafe code — `#![forbid(unsafe_code)]` on all library crates

---

## SECTION 4 — NINE CRATES (DEPENDENCY ORDER)

```
revoc-core → revoc-config → revoc-telemetry → revoc-detector →
revoc-pipeline → revoc-policy → revoc-redaction → revoc-dashboard → revoc-proxy
```

---

## SECTION 5 — WORKSPACE Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/revoc-core",
    "crates/revoc-config",
    "crates/revoc-telemetry",
    "crates/revoc-detector",
    "crates/revoc-pipeline",
    "crates/revoc-policy",
    "crates/revoc-redaction",
    "crates/revoc-dashboard",
    "crates/revoc-proxy",
]

[workspace.dependencies]
tokio          = { version = "1.40",  features = ["full"] }
tokio-util     = { version = "0.7",   features = ["io","codec"] }
axum           = { version = "0.7",   features = ["http2","macros","multipart"] }
axum-extra     = { version = "0.9",   features = ["typed-header"] }
tower          = { version = "0.5",   features = ["full"] }
tower-http     = { version = "0.6",   features = ["full"] }
hyper          = { version = "1.4",   features = ["full"] }
hyper-util     = { version = "0.1",   features = ["full"] }
reqwest        = { version = "0.12",  features = ["json","stream","rustls-tls","gzip"], default-features = false }
serde          = { version = "1.0",   features = ["derive"] }
serde_json     = { version = "1.0",   features = ["preserve_order"] }
thiserror      = "1.0"
anyhow         = "1.0"
tracing               = "0.1"
tracing-subscriber    = { version = "0.3", features = ["env-filter","json"] }
tracing-opentelemetry = "0.27"
opentelemetry             = { version = "0.26", features = ["metrics"] }
opentelemetry_sdk         = { version = "0.26", features = ["rt-tokio","metrics"] }
opentelemetry-otlp        = { version = "0.26", features = ["grpc-tonic","metrics"] }
opentelemetry-semantic-conventions = "0.26"
dashmap        = "6.1"
arc-swap       = "1.7"
smallvec       = { version = "1.13",  features = ["serde"] }
sqlx           = { version = "0.8",   features = ["runtime-tokio-rustls","sqlite","postgres","uuid","chrono","json","migrate"] }
redis          = { version = "0.27",  features = ["tokio-comp","connection-manager","aio"] }
wasmtime       = { version = "25.0",  default-features = false, features = ["cranelift","component-model"] }
ort            = { version = "2.0",   features = ["load-dynamic"] }
ndarray        = "0.15"
uuid           = { version = "1.10",  features = ["v7","serde"] }
chrono         = { version = "0.4",   features = ["serde"] }
sha2           = "0.10"
hex            = "0.4"
subtle         = "2.6"
zeroize        = "1.8"
unicode-normalization = "0.1"
regex          = "1.10"
fancy-regex    = "0.13"
config         = { version = "0.14",  features = ["toml","yaml"] }
jsonwebtoken   = "9.3"
prometheus     = { version = "0.13",  features = ["process"] }
futures        = "0.3"
async-trait    = "0.1"
bytes          = "1.7"
http           = "1.1"
http-body-util = "0.1"
once_cell      = "1.19"
mime           = "0.3"
include_dir    = "0.7"
rust_decimal   = { version = "1.36",  features = ["serde"] }
clap           = { version = "4.5",   features = ["derive","env"] }
nix            = { version = "0.29",  features = ["signal"] }
base64         = "0.22"
url            = "2.5"

[workspace.dev-dependencies]
tokio-test    = "0.4"
wiremock      = "0.6"
proptest      = "1.5"
criterion     = { version = "0.5",   features = ["html_reports","async_tokio"] }
rstest        = "0.22"
fake          = { version = "2.9",   features = ["derive"] }
insta         = { version = "1.39",  features = ["json","yaml"] }
assert_matches = "1.5"

[profile.release]
opt-level    = 3
lto          = "thin"
codegen-units = 1
panic        = "abort"
strip        = true

[profile.dev]
opt-level  = 1
debug      = true
incremental = true
```

---

## SECTION 6 — COMPLETE DIRECTORY TREE

```
revoc/
├── CLAUDE.md                    ← Contributor / coding-agent guide
├── SPEC.md                      ← This file
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
├── GOVERNANCE.md
├── NOTICE
├── LICENSE
├── Makefile
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── cliff.toml
├── .env.example
├── .gitignore
├── .editorconfig
├── .claude/settings.json        ← Shared Claude Code tool permissions
├── .cargo/config.toml
├── .github/
│   ├── workflows/ (ci.yml, release.yml, security.yml, docs.yml)
│   ├── ISSUE_TEMPLATE/ (bug_report.yml, feature_request.yml)
│   ├── CODEOWNERS
│   └── pull_request_template.md
├── crates/
│   ├── revoc-core/src/
│   │   ├── lib.rs
│   │   ├── error.rs
│   │   ├── traits.rs
│   │   └── types/ (mod.rs, finding.rs, decision.rs, mcp.rs, openai.rs)
│   ├── revoc-config/src/ (lib.rs, schema.rs, loader.rs)
│   ├── revoc-telemetry/src/ (lib.rs, tracer.rs, metrics.rs, attributes.rs, logger.rs)
│   ├── revoc-detector/src/
│   │   ├── lib.rs
│   │   ├── normalization.rs       ← MUST be built first in Phase 5
│   │   ├── engine.rs
│   │   ├── regex_detector.rs
│   │   ├── onnx_detector.rs
│   │   ├── encoding.rs
│   │   ├── manifest_analyzer.rs
│   │   ├── http_plugin.rs
│   │   ├── patterns/ (mod.rs, pii.rs, secrets.rs, security.rs, financial.rs)
│   │   ├── enrichers/ (mod.rs, presidio.rs, azure.rs)
│   │   └── tests/ (mod.rs, pii_tests.rs, security_tests.rs, encoding_tests.rs, normalization_tests.rs)
│   ├── revoc-pipeline/src/ (lib.rs, pipeline.rs, deduplication.rs)
│   ├── revoc-policy/src/ (lib.rs, engine.rs, native.rs, sidecar.rs, wasm.rs, cache.rs, conflict.rs, defaults.rs)
│   ├── revoc-redaction/src/ (lib.rs, redactor.rs, strategy.rs, json_mutator.rs)
│   ├── revoc-dashboard/
│   │   ├── ui/                    (React SPA source)
│   │   ├── ui/dist/               (pre-built — MUST be committed to git)
│   │   └── src/ (lib.rs, handler.rs, live_feed.rs, api.rs, auth.rs)
│   └── revoc-proxy/src/
│       ├── main.rs
│       ├── app.rs
│       ├── shutdown.rs
│       ├── kill_switch/ (mod.rs, service.rs, store.rs)  ← D11
│       ├── depth.rs               ← NEW Day-1 D9
│       ├── handlers/ (mod.rs, llm.rs, mcp.rs, embeddings.rs, emergency.rs, health.rs)
│       ├── middleware/ (mod.rs, auth.rs, request_id.rs, rate_limit.rs, metrics_recorder.rs, security.rs)
│       ├── upstream/ (mod.rs, client.rs, router.rs, retry.rs, streaming.rs, error.rs)
│       ├── streaming/ (mod.rs, governor.rs, tool_accumulator.rs)
│       └── tests/ (mod.rs, llm_handler_tests.rs, mcp_handler_tests.rs, streaming_tests.rs, kill_switch_tests.rs, depth_tests.rs)
├── policies/
│   ├── default/ (data.json, main.rego, llm_governance.rego, mcp_governance.rego,
│   │             quota_governance.rego, conflict_resolution.rego,
│   │             main_test.rego, llm_governance_test.rego, mcp_governance_test.rego, quota_governance_test.rego)
│   ├── profiles/ (hipaa.rego, pci-dss.rego, gdpr.rego, soc2.rego, financial-services.rego, internal-dev.rego)
│   ├── examples/ (hipaa-baseline.yaml, pci-dss-baseline.yaml, gdpr-baseline.yaml, internal-dev.yaml)
│   └── schemas/ (policy_manifest.json)
├── models/ (README.md, download.sh)
├── configs/ (revoc.toml, revoc.dev.toml)
├── admin-api/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/ (config.py, database.py, security.py, exceptions.py, logging.py)
│   │   ├── models/ (policy.py, audit.py, user.py, emergency.py)
│   │   ├── schemas/ (policy.py, audit.py, user.py, emergency.py, reports.py, common.py)
│   │   ├── routers/ (policies.py, audit.py, users.py, emergency.py, reports.py, health.py)
│   │   ├── services/ (policy_service.py, compiler_service.py, bundle_service.py,
│   │   │              notification_service.py, emergency_service.py, report_service.py)
│   │   └── middleware/ (telemetry.py)
│   ├── tests/ (conftest.py, test_policies.py, test_compiler.py, test_audit.py, test_auth.py, test_emergency.py)
│   ├── alembic/ (alembic.ini, env.py, versions/001_initial_schema.py)
│   ├── pyproject.toml
│   └── Dockerfile
├── sdk/
│   ├── python/ (revoc_sdk/__init__.py, client.py, governance.py, mcp.py, patch.py, exceptions.py)
│   └── node/ (src/index.ts, client.ts, governance.ts, mcp.ts, types.ts)
├── helm/revoc/ (Chart.yaml, values.yaml, values.production.yaml, templates/*)
├── examples/ (python-quickstart/, python-mcp-governance/, framework-integrations/*, policy-cookbook/*)
├── docs/ (mkdocs.yml, docs/*)
├── tests/ (integration/*, e2e/*, load/*)
├── benches/ (Cargo.toml, benches/*.rs)
└── fuzz/ (Cargo.toml, fuzz_targets/*.rs)
```

---

## SECTION 7 — CORE TYPES (revoc-core)

### 7.1 error.rs

```rust
#[derive(thiserror::Error, Debug)]
pub enum RevocError {
    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluation(String),
    #[error("Policy engine unreachable: {0}")]
    PolicyEngineUnreachable(String),
    #[error("Governance depth exceeded: {depth}/10")]
    GovernanceDepthExceeded { depth: u8 },
    #[error("Kill-switch active: scope={scope}")]
    KillSwitchActive { scope: String },
    #[error("ONNX model error: {0}")]
    OnnxModel(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Authentication failed: {reason}")]
    Authentication { reason: String },
    #[error("Rate limit exceeded for caller '{caller_id}'")]
    RateLimitExceeded { caller_id: String },
    #[error("Upstream error: HTTP {status} from {provider}")]
    Upstream { status: u16, provider: String },
    #[error("Request body too large: {size} bytes (max: {max})")]
    BodyTooLarge { size: usize, max: usize },
    #[error("Request parse error: {0}")]
    RequestParse(String),
    #[error("Redaction failed: {0}")]
    Redaction(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Security violation: {0}")]
    Security(String),
}

impl RevocError {
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::PolicyEngineUnreachable(_) | Self::Upstream { .. })
    }
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Authentication { .. }     => 401,
            Self::RateLimitExceeded { .. }  => 429,
            Self::BodyTooLarge { .. }       => 413,
            Self::RequestParse(_)           => 400,
            Self::PolicyEngineUnreachable(_)=> 503,
            Self::GovernanceDepthExceeded {..}=> 503,
            Self::KillSwitchActive { .. }   => 503,
            Self::Upstream { status, .. }   => *status,
            _                               => 500,
        }
    }
}
```

### 7.2 types/finding.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug,Clone,PartialEq,Eq,Hash,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum FindingType {
    Pii, SecretExposure, DdlMutation, PromptInjection,
    SystemPromptExtraction, SsrfAttempt, PathTraversal,
    KeywordMatch, McpToolBlock, QuotaExceeded, SessionAnomaly,
    ToolManifestRisk,
    #[serde(untagged)] Custom(String),
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum PiiEntityType {
    UsSsn, EmailAddress, PhoneNumber, CreditCard, IpAddressV4, IpAddressV6,
    UsPassport, UsDriverLicense, IbanCode, RoutingNumber, BankAccount, SwiftBic,
    DateOfBirth, MedicalRecordNumber, NpiNumber, DeaNumber,
    AwsAccessKey, AwsSecretKey, GithubToken, OpenaiKey, AnthropicKey,
    GenericApiKey, PrivateKey, JwtToken, PasswordInJson,
    #[serde(untagged)] Custom(String),
}

impl std::fmt::Display for PiiEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UsSsn => "US_SSN", Self::EmailAddress => "EMAIL_ADDRESS",
            Self::PhoneNumber => "PHONE_NUMBER", Self::CreditCard => "CREDIT_CARD",
            Self::IpAddressV4 => "IP_ADDRESS_V4", Self::IpAddressV6 => "IP_ADDRESS_V6",
            Self::UsPassport => "US_PASSPORT", Self::UsDriverLicense => "US_DRIVER_LICENSE",
            Self::IbanCode => "IBAN_CODE", Self::RoutingNumber => "ROUTING_NUMBER",
            Self::BankAccount => "BANK_ACCOUNT", Self::SwiftBic => "SWIFT_BIC",
            Self::DateOfBirth => "DATE_OF_BIRTH", Self::MedicalRecordNumber => "MEDICAL_RECORD_NUMBER",
            Self::NpiNumber => "NPI_NUMBER", Self::DeaNumber => "DEA_NUMBER",
            Self::AwsAccessKey => "AWS_ACCESS_KEY", Self::AwsSecretKey => "AWS_SECRET_KEY",
            Self::GithubToken => "GITHUB_TOKEN", Self::OpenaiKey => "OPENAI_KEY",
            Self::AnthropicKey => "ANTHROPIC_KEY", Self::GenericApiKey => "GENERIC_API_KEY",
            Self::PrivateKey => "PRIVATE_KEY", Self::JwtToken => "JWT_TOKEN",
            Self::PasswordInJson => "PASSWORD_IN_JSON",
            Self::Custom(s) => s,
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug,Clone,PartialEq,Eq,PartialOrd,Ord,Hash,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug,Clone,PartialEq,Eq,Hash,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum DetectionTier { Regex, Onnx, HttpPlugin, Enricher, McpInspector, SessionAnalysis, ManifestAnalysis }

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct TextSpan {
    pub start: usize,
    pub end: usize,
    pub field: String,
    #[serde(skip)]  // NEVER serialized — no PII values in transit
    pub value: Option<String>,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub detection_tier: DetectionTier,
    pub span: Option<TextSpan>,
    pub confidence: f64,
    pub pii_entity: Option<PiiEntityType>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub detected_at: DateTime<Utc>,
    pub redaction_applied: bool,
    pub was_encoded: bool,      // Found in base64/URL-decoded content
    pub was_normalized: bool,   // Found after NFKC/zero-width normalization
}

impl Finding {
    pub fn new(t: FindingType, s: Severity, tier: DetectionTier) -> Self {
        Self { id: Uuid::now_v7(), finding_type: t, severity: s, detection_tier: tier,
               span: None, confidence: 1.0, pii_entity: None, metadata: HashMap::new(),
               detected_at: Utc::now(), redaction_applied: false, was_encoded: false, was_normalized: false }
    }
    pub fn with_span(mut self, span: TextSpan) -> Self { self.span = Some(span); self }
    pub fn with_confidence(mut self, c: f64) -> Self { self.confidence = c; self }
    pub fn with_pii(mut self, e: PiiEntityType) -> Self { self.pii_entity = Some(e); self }
    pub fn is_high_severity(&self) -> bool { matches!(self.severity, Severity::High | Severity::Critical) }
}
```

### 7.3 types/decision.rs

```rust
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum Action { Allow, Redact, Block, Audit }

impl Action {
    pub fn is_blocking(&self) -> bool { matches!(self, Action::Block) }
    pub fn requires_redaction(&self) -> bool { matches!(self, Action::Redact) }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize,Default)]
#[serde(rename_all="snake_case")]
pub enum EnforcementMode { #[default] Enforce, Shadow }

/// Rule tier for conflict resolution. Higher tier always wins.
#[derive(Debug,Clone,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum PolicyRuleTier {
    Default = 0,    // Baseline allow
    Custom = 1,     // Operator custom rules
    Profile = 2,    // Compliance profile rules (HIPAA, PCI-DSS, etc.)
    Security = 3,   // Built-in security rules — CANNOT be overridden
    Emergency = 4,  // Kill-switch — highest precedence
}

#[derive(Debug,Clone,Default,Serialize,Deserialize)]
pub struct CallerContext {
    pub org_id: String,
    pub caller_id: String,
    pub team: Option<String>,
    pub agent_id: Option<String>,
    pub service_name: Option<String>,
    pub environment: String,
    pub policy_profile: Option<String>,
    pub enforcement_mode: EnforcementMode,
    pub governance_depth: u8,   // Incremented on each nested governance call
    pub attributes: std::collections::HashMap<String, String>,
}

impl CallerContext {
    pub fn is_shadow_mode(&self) -> bool { matches!(self.enforcement_mode, EnforcementMode::Shadow) }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub estimated_cost_usd: Option<f64>,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: serde_json::Value,
    #[serde(skip_serializing_if="Option::is_none")] pub name: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")] pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")] pub tool_calls: Option<Vec<serde_json::Value>>,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub org_id: String,
    pub caller_id: String,
    pub tools_called: Vec<(String, chrono::DateTime<chrono::Utc>)>,
    pub total_rows_read: u64,
    pub pii_entities_seen: std::collections::HashSet<String>,
    pub external_send_attempted: bool,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_active: chrono::DateTime<chrono::Utc>,
}

impl SessionState {
    pub fn is_exfil_pattern_detected(&self) -> bool {
        self.total_rows_read > 500
            && !self.pii_entities_seen.is_empty()
            && self.external_send_attempted
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum RequestType { LlmRequest, LlmResponse, McpToolCall, McpToolResult, McpSampling, LlmEmbeddings }

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
pub enum PolicyEngineMode { Native, OpaHttp, OpaWasm }

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PolicyDecision {
    pub action: Action,
    pub effective_action: Action,  // Shadow mode: always Audit regardless of action
    pub reason: String,
    pub applicable_rules: Vec<String>,
    pub severity: super::finding::Severity,
    pub tier: PolicyRuleTier,
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
    pub eval_duration_ms: f64,
    pub cache_hit: bool,
    pub policy_engine: PolicyEngineMode,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        Self { action: Action::Allow, effective_action: Action::Allow,
               reason: "All governance checks passed.".into(),
               applicable_rules: vec![], severity: super::finding::Severity::Info,
               tier: PolicyRuleTier::Default, metadata: Default::default(),
               eval_duration_ms: 0.0, cache_hit: false,
               policy_engine: PolicyEngineMode::Native,
               evaluated_at: chrono::Utc::now() }
    }
    pub fn block(reason: impl Into<String>, rules: Vec<String>) -> Self {
        let mut d = Self::allow();
        d.action = Action::Block; d.effective_action = Action::Block;
        d.reason = reason.into(); d.applicable_rules = rules;
        d.severity = super::finding::Severity::Critical;
        d.tier = PolicyRuleTier::Security;
        d
    }
    pub fn redact(reason: impl Into<String>, rules: Vec<String>) -> Self {
        let mut d = Self::allow();
        d.action = Action::Redact; d.effective_action = Action::Redact;
        d.reason = reason.into(); d.applicable_rules = rules;
        d.tier = PolicyRuleTier::Profile;
        d
    }
    pub fn audit() -> Self {
        let mut d = Self::allow(); d.action = Action::Audit; d.effective_action = Action::Audit; d
    }
    /// Apply shadow mode: keep action, set effective_action=Audit
    pub fn apply_shadow(mut self) -> Self { self.effective_action = Action::Audit; self }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PolicyInput {
    pub request_id: String,
    pub request_type: RequestType,
    pub caller: CallerContext,
    pub findings: Vec<super::finding::Finding>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub messages: Option<Vec<ChatMessage>>,
    pub tool_call: Option<super::mcp::McpToolCall>,
    pub tool_result: Option<serde_json::Value>,
    pub token_usage: Option<TokenUsage>,
    pub session_state: Option<SessionState>,
    pub governance_depth: u8,
    pub timestamp: i64,
}
```

### 7.4 types/mcp.rs

```rust
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum McpMethod {
    Initialize, Ping,
    ToolsList, ToolsCall,
    ResourcesList, ResourcesRead, ResourcesSubscribe,
    PromptsGet, PromptsList,
    SamplingCreateMessage,
    LoggingSetLevel,
    Completion,
}

impl McpMethod {
    /// Returns true if this method requires full governance inspection.
    pub fn requires_governance(&self) -> bool {
        matches!(self, Self::ToolsCall | Self::ResourcesRead | Self::SamplingCreateMessage)
    }
    /// Returns true if this method's RESPONSE should be inspected (bidirectional).
    pub fn response_requires_inspection(&self) -> bool {
        matches!(self, Self::ToolsCall | Self::ResourcesRead)
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct McpToolCall {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub server_id: Option<String>,
    pub call_id: Option<String>,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct McpRawRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC error response for blocked MCP calls.
/// dashboard_url goes in error.data so the AI client can surface it.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct McpBlockResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub error: McpBlockError,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct McpBlockError {
    pub code: i32,
    pub message: String,
    pub data: McpBlockData,
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct McpBlockData {
    pub code: String,
    pub rules: Vec<String>,
    pub trace_id: String,
    pub dashboard_url: String,
}

impl McpBlockResponse {
    pub fn new(id: serde_json::Value, trace_id: &str, rules: Vec<String>,
               reason: &str, dashboard_url: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(), id,
            error: McpBlockError {
                code: -32603,
                message: reason.to_string(),
                data: McpBlockData {
                    code: "REVOC_GOVERNANCE_BLOCK".into(),
                    rules, trace_id: trace_id.to_string(),
                    dashboard_url: dashboard_url.to_string(),
                },
            },
        }
    }
}

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ToolManifestFinding {
    pub tool_name: String,
    pub parameter_name: String,
    pub matched_keyword: String,
    pub severity: super::finding::Severity,
}
```

### 7.5 types/openai.rs

```rust
/// ONLY for REVOC-originated errors. Upstream 4xx/5xx are ALWAYS forwarded verbatim.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RevocErrorResponse { pub error: RevocErrorDetail }

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RevocErrorDetail {
    pub code: String,
    pub message: String,
    pub r#type: String,
    pub blocked_by: Option<String>,
    pub rules: Option<Vec<String>>,
    pub trace_id: String,
    pub dashboard_url: String,
    pub documentation_url: Option<String>,
}

impl RevocErrorResponse {
    pub fn governance_block(trace_id: &str, reason: &str, rules: Vec<String>, dash_base: &str) -> Self {
        let first = rules.first().cloned();
        let doc = first.as_ref().map(|r| format!("https://revoc.io/docs/policies/{}", r));
        Self { error: RevocErrorDetail { code: "REVOC_GOVERNANCE_BLOCK".into(),
            message: reason.to_string(), r#type: "governance_error".into(),
            blocked_by: first, rules: Some(rules), trace_id: trace_id.to_string(),
            dashboard_url: format!("{}/traces/{}", dash_base, trace_id), documentation_url: doc } }
    }
    pub fn kill_switch_active(trace_id: &str, dash_base: &str) -> Self {
        Self { error: RevocErrorDetail { code: "REVOC_KILL_SWITCH_ACTIVE".into(),
            message: "All AI traffic suspended by emergency stop. Contact your AI platform team.".into(),
            r#type: "emergency_stop".into(), blocked_by: None, rules: None,
            trace_id: trace_id.to_string(),
            dashboard_url: format!("{}/emergency", dash_base),
            documentation_url: Some("https://revoc.io/docs/operations/emergency-kill-switch".into()) } }
    }
    pub fn depth_exceeded(trace_id: &str, depth: u8, dash_base: &str) -> Self {
        Self { error: RevocErrorDetail { code: "REVOC_GOVERNANCE_DEPTH_EXCEEDED".into(),
            message: format!("Governance depth limit ({}/10) reached. Possible infinite agent loop.", depth),
            r#type: "depth_exceeded".into(), blocked_by: None, rules: None,
            trace_id: trace_id.to_string(),
            dashboard_url: format!("{}/traces/{}", dash_base, trace_id),
            documentation_url: Some("https://revoc.io/docs/concepts/governance-depth".into()) } }
    }
    pub fn rate_limit(trace_id: &str, retry_after: u64, dash_base: &str) -> Self {
        Self { error: RevocErrorDetail { code: "REVOC_RATE_LIMIT_EXCEEDED".into(),
            message: format!("Rate limit exceeded. Retry after {} seconds.", retry_after),
            r#type: "rate_limit_error".into(), blocked_by: None, rules: None,
            trace_id: trace_id.to_string(), dashboard_url: format!("{}/traces/{}", dash_base, trace_id),
            documentation_url: None } }
    }
    pub fn internal_error(trace_id: &str, dash_base: &str) -> Self {
        Self { error: RevocErrorDetail { code: "REVOC_INTERNAL_ERROR".into(),
            message: "An internal error occurred. Please retry.".into(),
            r#type: "internal_error".into(), blocked_by: None, rules: None,
            trace_id: trace_id.to_string(), dashboard_url: format!("{}/traces/{}", dash_base, trace_id),
            documentation_url: None } }
    }
}
```

### 7.6 traits.rs

```rust
use async_trait::async_trait;
use crate::error::RevocError;
use crate::types::finding::{Finding, DetectionTier};
use crate::types::decision::{PolicyDecision, PolicyInput, RequestType, CallerContext};
use crate::types::mcp::McpToolCall;

#[derive(Debug,Clone)]
pub struct InspectionInput {
    pub request_id: String,
    pub request_type: RequestType,
    pub raw_body: bytes::Bytes,
    pub parsed_messages: Option<Vec<crate::types::decision::ChatMessage>>,
    pub mcp_call: Option<McpToolCall>,
    pub caller: CallerContext,
    pub governance_depth: u8,
}
impl InspectionInput {
    pub fn is_mcp_call(&self) -> bool { self.mcp_call.is_some() }
}

#[async_trait]
pub trait DetectionStage: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;
    fn tier(&self) -> DetectionTier;
    async fn detect(&self, input: &InspectionInput) -> Result<Vec<Finding>, RevocError>;
}

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision, RevocError>;
    async fn reload(&self) -> Result<(), RevocError>;
    fn engine_type(&self) -> crate::types::decision::PolicyEngineMode;
}

pub trait Redactor: Send + Sync {
    fn redact_body(&self, body: &[u8], findings: &[Finding], decision: &PolicyDecision)
        -> Result<(Vec<u8>, Vec<Finding>), RevocError>;
    fn redact_mcp_result(&self, result_json: &[u8], findings: &[Finding], decision: &PolicyDecision)
        -> Result<(Vec<u8>, Vec<Finding>), RevocError>;
}
```

---

## SECTION 8 — DETECTION PATTERNS

### 8.1 PII Patterns (patterns/pii.rs)

| Entity | Regex hint | Validator |
|---|---|---|
| US_SSN | `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b` | None |
| EMAIL_ADDRESS | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` | None |
| PHONE_NUMBER | US phone including +1, dashes, parens | None |
| CREDIT_CARD | Combined Visa/MC/Amex/Discover | `luhn_check()` |
| IBAN_CODE | `\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b` | `iban_checksum_valid()` |
| IP_ADDRESS_V4 | `\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b` | None |
| IP_ADDRESS_V6 | Full IPv6 including compressed | None |
| US_PASSPORT | `\b[A-Z]\d{8}\b` | None |
| US_DRIVER_LICENSE | State-specific patterns | None |
| DATE_OF_BIRTH | Date patterns near dob/born/birthday context | None |
| MEDICAL_RECORD_NUMBER | `(?i)\b(?:mrn|medical\s+record)\s*[:#]?\s*([A-Z0-9\-]{5,20})\b` | None |

Validation functions (all in pii.rs):
- `pub fn luhn_check(s: &str) -> bool` — complete Luhn algorithm
- `pub fn iban_checksum_valid(s: &str) -> bool` — full IBAN mod-97 check
- `pub fn aba_routing_check(s: &str) -> bool` — ABA checksum

### 8.2 Secret Patterns (patterns/secrets.rs)

| Entity | Pattern hint |
|---|---|
| AWS_ACCESS_KEY | `(?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|AROA|ASCA|ASIA)[A-Z0-9]{16}` |
| AWS_SECRET_KEY | 40-char base64 near aws context |
| GITHUB_TOKEN | `ghp_[0-9a-zA-Z]{36}` or `github_pat_[0-9a-zA-Z_]{82}` |
| OPENAI_KEY | `sk-[a-zA-Z0-9]{48}` or `sk-proj-[a-zA-Z0-9_\-]{64,}` |
| ANTHROPIC_KEY | `sk-ant-[a-zA-Z0-9\-_]{95}` |
| GENERIC_API_KEY | `"(?:api[_-]?key|apikey)"\s*:\s*"([A-Za-z0-9\-_]{20,})"` |
| PRIVATE_KEY | `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----` |
| JWT_TOKEN | `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+` |
| PASSWORD_IN_JSON | `"(?:password|passwd|secret)"\s*:\s*"([^"]{6,})"` |

### 8.3 Security Patterns (patterns/security.rs)

| Pattern | Regex hint | Finding type |
|---|---|---|
| DDL_MUTATION | `(?i)\b(DROP|TRUNCATE|ALTER)\s+TABLE\b` | DdlMutation |
| DELETE_NO_WHERE | `(?i)\bDELETE\s+FROM\b` not followed by WHERE | DdlMutation |
| SSRF_INTERNAL | localhost, 127.x, 10.x, 192.168.x, 172.16-31.x, 169.254.x | SsrfAttempt |
| PATH_TRAVERSAL | `(?:\.\./|\.\.\\){1,}` | PathTraversal |
| PROMPT_INJECT | ignore previous/prior/above instructions, disregard system prompt, jailbreak variants | PromptInjection |
| SYS_EXTRACT | reveal your system prompt, what are your instructions, print initial prompt | SystemPromptExtraction |
| MASS_DELETE | DELETE without WHERE on large tables | DdlMutation |

### 8.4 Financial Patterns (patterns/financial.rs)

| Entity | Hint |
|---|---|
| SWIFT_BIC | `\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b` |
| ROUTING_NUMBER | 9 digits with ABA checksum |
| BANK_ACCOUNT | Account number near banking context keywords |

---

## SECTION 9 — NEW DAY-1 SECURITY PROPERTIES

### D8 — Unicode Normalization (revoc-detector/src/normalization.rs)

Must be called on every text field BEFORE any regex detection.

```rust
use unicode_normalization::UnicodeNormalization;

pub struct NormalizedText { pub text: String, pub was_modified: bool }

pub fn normalize(text: &str) -> NormalizedText {
    // Step 1: NFKC — fullwidth (ＤＲＯＰTable→DROPTable), ligatures, etc.
    let s1: String = text.nfkc().collect();
    // Step 2: Zero-width removal (7 chars)
    const ZW: &[char] = &['\u{200B}','\u{200C}','\u{200D}','\u{FEFF}','\u{00AD}','\u{2060}','\u{180E}'];
    let s2: String = s1.chars().filter(|c| !ZW.contains(c)).collect();
    // Step 3: RTLO/BIDI removal (9 chars)
    const BIDI: &[char] = &['\u{202E}','\u{202D}','\u{202A}','\u{202B}','\u{202C}','\u{2066}','\u{2067}','\u{2068}','\u{2069}'];
    let s3: String = s2.chars().filter(|c| !BIDI.contains(c)).collect();
    // Step 4: Non-printable control chars (preserve \n \r \t)
    let result: String = s3.chars().filter(|c| !c.is_control() || matches!(c,'\n'|'\r'|'\t')).collect();
    NormalizedText { was_modified: result != text, text: result }
}
// normalize() MUST be idempotent: normalize(normalize(x)).text == normalize(x).text
```

**Integration**: In `regex_detector.rs::detect()`, for each (field, raw_text):
1. `let n = normalization::normalize(&raw_text);`
2. Scan `n.text`, NOT `raw_text`
3. Set `finding.was_normalized = n.was_modified`

### D9 — Governance Depth (revoc-proxy/src/depth.rs)

```rust
pub const MAX_GOVERNANCE_DEPTH: u8 = 10;
pub const REVOC_DEPTH_HEADER: &str = "X-Revoc-Depth";

pub fn extract_depth(headers: &http::HeaderMap) -> u8 {
    headers.get(REVOC_DEPTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0)
}
pub fn check_depth(depth: u8) -> Result<(), crate::RevocError> {
    if depth >= MAX_GOVERNANCE_DEPTH {
        Err(crate::RevocError::GovernanceDepthExceeded { depth })
    } else { Ok(()) }
}
pub fn set_outgoing_depth(headers: &mut http::HeaderMap, current: u8) {
    let next = current.saturating_add(1);
    if let Ok(v) = next.to_string().parse() { headers.insert(REVOC_DEPTH_HEADER, v); }
}
```

### D10 — Tool Manifest Analysis (revoc-detector/src/manifest_analyzer.rs)

```rust
pub const DANGEROUS_PARAM_KEYWORDS: &[&str] = &[
    "password","passwd","token","secret","api_key","apikey","auth","credential","credentials",
    "private_key","cert","bearer","access_token","refresh_token",
    "cmd","command","eval","exec","shell","script","execute","subprocess",
    "sql","query","statement","raw_sql","admin","root","sudo","privilege",
    "ssn","credit_card","card_number","cvv",
];
pub const SUSPICIOUS_DESC_PATTERNS: &[&str] = &[
    "ignore previous","disregard","override all","system prompt",
    "admin access","privileged","bypass","jailbreak",
];

#[derive(Debug,Clone,serde::Serialize,serde::Deserialize)]
pub struct ManifestFinding { pub tool_name: String, pub parameter_name: String,
    pub matched_keyword: String, pub severity: crate::types::finding::Severity }
pub struct ManifestAnalysisResult { pub findings: Vec<ManifestFinding>, pub tools_analyzed: usize }

pub fn analyze_tools_list(body: &[u8]) -> ManifestAnalysisResult {
    let mut findings = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return ManifestAnalysisResult { findings, tools_analyzed: 0 },
    };
    // Accept {"tools":[...]} or bare [...] arrays
    let tools = match value.get("tools").and_then(|t| t.as_array())
        .or_else(|| value.as_array()) {
        Some(t) => t,
        None => return ManifestAnalysisResult { findings, tools_analyzed: 0 },
    };
    for tool in tools {
        let tool_name = tool.get("name")
            .and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
        // Check parameter names (.inputSchema.properties or .parameters.properties)
        if let Some(props) = tool.pointer("/inputSchema/properties")
            .or_else(|| tool.pointer("/parameters/properties"))
            .and_then(|p| p.as_object())
        {
            for (param_name, _) in props {
                let lower = param_name.to_lowercase();
                for &kw in DANGEROUS_PARAM_KEYWORDS {
                    if lower.contains(kw) {
                        findings.push(ManifestFinding {
                            tool_name: tool_name.clone(),
                            parameter_name: param_name.clone(),
                            matched_keyword: kw.to_string(),
                            severity: crate::types::finding::Severity::High,
                        });
                        break;
                    }
                }
            }
        }
        // Check description for suspicious instruction patterns
        if let Some(desc) = tool.get("description").and_then(|d| d.as_str()) {
            let lower = desc.to_lowercase();
            for &pattern in SUSPICIOUS_DESC_PATTERNS {
                if lower.contains(pattern) {
                    findings.push(ManifestFinding {
                        tool_name: tool_name.clone(),
                        parameter_name: "description".to_string(),
                        matched_keyword: pattern.to_string(),
                        severity: crate::types::finding::Severity::Critical,
                    });
                    break;
                }
            }
        }
    }
    ManifestAnalysisResult { findings, tools_analyzed: tools.len() }
}
```

**MCP Handler integration** (Step 4 in MCP lifecycle): When method = `tools/list`, run
`analyze_tools_list()` on the response. If findings > 0: add `X-Revoc-Manifest-Warnings: {count}`.

### D11 — Emergency Kill-Switch (revoc-proxy/src/kill_switch/)

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use dashmap::DashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct KillSwitchEntry { pub activated_by: String, pub activated_at: DateTime<Utc>,
    pub reason: String, pub scope: KillSwitchScope }

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="snake_case")]
pub enum KillSwitchScope { Global, Org(String), Caller(String) }

pub struct KillSwitchState {
    pub global: AtomicBool,
    pub by_org: DashMap<String, KillSwitchEntry>,
    pub by_caller: DashMap<String, KillSwitchEntry>,
}
impl KillSwitchState {
    pub fn new() -> Self { Self { global: AtomicBool::new(false), by_org: DashMap::new(), by_caller: DashMap::new() } }
    pub fn is_active_for(&self, caller: &crate::types::decision::CallerContext) -> bool {
        if self.global.load(Ordering::Relaxed) { return true; }
        if self.by_org.contains_key(&caller.org_id) { return true; }
        self.by_caller.contains_key(&caller.caller_id)
    }
    pub fn activate(&self, entry: KillSwitchEntry) {
        match &entry.scope {
            KillSwitchScope::Global => self.global.store(true, Ordering::SeqCst),
            KillSwitchScope::Org(id) => { self.by_org.insert(id.clone(), entry); }
            KillSwitchScope::Caller(id) => { self.by_caller.insert(id.clone(), entry); }
        }
    }
    pub fn deactivate(&self, scope: &KillSwitchScope) {
        match scope {
            KillSwitchScope::Global => self.global.store(false, Ordering::SeqCst),
            KillSwitchScope::Org(id) => { self.by_org.remove(id); }
            KillSwitchScope::Caller(id) => { self.by_caller.remove(id); }
        }
    }
}
// Endpoints (internal port 8081 ONLY — never on port 8080):
// POST /internal/emergency/kill-switch/activate
// POST /internal/emergency/kill-switch/deactivate
// GET  /internal/emergency/kill-switch/status
// /health, /ready, /startup, /metrics BYPASS kill-switch (always accessible)
```

**Redis propagation**: On activate, publish JSON to `revoc:kill_switch` channel.
Background task subscribes and updates local state within ~50ms.

**Durability and propagation.**
- **The document.** State is one `KillSwitchDoc { version, updated_at, entries }`, stored as `{"doc": "<json>", "sig": "<hex HMAC-SHA256>"}`.
- **The store.** Redis (`<channel>:state`, shared) when `REDIS_URL` is set, else the local SQLite table `kill_switch_state`.
- **Writes.** Compare-and-swap on `version`, using an atomic Lua script in Redis that also publishes the new document on `<channel>`.
- **Startup.** State is loaded before traffic is served.
- **Reconcile.** Every `reconcile_interval_ms` (2000) each instance re-reads the store and adopts a strictly newer version only, so old documents can't be replayed. Pub/sub delivers changes in ~50 ms.
- **Signing.** A signature that fails verification means the document is ignored. Redis requires `kill_switch.signing_key_env` (≥ 32 bytes).
- **Activate.** Applied locally first. A failed write is reported as `durable: false` and retried on each reconcile.
- **Deactivate.** Persisted first: a failed write returns 503 and lifts nothing.
- **Store unavailable.** `on_redis_unavailable = "local_only"` keeps the last state (`/ready` reports degraded). `"fail_closed"` blocks all traffic, and `/ready` returns 503, once the store has been unreadable for three intervals, or immediately if it was never read.

**Admin credentials.**
- Every kill-switch change requires the admin key (`X-Admin-Key`): on the internal API, and on the dashboard regardless of dashboard auth mode.
- Client API keys never grant it.
- Startup fails if the admin key is also a client API key.


### D12 — Policy Conflict Resolution (revoc-policy/src/conflict.rs)

```rust
pub const SECURITY_RULE_IDS: &[&str] = &[
    "sec_ddl_mutation_v1","sec_delete_no_where_v1","sec_ssrf_v1","sec_path_traversal_v1",
    "sec_prompt_injection_v1","sec_sysextract_v1","sec_encoded_evasion_v1",
    "secret_block_v1","session_data_exfil_v1","mcp_result_pii_v1",
];

pub fn is_security_rule(rule_id: &str) -> bool { SECURITY_RULE_IDS.contains(&rule_id) }

/// Tier precedence: Emergency=4 > Security=3 > Profile=2 > Custom=1 > Default=0
/// Within tier: Block > Redact > Audit > Allow
/// CRITICAL: If ANY Security-tier block fires, return it regardless of other rules.
pub fn resolve(violations: &[PolicyDecision]) -> PolicyDecision {
    // Step 1: Security-tier block always wins
    for v in violations {
        if v.tier >= PolicyRuleTier::Security && v.action.is_blocking() { return v.clone(); }
    }
    // Step 2: Max by tier, then action priority
    violations.iter()
        .max_by(|a,b| a.tier.cmp(&b.tier).then(action_priority(&a.action).cmp(&action_priority(&b.action))))
        .cloned()
        .unwrap_or_else(PolicyDecision::allow)
}
fn action_priority(a: &Action) -> u8 { match a { Action::Allow=>0,Action::Audit=>1,Action::Redact=>2,Action::Block=>3 } }
```

---

## SECTION 10 — DETECTION PIPELINE FLOW

Every text field processed in this exact sequence:

```
Raw text
  ↓ [1] normalization::normalize()       NFKC + zero-width + RTLO + control chars
  ↓ [2] encoding::prepare_scan_targets() base64 decode attempt + URL decode attempt
  ↓ [3] regex_detector::detect()         PII + secrets + security + financial patterns
  ↓ [4] onnx_detector::detect()          NER if onnx_enabled=true (optional)
  ↓ [5] http_plugin::detect()            community plugins if configured
  ↓ [6] deduplication::deduplicate()     merge overlapping, keep higher confidence
  ↓
Vec<Finding>  (findings carry was_normalized and was_encoded flags)
```

---

## SECTION 11 — HANDLER LIFECYCLES

### LLM Handler — 22 steps

```
Step  0: KILL-SWITCH CHECK — if active: 503 RevocErrorResponse::kill_switch_active
Step  1: DEPTH CHECK — check_depth(governance_depth)? — if exceeded: 503 depth_exceeded
Step  2: Read body bytes (413 if > max_request_body_bytes)
Step  3: Parse ChatCompletionRequest (400 on failure)
Step  4: Extract CallerContext + request_id + governance_depth from extensions
Step  5: Check enforcement_mode (shadow = observe only)
Step  6: Start OTel child span (W3C traceparent propagation)
Step  7: Run detection engine with 8s timeout → Vec<Finding>
Step  8: Build PolicyInput (includes governance_depth, session_state)
Step  9: Evaluate policy, apply conflict::resolve()
Step 10: Shadow mode override: effective_action = Audit
Step 11: Route on effective_action:
         BLOCK  → 403 RevocErrorResponse::governance_block (with dashboard_url + documentation_url)
         REDACT → redact body, log entity types ONLY (never values)
         ALLOW/AUDIT → use original body
Step 12: Validate upstream URL (SSRF protection — validate against allowlist)
Step 13: Build upstream request + format translation (OpenAI→Anthropic if needed)
Step 14: Set X-Revoc-Depth: {depth+1} on upstream request
Step 15: If stream=true: stream governor (§12) — per-choice hold-back, in-stream redaction, tool calls held until governed
         If stream=false: buffer full response, output governance
Step 16: Extract TokenUsage. Compute estimated_cost_usd.
Step 17: Update session state in Redis/memory.
Step 18: If upstream 4xx/5xx → forward verbatim + add only X-Revoc-Trace-ID header
Step 19: Set ALL response headers (sanitize every value: strip \r\n\0):
         X-Revoc-Trace-ID, X-Revoc-Decision, X-Revoc-Dashboard (NON-NEGOTIABLE),
         X-Revoc-Rules, X-Revoc-Timing (NON-NEGOTIABLE), X-Revoc-Request-ID, X-Revoc-Depth
Step 20: Write AuditEvent (async, batched)
Step 21: Publish GovernanceEvent to dashboard SSE bus
Step 22: Record metrics, close OTel span
```

### MCP Handler — 12 steps

```
Step  0: KILL-SWITCH CHECK (same as LLM Step 0)
Step  1: DEPTH CHECK (same as LLM Step 1)
Step  2: Read body → parse McpRawRequest
Step  3: initialize/ping → forward directly, start session, return
Step  4: tools/list or resources/list:
           Forward to MCP server
           Run manifest_analyzer::analyze_tools_list(response_bytes)
           If findings > 0: set X-Revoc-Manifest-Warnings: {count} header
           Return (optionally remove dangerous tools if auto_disable=true)
Step  5: sampling/createMessage → route to LLM handler (depth+1)
Step  6: tools/call / resources/read: validate server in trusted registry
Step  7: Run detection engine on tool arguments
Step  8: Evaluate policy (conflict::resolve())
Step  9: BLOCK: return McpBlockResponse (JSON-RPC error -32603, HTTP 200 body)
           Set X-Revoc-Block: true, X-Revoc-Dashboard, X-Revoc-Trace-ID
           UPSTREAM MCP SERVER MUST NEVER RECEIVE A BLOCKED REQUEST
Step 10: ALLOW: forward to upstream MCP server. Set X-Revoc-Depth on upstream.
Step 11: Receive tool result. Run detection on result (bidirectional governance).
           Redact PII before returning to AI client.
Step 12: Write audit, publish SSE, record metrics, close span
```

---

## SECTION 12 — STREAMING ARCHITECTURE

### SSE parser (revoc-pipeline/src/sse.rs)

`SseParser` is incremental: it keeps the unterminated tail between chunks, so an
event split across TCP reads, or several events in one read, are each seen once
and whole. Accepts `\n`, `\r\n` and `\r` line endings, multi-line `data:`,
comments and an unterminated final event. A single event larger than
`server.max_response_body_bytes` is an error. Fuzzed by `fuzz_sse_parser`
(chunked parse == whole-body parse).

### Stream governor (streaming/governor.rs)

Sits between the parser and the client and decides, per event, what may be sent.

```text
Text   — OpenAI choices[i].delta.content; Anthropic text_delta / thinking_delta
         One channel per choice / content block. Text is NFKC-normalised on
         arrival (D8) and appended to the channel's pending buffer.
         The last stream.hold_back_chars (default 128) characters are held.
         When more than that is pending, scan (released tail + pending):
           detection → policy (RequestType::LlmResponse)
           Block            → stop the stream (below)
           Redact / High    → rewrite the spans in pending (strategy_for);
                              a span crossing the release point moves it forward
           findings in encoded text that need redaction → stop (cannot rewrite)
         Release pending minus the tail, as a copy of the last text event with
         the text replaced. At finish_reason / content_block_stop /
         message_delta / [DONE] / EOF, scan and release everything.
         Any pattern up to hold_back_chars long is complete before any of its
         characters is released.
Tools  — OpenAI delta.tool_calls; Anthropic tool_use blocks + input_json_delta
         Every tool event is held. Before the choice's finish_reason (or
         message_delta) is forwarded, the assembled calls are governed as
         RequestType::McpToolCall; anything but allow stops the stream.
         Arguments that are not valid JSON are governed as a raw string.
Other  — role-only deltas, usage chunks, message_start, ping: forwarded.
         Unrecognised JSON events are scanned whole and forwarded only if
         nothing needs blocking or redaction. Non-JSON data stops the stream
         when fail-closed.
Stop   — OpenAI: synthetic finish_reason=content_filter chunk, then [DONE].
         Anthropic: `event: error` with type revoc_governance_block.
         Nothing held is released.
Shadow — nothing is blocked or rewritten; findings and the action that would
         have been taken are recorded.
Errors — detection or policy failure stops the stream unless fail_open.
         Upstream read error: held text is released after a final scan and no
         [DONE] is sent, so the client sees the truncation.
         Total bytes over server.max_response_body_bytes: stream stopped.
```

`stream.buffer_output = true` reads the whole body (within
`max_response_body_bytes`), runs the same governor with unlimited hold-back,
and only then responds: a block becomes HTTP 403 `RevocErrorResponse`, a
redaction a rewritten SSE body.

### Audit

A streamed request writes two audit events with the same `trace_id`: the
request side when the stream starts (as for non-streamed requests) and the
response side (`request_type = LlmResponse`) when it ends, carrying the
findings, matched rules, `decision` / `effective_action` (`audit` for shadow),
token usage from the stream when the provider sends it, and
`stream_truncated` in `violated_rules` when the stream ended early.

---

## SECTION 13 — COMPLETE CONFIG SCHEMA

```toml
[server]
host = "0.0.0.0"
port = 8080
dashboard_port = 3000       # 0 = dashboard disabled
environment = "production"
max_request_body_bytes = 10485760    # 10MB
max_response_body_bytes = 52428800   # 50MB
shutdown_timeout_secs = 120
http2_enabled = true
dashboard_base_url = "http://localhost:3000"

[upstream]
timeout_ms = 120000
connect_timeout_ms = 5000
max_idle_connections_per_host = 100
mock_mode = false
mock_response = "Mock response. Governance pipeline ran."

[[upstream.providers]]
name = "openai"
base_url = "https://api.openai.com"
api_key_env = "OPENAI_API_KEY"
api_key_file = ""
format = "openai"
default = true

[[upstream.providers]]
name = "anthropic"
base_url = "https://api.anthropic.com"
api_key_env = "ANTHROPIC_API_KEY"
format = "anthropic"
default = false

[[upstream.providers]]
name = "azure"
base_url = ""
api_key_env = "AZURE_OPENAI_API_KEY"
format = "azure"
default = false

[policy]
engine = "native"               # native | sidecar | wasm
enforcement_mode = "enforce"    # enforce | shadow
opa_url = "http://localhost:8181"
opa_timeout_ms = 2000
wasm_bundle_path = ""
fail_open = false               # NEVER set to true in production
decision_cache_ttl_secs = 60
decision_cache_max_entries = 10000
conflict_resolution = "tier_based"  # tier_based | strict_deny

[governance]
max_depth = 10
depth_exceeded_action = "block"

[kill_switch]
enabled = true
redis_channel = "revoc:kill_switch"
on_redis_unavailable = "local_only"   # local_only | fail_closed
signing_key_env = "REVOC_KILL_SWITCH_KEY"
reconcile_interval_ms = 2000

[detection]
normalize_before_scan = true       # MUST default true — evasion defense
regex_enabled = true
onnx_enabled = false
onnx_model_path = "models/bert-base-ner.onnx"
onnx_tokenizer_path = "models/bert-base-ner-tokenizer.json"
presidio_enabled = false
presidio_url = ""
decode_base64_args = true
decode_url_encoded_args = true

[stream]
buffer_output = false           # true = full buffer (HIPAA/PCI compliance mode)
hold_back_chars = 128           # chars held per choice until scanned

[mcp]
analyze_tool_manifests = true   # MUST default true — schema poisoning defense
auto_disable_dangerous_tools = false
dangerous_tool_action = "audit"
# trusted_servers = [{ id="", url="", tls_verify=true }]

[session]
enabled = true
ttl_secs = 3600
max_rows_before_alert = 500

[storage]
backend = "sqlite"              # sqlite | postgres
sqlite_path = "revoc-audit.db"
postgres_url_env = "DATABASE_URL"
pool_size = 20
migrations_auto_run = true
audit_write_batch_size = 100
audit_write_interval_ms = 100
audit_retention_days = 90

[cache]
backend = "memory"              # memory | redis
redis_url_env = "REDIS_URL"

[telemetry]
otlp_endpoint = ""              # empty = OTel disabled
service_name = "revoc-proxy"
service_version = "1.0.0"
sample_rate = 1.0
prometheus_port = 9090
log_level = "info"
log_format = "json"             # json | pretty

[auth]
mode = "apikey"                 # apikey | jwt | none (none: dev only)
jwt_secret_env = "REVOC_JWT_SECRET"
api_keys_env = "REVOC_API_KEYS"
api_keys_file = ""              # preferred over env in production

[dashboard]
auth_mode = "shared"            # shared | none
max_sse_connections = 100

[webhooks]
enabled = false
# [[webhooks.endpoints]]
# url = ""
# events = ["block", "quota_exceeded"]
# min_severity = "high"
# cooldown_minutes = 5
```

---

## SECTION 14 — 30 DEFAULT RULES

All rules are active from first run with no configuration.

### PII Rules (action: redact or remove)

| rule_id | entity | action |
|---|---|---|
| pii_ssn_v1 | US_SSN | Remove |
| pii_credit_card_v1 | CREDIT_CARD (Luhn validated) | Remove |
| pii_iban_v1 | IBAN_CODE (checksum validated) | Remove |
| pii_bank_account_v1 | BANK_ACCOUNT | Remove |
| pii_passport_v1 | US_PASSPORT | Remove |
| pii_driver_license_v1 | US_DRIVER_LICENSE | Mask |
| pii_email_v1 | EMAIL_ADDRESS | Mask |
| pii_phone_v1 | PHONE_NUMBER | Mask |
| pii_ip_address_v1 | IP_ADDRESS_V4/V6 | Mask |
| pii_mrn_v1 | MEDICAL_RECORD_NUMBER | Remove |
| pii_dob_v1 | DATE_OF_BIRTH | Mask |

### Secret Rules (action: block/remove)

| rule_id | entity | action |
|---|---|---|
| secret_block_v1 (umbrella) | Any secret finding | Block |
| secret_aws_key_v1 | AWS_ACCESS_KEY | Remove from output |
| secret_aws_secret_v1 | AWS_SECRET_KEY | Remove |
| secret_github_token_v1 | GITHUB_TOKEN | Remove |
| secret_openai_key_v1 | OPENAI_KEY | Remove |
| secret_anthropic_key_v1 | ANTHROPIC_KEY | Remove |
| secret_generic_api_key_v1 | GENERIC_API_KEY | Remove |
| secret_private_key_v1 | PRIVATE_KEY | Remove |
| secret_jwt_v1 | JWT_TOKEN in content | Hash |
| secret_password_json_v1 | PASSWORD_IN_JSON | Remove |

### Security Rules (action: block — TIER 3, cannot be overridden)

| rule_id | threat | action |
|---|---|---|
| sec_prompt_injection_v1 | Prompt injection phrases | Block |
| sec_sysextract_v1 | System prompt extraction | Block |
| sec_ddl_mutation_v1 | DROP/TRUNCATE/ALTER TABLE | Block |
| sec_delete_no_where_v1 | DELETE without WHERE | Block |
| sec_ssrf_v1 | Internal IP in HTTP args | Block |
| sec_path_traversal_v1 | ../ in file args | Block |
| sec_encoded_evasion_v1 | Above patterns in encoded content | Block |
| sec_mass_delete_v1 | Bulk delete operations | Block |
| session_data_exfil_v1 | Session exfil pattern | Block |
| mcp_result_pii_v1 | PII in MCP tool result | Redact |

### Operational Rules

| rule_id | condition | action |
|---|---|---|
| mcp_tool_acl_v1 | Tool not in org ACL | Block |
| token_quota_v1 | Token budget exceeded | Block |

---

## SECTION 15 — DATABASE SCHEMA (ANSI SQL)

```sql
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policy_bundles (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production', version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft', yaml_content TEXT NOT NULL,
    rego_content TEXT, compiled_at TEXT, activated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')), created_by TEXT NOT NULL,
    UNIQUE(org_id, name, version, environment)
);

CREATE TABLE IF NOT EXISTS policy_audit_log (
    id TEXT PRIMARY KEY, policy_bundle_id TEXT NOT NULL,
    action TEXT NOT NULL, actor TEXT NOT NULL,
    yaml_hash_before TEXT, yaml_hash_after TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY, org_id TEXT, request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, caller_id TEXT, caller_team TEXT,
    environment TEXT, decision TEXT NOT NULL, effective_action TEXT NOT NULL,
    enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
    violated_rules TEXT, finding_types TEXT, model TEXT, provider TEXT,
    tool_name TEXT, request_type TEXT, governance_depth INTEGER DEFAULT 0,
    prompt_tokens INTEGER, completion_tokens INTEGER,
    estimated_cost_usd REAL, duration_ms REAL,
    detection_ms REAL, policy_ms REAL,
    was_normalized INTEGER DEFAULT 0, manifest_warnings INTEGER DEFAULT 0,
    trace_id TEXT, policy_engine TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ae_org_time ON audit_events(org_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_decision ON audit_events(decision, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_trace    ON audit_events(trace_id);

CREATE TABLE IF NOT EXISTS kill_switch_log (
    id TEXT PRIMARY KEY, scope TEXT NOT NULL, scope_value TEXT,
    action TEXT NOT NULL, activated_by TEXT NOT NULL, reason TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE, hashed_pw TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer', is_superuser INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL,
    name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, caller_id TEXT NOT NULL,
    policy_profile TEXT, expires_at TEXT, last_used TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## SECTION 16 — RESPONSE HEADERS

Every response from every handler sets ALL of these:

| Header | Value | Mandatory |
|---|---|---|
| X-Revoc-Trace-ID | UUID v7 | Always |
| X-Revoc-Decision | allow/redact/block/audit/shadow-block | Always |
| X-Revoc-Dashboard | {base_url}/traces/{trace_id} | **NON-NEGOTIABLE** |
| X-Revoc-Timing | detection=Xms,policy=Xms,redaction=Xms,upstream=Xms,total=Xms | **NON-NEGOTIABLE** |
| X-Revoc-Request-ID | UUID v7 | Always |
| X-Revoc-Depth | governance_depth value | Always |
| X-Revoc-Rules | comma-separated rule IDs | When decision != allow |
| X-Revoc-Block | true | MCP blocks only |
| X-Revoc-Manifest-Warnings | count | tools/list with findings |
| X-Upstream-Request-ID | upstream provider's ID | When upstream provides it |

All header values are `sanitize_header_value()` filtered (strips `\r`, `\n`, `\0`).

---

## SECTION 17 — SECURITY PROPERTIES

```rust
// 1. Header injection prevention — on EVERY value placed in response headers
fn sanitize_header_value(v: &str) -> String {
    v.chars().filter(|&c| c!='\r' && c!='\n' && c!='\0').collect()
}

// 2. Constant-time API key comparison — prevents timing attacks
use subtle::ConstantTimeEq;
fn validate_api_key(provided: &[u8], stored: &[u8]) -> bool { provided.ct_eq(stored).into() }

// 3. SSRF protection — upstream URL from config allowlist ONLY, never from request headers
fn validate_upstream_url(url: &url::Url, providers: &[ProviderConfig]) -> Result<(), RevocError> {
    let origin = url.origin().ascii_serialization();
    if !providers.iter().any(|p| p.base_url.starts_with(&origin)) {
        return Err(RevocError::Security("SSRF: URL not in allowed providers".into()));
    }
    Ok(())
}

// 4. Upstream error transparency — always forward verbatim
fn should_forward_verbatim(status: u16) -> bool { status >= 400 }
// When true: copy upstream response as-is; only add X-Revoc-Trace-ID header
// NEVER wrap in RevocErrorResponse — that type is for REVOC errors only

// 5. Audit log privacy — finding spans store position only, never value
// TextSpan.value is always None; span.value has #[serde(skip)]
```

---

## SECTION 18 — CLI SUBCOMMANDS

```
revoc-proxy serve [--config PATH]
revoc-proxy migrate [--config PATH]
revoc-proxy validate-config [--config PATH]
revoc-proxy check-policies [--dir PATH]
revoc-proxy generate-key [--label NAME]
revoc-proxy version
revoc-proxy benchmark [--quick]
revoc-proxy emergency activate --scope global|org|caller --reason TEXT --admin-key KEY [--target ID]
revoc-proxy emergency deactivate --scope global|org|caller --admin-key KEY [--target ID]
revoc-proxy emergency status
```

---

## SECTION 19 — PERFORMANCE TARGETS

| Benchmark | Target | How measured |
|---|---|---|
| P95 proxy overhead (proxy-only, no upstream) | < 10ms | criterion |
| Regex detection (4KB LLM body, no PII) | > 100K req/s | criterion throughput |
| Regex detection (4KB, 3 PII findings) | > 50K req/s | criterion throughput |
| Full pipeline (regex + policy + redaction) | > 40K req/s | criterion throughput |
| Policy cache hit | > 1M ops/s | criterion |
| Native policy engine (empty findings) | > 500K/s | criterion |
| Normalization overhead | < 0.5ms added | criterion |
| Manifest analysis (10 tools) | < 1ms | criterion |
| MCP arg parse + detect | > 200K req/s | criterion |

---

## SECTION 20 — ADMIN API PYTHON DEPENDENCIES

```toml
fastapi==0.162.0
uvicorn[standard]==0.54.0
pydantic==2.9.2
pydantic-settings==2.6.1
sqlalchemy[asyncio]==2.0.36
alembic==1.14.0
aiosqlite==0.20.0
asyncpg==0.30.0
redis[hiredis]==5.2.0
httpx==0.28.1
pyjwt[crypto]==2.15.1
passlib[bcrypt]==1.7.4
opentelemetry-sdk==1.45.2
opentelemetry-exporter-otlp==1.45.2
opentelemetry-instrumentation-fastapi==0.66b2
structlog==24.4.0
pyyaml==6.0.2
jsonschema==4.23.0
python-multipart==0.0.33
weasyprint==70.0
```

---

## SECTION 21 — BUILD SEQUENCE (21 PHASES)

```
Phase  1: Workspace scaffold — all root files
Phase  2: revoc-core — types, traits, errors, tests
Phase  3: revoc-config — schema (all fields), loader, validation, tests
Phase  4: revoc-telemetry — tracer, metrics (all counters), attributes, logger
Phase  5: revoc-detector — normalization FIRST, patterns, regex_detector,
           manifest_analyzer, onnx stub, http_plugin, enrichers, all tests
Phase  6: revoc-pipeline — deduplication, orchestrator, tests
Phase  7: revoc-policy — conflict.rs, cache, native engine (30 rules), sidecar, wasm stub
Phase  8: revoc-redaction — strategy, json_mutator, redactor, tests
Phase  9: revoc-dashboard — React SPA (build + commit dist/), Rust handler, SSE, REST
Phase 10: revoc-proxy — kill_switch/, depth.rs, emergency.rs, ALL middleware,
           ALL handlers (kill-switch Step 0 + depth Step 1 in every handler),
           streaming, CLI with emergency commands, Dockerfile
Phase 11: Rego policies — replace stubs with complete content, OPA test files
Phase 12: Admin API core — config, database, security, exceptions, logging
Phase 13: Admin API models + schemas + services
Phase 14: Admin API routers + app + migrations + tests
Phase 15: Python SDK + Node SDK
Phase 16: Docker — single-container + compose + test + observability
Phase 17: Helm chart — all templates, values, NOTES.txt
Phase 18: Integration tests — all 30 rules + normalization + kill-switch + depth + manifest
Phase 19: Benchmarks (criterion) + fuzz tests (4 targets)
Phase 20: MkDocs site + all doc pages + examples
Phase 21: CI/CD + GitHub files + final README
```

---

## SECTION 22 — DEFINITION OF DONE

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo test -p revoc-detector normalization -- --nocapture

cd admin-api && ruff check . && mypy app/ --strict && pytest tests/ --cov-fail-under=85 && cd ..
opa check policies/ --strict
opa test policies/ -v --coverage

# Single-container mode (zero dependencies)
docker build -t revoc-local -f crates/revoc-proxy/Dockerfile .
docker run -d -p 8080:8080 -p 3000:3000 -p 8081:8081 \
  -e REVOC_AUTH__MODE=none -e REVOC_UPSTREAM__MOCK_MODE=true \
  --name revoc-sc revoc-local
sleep 8
curl -s http://localhost:8080/health | jq .
curl -s http://localhost:3000/ | grep -c revoc

# Kill-switch test
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/activate \
  -H "X-Admin-Key: dev-admin-key" -H "Content-Type: application/json" \
  -d '{"scope":"global","reason":"ci-test","activated_by":"ci"}' | jq .
curl -s -X POST http://localhost:8080/v1/chat/completions -d '{}' | jq '.error.code'
# Expected: "REVOC_KILL_SWITCH_ACTIVE"
curl -s http://localhost:8080/health | jq '.status'
# Expected: "ok" (health always bypasses kill-switch)
curl -s -X POST http://localhost:8081/internal/emergency/kill-switch/deactivate \
  -H "X-Admin-Key: dev-admin-key" -d '{"scope":"global"}' | jq .

# Depth limit test
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "X-Revoc-Depth: 10" -d '{"model":"gpt-4o-mini","messages":[]}' | jq '.error.code'
# Expected: "REVOC_GOVERNANCE_DEPTH_EXCEEDED"

# Normalization evasion test
curl -s -X POST http://localhost:8080/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"execute_sql","arguments":{"query":"ＤＲＯＰTableusers"}}}' \
  | jq '.error'
# Expected: governance block

docker rm -f revoc-sc

make up && sleep 25
pytest tests/integration/ -v 2>&1 | tail -20
mkdocs build --strict
helm lint helm/revoc/
make down
echo "✅ REVOC v1.0.0 PRODUCTION READY"
```

---

## SECTION 23 — WHAT NOT TO DO (27 RULES)

1. Never `.unwrap()` or `.expect()` outside `#[cfg(test)]`
2. Never log or store original PII values — only entity type + field + position
3. Never call external HTTP in Tier 1 or Tier 2 detection hot path
4. Never set `fail_open = true` in any committed config
5. Never hardcode API keys, secrets, or environment-specific values
6. ZERO INCOMPLETE CODE — absolute prohibition, no exceptions.
   Banned in ALL files (Rust, Python, TypeScript, Rego, YAML, shell):
   - TODO, FIXME, HACK, XXX comments
   - "implement later", "in Phase N", "simplified in", "stub", "placeholder"
   - Functions returning empty vec![], Ok(()), None, 0, or "" as a permanent value
   - Hardcoded mock/fake values where real computation is required
   - panic!(), unimplemented!(), todo!() macros in non-test code
   - Comments like "// full implementation in Phase N" or "// simplified"
   - Functions that exist but do nothing (no-op when the spec requires behavior)
   - Returning synthetic/fabricated data instead of actually computing it
   VERIFICATION before marking any phase complete:
   - Run cargo grep: grep -rn "TODO\|stub\|placeholder\|simplified\|Phase [0-9]\|unimplemented\|todo!()\|panic!()" src/
7. Never return HTTP 200 for governance blocks on LLM endpoint (use 403)
8. Never wrap upstream 4xx/5xx in RevocErrorResponse — forward verbatim
9. Never forward a blocked MCP request to the upstream tool server
10. Never skip X-Revoc-Dashboard on any response
11. Never skip X-Revoc-Timing on any response
12. Never put X-Revoc-Depth on response to client — only on upstream requests
13. Never skip normalization before regex patterns (Rule D8)
14. Never skip kill-switch check — it is Step 0 in every handler
15. Never allow a custom allow rule to override a Tier 3 security rule
16. Never let governance depth exceed 10 without returning 503 immediately
17. Never let tools/list pass through without manifest analysis
18. Never use `==` for API key comparison — use `subtle::ConstantTimeEq`
19. Never derive upstream URL from request headers (SSRF)
20. Never place `\r\n\0` in response headers
21. Never buffer streaming responses unless `stream.buffer_output=true` is configured
22. Never forward `finish_reason=tool_calls` before governance on accumulated calls
23. Never call home to revoc.io from the proxy process
24. Never rename public crates, packages, headers or env vars outside a major version
25. Never let SQLite audit writes block the request path — use async batch writer
26. Never activate kill-switch without writing to kill_switch_log table
27. Never skip X-Revoc-Depth on outgoing upstream requests
