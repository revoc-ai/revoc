//! Detection finding types: [`Finding`], [`FindingType`], [`PiiEntityType`],
//! [`Severity`], [`DetectionTier`], and [`TextSpan`].
//!
//! **Privacy invariant**: [`TextSpan::value`] is annotated `#[serde(skip)]`
//! and is therefore **never** included in serialized output. Audit storage
//! records only entity type, field name, and byte position — never the
//! matched text (SPEC.md §9, §17, §23 Rule 2).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// High-level category of a governance finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingType {
    /// Personally identifiable information detected.
    Pii,
    /// Credential or secret key detected.
    SecretExposure,
    /// Destructive DDL (DROP/TRUNCATE/ALTER) detected in a SQL argument.
    DdlMutation,
    /// Prompt injection attempt detected.
    PromptInjection,
    /// System-prompt extraction attempt detected.
    SystemPromptExtraction,
    /// Server-Side Request Forgery attempt detected (internal IP in HTTP arg).
    SsrfAttempt,
    /// Path traversal sequence (`../`) detected in a file argument.
    PathTraversal,
    /// Operator-defined keyword match.
    KeywordMatch,
    /// MCP tool call blocked by ACL or policy.
    McpToolBlock,
    /// Token or request quota exceeded.
    QuotaExceeded,
    /// Session-level anomaly (data exfiltration pattern).
    SessionAnomaly,
    /// Tool manifest (tools/list) contained dangerous parameter or description.
    ToolManifestRisk,
    /// Custom finding type defined by an operator detection plugin.
    #[serde(untagged)]
    Custom(String),
}

/// Specific PII entity category identified by the detection engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiEntityType {
    /// US Social Security Number.
    UsSsn,
    /// Email address.
    EmailAddress,
    /// Phone number (US and international formats).
    PhoneNumber,
    /// Credit/debit card number (Luhn validated).
    CreditCard,
    /// IPv4 address.
    IpAddressV4,
    /// IPv6 address.
    IpAddressV6,
    /// US passport number.
    UsPassport,
    /// US driver's license number.
    UsDriverLicense,
    /// IBAN bank account code (mod-97 validated).
    IbanCode,
    /// ABA routing number (checksum validated).
    RoutingNumber,
    /// Bank account number (context-sensitive).
    BankAccount,
    /// SWIFT/BIC bank identifier code.
    SwiftBic,
    /// Date of birth (detected near contextual keywords).
    DateOfBirth,
    /// Medical record number (MRN).
    MedicalRecordNumber,
    /// National Provider Identifier (NPI).
    NpiNumber,
    /// DEA (Drug Enforcement Administration) number.
    DeaNumber,
    /// AWS access key ID.
    AwsAccessKey,
    /// AWS secret access key.
    AwsSecretKey,
    /// GitHub personal access token.
    GithubToken,
    /// `OpenAI` API key.
    OpenaiKey,
    /// Anthropic API key.
    AnthropicKey,
    /// Generic API key (heuristic match).
    GenericApiKey,
    /// PEM-encoded private key.
    PrivateKey,
    /// JSON Web Token.
    JwtToken,
    /// Password value embedded in a JSON object.
    PasswordInJson,
    /// Custom entity type defined by an operator enricher.
    #[serde(untagged)]
    Custom(String),
}

impl std::fmt::Display for PiiEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UsSsn               => "US_SSN",
            Self::EmailAddress        => "EMAIL_ADDRESS",
            Self::PhoneNumber         => "PHONE_NUMBER",
            Self::CreditCard          => "CREDIT_CARD",
            Self::IpAddressV4         => "IP_ADDRESS_V4",
            Self::IpAddressV6         => "IP_ADDRESS_V6",
            Self::UsPassport          => "US_PASSPORT",
            Self::UsDriverLicense     => "US_DRIVER_LICENSE",
            Self::IbanCode            => "IBAN_CODE",
            Self::RoutingNumber       => "ROUTING_NUMBER",
            Self::BankAccount         => "BANK_ACCOUNT",
            Self::SwiftBic            => "SWIFT_BIC",
            Self::DateOfBirth         => "DATE_OF_BIRTH",
            Self::MedicalRecordNumber => "MEDICAL_RECORD_NUMBER",
            Self::NpiNumber           => "NPI_NUMBER",
            Self::DeaNumber           => "DEA_NUMBER",
            Self::AwsAccessKey        => "AWS_ACCESS_KEY",
            Self::AwsSecretKey        => "AWS_SECRET_KEY",
            Self::GithubToken         => "GITHUB_TOKEN",
            Self::OpenaiKey           => "OPENAI_KEY",
            Self::AnthropicKey        => "ANTHROPIC_KEY",
            Self::GenericApiKey       => "GENERIC_API_KEY",
            Self::PrivateKey          => "PRIVATE_KEY",
            Self::JwtToken            => "JWT_TOKEN",
            Self::PasswordInJson      => "PASSWORD_IN_JSON",
            Self::Custom(s)           => s,
        };
        write!(f, "{s}")
    }
}

/// Finding severity, ordered from least to most severe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Informational — no action required.
    Info,
    /// Low severity — log and observe.
    Low,
    /// Medium severity — consider redaction or rate limiting.
    Medium,
    /// High severity — strong governance action recommended.
    High,
    /// Critical severity — block immediately.
    Critical,
}

/// Which tier of the detection pipeline produced this finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DetectionTier {
    /// Rust regex engine (fastest, lowest recall for unstructured text).
    Regex,
    /// ONNX NER model (higher recall, higher latency).
    Onnx,
    /// External HTTP detection plugin.
    HttpPlugin,
    /// Presidio or Azure enricher.
    Enricher,
    /// MCP tool call inspector.
    McpInspector,
    /// Session-level anomaly analysis.
    SessionAnalysis,
    /// Tool manifest (tools/list) analysis.
    ManifestAnalysis,
}

/// Byte-offset span of a matched entity within a field value.
///
/// **Privacy**: `value` carries the original matched text in memory during
/// processing but is annotated `#[serde(skip)]` so it is **never** serialized
/// to JSON, written to audit storage, or included in log output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSpan {
    /// Start byte offset (inclusive) within the field value.
    pub start: usize,
    /// End byte offset (exclusive) within the field value.
    pub end: usize,
    /// JSON field path where the entity was found (e.g. `"messages[1].content"`).
    pub field: String,
    /// Original matched text — **never serialized** (SPEC.md §17).
    #[serde(skip)]
    pub value: Option<String>,
}

/// A single governance finding produced by the detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding (UUID v7).
    pub id: Uuid,
    /// Category of the finding.
    pub finding_type: FindingType,
    /// Severity level.
    pub severity: Severity,
    /// Detection tier that produced this finding.
    pub detection_tier: DetectionTier,
    /// Position of the matched entity within the request/response body.
    pub span: Option<TextSpan>,
    /// Detection confidence in the range [0.0, 1.0].
    pub confidence: f64,
    /// Specific PII entity type, if applicable.
    pub pii_entity: Option<PiiEntityType>,
    /// Additional metadata from the detector (e.g. checksum result, model score).
    pub metadata: HashMap<String, serde_json::Value>,
    /// Wall-clock time when the finding was produced.
    pub detected_at: DateTime<Utc>,
    /// Whether redaction was applied to the matched span.
    pub redaction_applied: bool,
    /// Whether the entity was found in base64- or URL-decoded content.
    pub was_encoded: bool,
    /// Whether the entity was found after Unicode normalization changed the text.
    pub was_normalized: bool,
}

impl Finding {
    /// Construct a new finding with default values for optional fields.
    pub fn new(t: FindingType, s: Severity, tier: DetectionTier) -> Self {
        Self {
            id: Uuid::now_v7(),
            finding_type: t,
            severity: s,
            detection_tier: tier,
            span: None,
            confidence: 1.0,
            pii_entity: None,
            metadata: HashMap::new(),
            detected_at: Utc::now(),
            redaction_applied: false,
            was_encoded: false,
            was_normalized: false,
        }
    }

    /// Attach a [`TextSpan`] indicating where in the body the entity was found.
    #[must_use]
    pub fn with_span(mut self, span: TextSpan) -> Self {
        self.span = Some(span);
        self
    }

    /// Override the default confidence score of `1.0`.
    #[must_use]
    pub fn with_confidence(mut self, c: f64) -> Self {
        self.confidence = c;
        self
    }

    /// Set the specific PII entity type.
    #[must_use]
    pub fn with_pii(mut self, e: PiiEntityType) -> Self {
        self.pii_entity = Some(e);
        self
    }

    /// Returns `true` if the severity is [`Severity::High`] or [`Severity::Critical`].
    pub fn is_high_severity(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}
