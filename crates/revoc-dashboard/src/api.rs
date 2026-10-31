//! Dashboard REST API handlers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    AnalyticsResult, AnalyticsWindow, AuditEvent, AuditStore, EventFilter, KillSwitchControl,
};

// ── Shared app state ──────────────────────────────────────────────────────────

/// Dashboard application state injected into all handlers.
#[derive(Clone)]
pub struct DashboardState {
    /// Audit event store (`SQLite` or Postgres backend).
    pub store: std::sync::Arc<dyn AuditStore>,
    /// Adapter over the proxy's real emergency kill-switch state (SPEC.md §9 D11).
    pub kill_switch: std::sync::Arc<dyn KillSwitchControl>,
}

// ── Request listing ───────────────────────────────────────────────────────────

/// Query parameters for listing audit events.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Filter by effective action (allow/redact/block/audit).
    decision:  Option<String>,
    /// Filter by caller ID.
    caller_id: Option<String>,
    /// Filter by a violated rule ID.
    rule_id:   Option<String>,
    #[allow(dead_code)]
    /// Filter to events at or after this ISO 8601 timestamp.
    start_time: Option<String>,
    #[allow(dead_code)]
    /// Filter to events at or before this ISO 8601 timestamp.
    end_time:   Option<String>,
    /// Look up by exact trace ID.
    trace_id:   Option<String>,
    /// Maximum number of rows to return (default 25).
    #[serde(default = "default_limit")]
    limit:  usize,
    /// Rows to skip for pagination.
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize { 25 }

/// Paginated list of audit events.
#[derive(Serialize)]
pub struct PaginatedEvents {
    /// Events in this page.
    events: Vec<AuditEvent>,
    /// Total matching events across all pages.
    total:  u64,
    /// Page size used for this query.
    limit:  usize,
    /// Offset used for this query.
    offset: usize,
}

/// `GET /dashboard/api/requests`
///
/// # Errors
/// Returns `StatusCode::INTERNAL_SERVER_ERROR` if the store query fails.
pub async fn list_requests(
    State(state): State<DashboardState>,
    Query(q): Query<ListQuery>,
) -> Result<Json<PaginatedEvents>, StatusCode> {
    let filter = EventFilter {
        decision:  q.decision,
        caller_id: q.caller_id,
        rule_id:   q.rule_id,
        trace_id:  q.trace_id,
        limit:     Some(q.limit),
        offset:    Some(q.offset),
        ..Default::default()
    };

    state
        .store
        .list_events(filter)
        .await
        .map(|(events, total)| {
            Json(PaginatedEvents { events, total, limit: q.limit, offset: q.offset })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// `GET /dashboard/api/requests/:trace_id`
///
/// # Errors
/// Returns `StatusCode::INTERNAL_SERVER_ERROR` if the store query fails.
pub async fn get_request_detail(
    State(state): State<DashboardState>,
    Path(trace_id): Path<String>,
) -> Result<Json<AuditEvent>, StatusCode> {
    state
        .store
        .get_event_by_trace(&trace_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

// ── Analytics ─────────────────────────────────────────────────────────────────

/// Query parameters for analytics and cost endpoints.
#[derive(Deserialize)]
pub struct WindowQuery {
    /// Time window: `"1h"`, `"24h"` (default), `"7d"`, `"30d"`.
    #[serde(default = "default_window")]
    window: String,
}

fn default_window() -> String { "24h".into() }

/// `GET /dashboard/api/analytics`
///
/// # Errors
/// Returns `StatusCode::INTERNAL_SERVER_ERROR` if the store query fails.
pub async fn get_analytics(
    State(state): State<DashboardState>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<AnalyticsResult>, StatusCode> {
    let window = AnalyticsWindow::parse_window(&q.window);
    state
        .store
        .analytics(window)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// `GET /dashboard/api/costs`
///
/// # Errors
/// Returns `StatusCode::INTERNAL_SERVER_ERROR` if the store query fails.
pub async fn get_costs(
    State(state): State<DashboardState>,
    Query(q): Query<WindowQuery>,
) -> Result<Json<Vec<crate::ServiceCost>>, StatusCode> {
    let window = AnalyticsWindow::parse_window(&q.window);
    state
        .store
        .analytics(window)
        .await
        .map(|a| Json(a.costs_by_service))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── 30-rule catalogue ─────────────────────────────────────────────────────────

/// A single entry in the 30-rule governance catalogue.
#[derive(Serialize)]
pub struct Rule {
    /// Unique rule identifier (e.g. `"pii_ssn_v1"`).
    id:          &'static str,
    entity:      &'static str,
    action:      &'static str,
    tier:        &'static str,
    severity:    &'static str,
    description: &'static str,
}

/// `GET /dashboard/api/rules` — returns the 30 default rule catalogue.
pub async fn get_rules() -> Json<Vec<Rule>> {
    Json(vec![
        Rule { id:"pii_ssn_v1",            entity:"US_SSN",              action:"remove",  tier:"profile",   severity:"high",     description:"US Social Security Number" },
        Rule { id:"pii_credit_card_v1",    entity:"CREDIT_CARD",         action:"remove",  tier:"profile",   severity:"high",     description:"Credit/debit card (Luhn validated)" },
        Rule { id:"pii_iban_v1",           entity:"IBAN_CODE",           action:"remove",  tier:"profile",   severity:"high",     description:"IBAN (mod-97 validated)" },
        Rule { id:"pii_bank_account_v1",   entity:"BANK_ACCOUNT",        action:"remove",  tier:"profile",   severity:"high",     description:"Bank account number" },
        Rule { id:"pii_passport_v1",       entity:"US_PASSPORT",         action:"remove",  tier:"profile",   severity:"high",     description:"US passport number" },
        Rule { id:"pii_driver_license_v1", entity:"US_DRIVER_LICENSE",   action:"mask",    tier:"profile",   severity:"medium",   description:"US driver's license" },
        Rule { id:"pii_email_v1",          entity:"EMAIL_ADDRESS",       action:"mask",    tier:"profile",   severity:"medium",   description:"Email address" },
        Rule { id:"pii_phone_v1",          entity:"PHONE_NUMBER",        action:"mask",    tier:"profile",   severity:"low",      description:"Phone number" },
        Rule { id:"pii_ip_address_v1",     entity:"IP_ADDRESS_V4/V6",   action:"mask",    tier:"profile",   severity:"low",      description:"IP address" },
        Rule { id:"pii_mrn_v1",            entity:"MEDICAL_RECORD_NUMBER",action:"remove", tier:"profile",   severity:"high",     description:"Medical record number" },
        Rule { id:"pii_dob_v1",            entity:"DATE_OF_BIRTH",       action:"mask",    tier:"profile",   severity:"medium",   description:"Date of birth" },
        Rule { id:"secret_block_v1",       entity:"ANY_SECRET",          action:"block",   tier:"security",  severity:"critical", description:"Secret credential (umbrella)" },
        Rule { id:"secret_aws_key_v1",     entity:"AWS_ACCESS_KEY",      action:"remove",  tier:"security",  severity:"critical", description:"AWS access key ID" },
        Rule { id:"secret_aws_secret_v1",  entity:"AWS_SECRET_KEY",      action:"remove",  tier:"security",  severity:"critical", description:"AWS secret access key" },
        Rule { id:"secret_github_token_v1",entity:"GITHUB_TOKEN",        action:"remove",  tier:"security",  severity:"critical", description:"GitHub personal access token" },
        Rule { id:"secret_openai_key_v1",  entity:"OPENAI_KEY",          action:"remove",  tier:"security",  severity:"critical", description:"OpenAI API key" },
        Rule { id:"secret_anthropic_key_v1",entity:"ANTHROPIC_KEY",      action:"remove",  tier:"security",  severity:"critical", description:"Anthropic API key" },
        Rule { id:"secret_generic_api_key_v1",entity:"GENERIC_API_KEY",  action:"remove",  tier:"security",  severity:"high",     description:"Generic API key in JSON" },
        Rule { id:"secret_private_key_v1", entity:"PRIVATE_KEY",         action:"remove",  tier:"security",  severity:"critical", description:"PEM private key" },
        Rule { id:"secret_jwt_v1",         entity:"JWT_TOKEN",           action:"hash",    tier:"security",  severity:"high",     description:"JSON Web Token" },
        Rule { id:"secret_password_json_v1",entity:"PASSWORD_IN_JSON",   action:"remove",  tier:"security",  severity:"critical", description:"Password in JSON body" },
        Rule { id:"sec_prompt_injection_v1",entity:"N/A",                action:"block",   tier:"security",  severity:"critical", description:"Prompt injection attempt" },
        Rule { id:"sec_sysextract_v1",     entity:"N/A",                 action:"block",   tier:"security",  severity:"high",     description:"System prompt extraction attempt" },
        Rule { id:"sec_ddl_mutation_v1",   entity:"N/A",                 action:"block",   tier:"security",  severity:"critical", description:"DDL mutation (DROP/TRUNCATE/ALTER TABLE)" },
        Rule { id:"sec_delete_no_where_v1",entity:"N/A",                 action:"block",   tier:"security",  severity:"high",     description:"DELETE FROM without WHERE clause" },
        Rule { id:"sec_ssrf_v1",           entity:"N/A",                 action:"block",   tier:"security",  severity:"critical", description:"SSRF: internal IP in HTTP argument" },
        Rule { id:"sec_path_traversal_v1", entity:"N/A",                 action:"block",   tier:"security",  severity:"high",     description:"Path traversal sequence in file argument" },
        Rule { id:"sec_encoded_evasion_v1",entity:"N/A",                 action:"block",   tier:"security",  severity:"critical", description:"Security pattern in encoded (evasion) content" },
        Rule { id:"mcp_tool_acl_v1",       entity:"N/A",                 action:"block",   tier:"profile",   severity:"high",     description:"MCP tool not in org ACL" },
        Rule { id:"token_quota_v1",        entity:"N/A",                 action:"block",   tier:"profile",   severity:"medium",   description:"Token quota exceeded" },
    ])
}

// ── Kill-switch ───────────────────────────────────────────────────────────────

/// Current status of the emergency kill-switch across all scopes.
#[derive(Serialize)]
pub struct KillSwitchStatus {
    /// Whether the global kill-switch is active.
    pub global: bool,
    /// Active org-scoped kill-switches: `org_id -> reason`.
    pub by_org: std::collections::HashMap<String, String>,
    /// Active caller-scoped kill-switches: `caller_id -> reason`.
    pub by_caller: std::collections::HashMap<String, String>,
}

/// `GET /dashboard/api/kill-switch/status`
///
/// Reads the live status from the proxy's real `KillSwitchState` via the
/// [`KillSwitchControl`] adapter injected into [`DashboardState`] — never a
/// fabricated snapshot.
pub async fn get_kill_switch_status(
    State(state): State<DashboardState>,
) -> Json<KillSwitchStatus> {
    let view = state.kill_switch.status().await;
    Json(KillSwitchStatus {
        global:    view.global,
        by_org:    view.by_org,
        by_caller: view.by_caller,
    })
}

/// Request body for kill-switch activate / deactivate endpoints.
#[derive(Deserialize)]
pub struct KillSwitchRequest {
    /// Scope of the kill-switch: `"global"`, `"org"`, or `"caller"`.
    pub scope:  String,
    /// Human-readable reason (required for activation, audited).
    pub reason: Option<String>,
    /// Target ID for org- or caller-scoped switches.
    pub target: Option<String>,
}

/// Identity recorded as the activator for dashboard-originated kill-switch
/// changes. The dashboard authenticates callers via a shared secret
/// ([`crate::auth::DashboardAuth`]) rather than per-user identities, so a
/// fixed, clearly-labelled actor is recorded in the audit trail.
const DASHBOARD_ACTOR: &str = "dashboard-operator";

/// `POST /dashboard/api/kill-switch/activate`
///
/// Activates the real kill-switch via [`KillSwitchControl::activate`]. A
/// non-empty `reason` is required — the emergency stop must always be
/// auditable (SPEC.md §23 Rule 26).
///
/// # Errors
/// Returns `StatusCode::BAD_REQUEST` for an empty reason, an unknown scope, or
/// a missing `target` for an org/caller-scoped activation.
pub async fn activate_kill_switch(
    State(state): State<DashboardState>,
    Json(req): Json<KillSwitchRequest>,
) -> Result<StatusCode, StatusCode> {
    let reason = req
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;

    state
        .kill_switch
        .activate(&req.scope, req.target.as_deref(), reason, DASHBOARD_ACTOR)
        .await
        .map(|()| StatusCode::ACCEPTED)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

/// `POST /dashboard/api/kill-switch/deactivate`
///
/// Deactivates the real kill-switch via [`KillSwitchControl::deactivate`].
///
/// # Errors
/// Returns `StatusCode::BAD_REQUEST` for an unknown scope or a missing
/// `target` for an org/caller-scoped deactivation.
pub async fn deactivate_kill_switch(
    State(state): State<DashboardState>,
    Json(req): Json<KillSwitchRequest>,
) -> Result<StatusCode, StatusCode> {
    state
        .kill_switch
        .deactivate(&req.scope, req.target.as_deref())
        .await
        .map(|()| StatusCode::ACCEPTED)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

// ── Policy validation ─────────────────────────────────────────────────────────

/// Request body for policy bundle validation.
#[derive(Deserialize)]
pub struct ValidatePolicyRequest {
    /// YAML-encoded policy bundle to validate.
    pub yaml: String,
}

/// Result of policy bundle validation.
#[derive(Serialize)]
pub struct ValidationResult {
    /// Whether the policy is syntactically and semantically valid.
    pub valid:  bool,
    /// Validation error messages (empty when `valid` is `true`).
    pub errors: Vec<String>,
}

/// `POST /dashboard/api/policies/validate`
///
/// Performs real structural validation of a policy manifest YAML document
/// against the rules encoded in `policies/schemas/policy_manifest.json`
/// (`apiVersion`/`kind` constants, `metadata`/`spec` shape, field patterns
/// and enums). This is YAML/structure validation — full Rego compilation is
/// performed by the admin API's `compiler_service` (SPEC.md §6 admin-api).
pub async fn validate_policy(
    Json(req): Json<ValidatePolicyRequest>,
) -> Json<ValidationResult> {
    let errors = validate_policy_manifest(&req.yaml);
    Json(ValidationResult { valid: errors.is_empty(), errors })
}

/// Structurally validate a policy manifest YAML document, returning a list of
/// human-readable error messages (empty when the document is valid).
fn validate_policy_manifest(yaml: &str) -> Vec<String> {
    if yaml.trim().is_empty() {
        return vec!["Policy YAML must not be empty.".into()];
    }

    let doc: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(e) => return vec![format!("YAML parse error: {e}")],
    };

    let Some(root) = doc.as_mapping() else {
        return vec!["Policy manifest must be a YAML mapping (object) at the top level.".into()];
    };

    let mut errors = Vec::new();

    match root.get("apiVersion").and_then(serde_yaml::Value::as_str) {
        Some("revoc.io/v1") => {}
        Some(other) => errors.push(format!(
            "apiVersion must be 'revoc.io/v1', found '{other}'."
        )),
        None => errors.push("apiVersion is required and must be 'revoc.io/v1'.".into()),
    }

    match root.get("kind").and_then(serde_yaml::Value::as_str) {
        Some("PolicyManifest") => {}
        Some(other) => errors.push(format!(
            "kind must be 'PolicyManifest', found '{other}'."
        )),
        None => errors.push("kind is required and must be 'PolicyManifest'.".into()),
    }

    match root.get("metadata").and_then(serde_yaml::Value::as_mapping) {
        Some(meta) => validate_metadata(meta, &mut errors),
        None => errors.push("metadata is required and must be an object.".into()),
    }

    match root.get("spec") {
        Some(serde_yaml::Value::Mapping(spec)) => validate_spec(spec, &mut errors),
        Some(_) => errors.push("spec must be an object.".into()),
        None => errors.push("spec is required and must be an object.".into()),
    }

    errors
}

/// `^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$` — kebab-case, 2-64 chars, no leading/trailing hyphen.
fn is_kebab_case_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 64 {
        return false;
    }
    let is_alnum_lower = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum_lower(bytes[0]) || !is_alnum_lower(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|&b| is_alnum_lower(b) || b == b'-')
}

/// `^\d+\.\d+\.\d+$` — strict `MAJOR.MINOR.PATCH` semantic version.
fn is_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn validate_metadata(meta: &serde_yaml::Mapping, errors: &mut Vec<String>) {
    match meta.get("name").and_then(serde_yaml::Value::as_str) {
        Some(name) if is_kebab_case_name(name) => {}
        Some(name) => errors.push(format!(
            "metadata.name '{name}' must be kebab-case, 2-64 lowercase alphanumeric characters \
             or hyphens, with no leading or trailing hyphen."
        )),
        None => errors.push("metadata.name is required and must be a string.".into()),
    }

    match meta.get("org_id").and_then(serde_yaml::Value::as_str) {
        Some(id) if !id.trim().is_empty() => {}
        _ => errors.push("metadata.org_id is required and must be a non-empty string.".into()),
    }

    if let Some(version) = meta.get("version") {
        match version.as_str() {
            Some(v) if is_semver(v) => {}
            Some(v) => errors.push(format!(
                "metadata.version '{v}' must match MAJOR.MINOR.PATCH (e.g. '1.0.0')."
            )),
            None => errors.push("metadata.version must be a string.".into()),
        }
    }

    if let Some(env) = meta.get("environment") {
        const ALLOWED: &[&str] = &["development", "staging", "production", "test"];
        match env.as_str() {
            Some(e) if ALLOWED.contains(&e) => {}
            Some(e) => errors.push(format!(
                "metadata.environment '{e}' must be one of: {}.",
                ALLOWED.join(", ")
            )),
            None => errors.push("metadata.environment must be a string.".into()),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_spec(spec: &serde_yaml::Mapping, errors: &mut Vec<String>) {
    if let Some(profile) = spec.get("profile") {
        const ALLOWED: &[&str] = &[
            "hipaa", "pci-dss", "gdpr", "soc2", "financial-services", "internal-dev",
        ];
        match profile.as_str() {
            Some(p) if ALLOWED.contains(&p) => {}
            Some(p) => errors.push(format!(
                "spec.profile '{p}' must be one of: {}.",
                ALLOWED.join(", ")
            )),
            None => errors.push("spec.profile must be a string.".into()),
        }
    }

    if let Some(enforcement) = spec.get("enforcement") {
        match enforcement.as_mapping() {
            Some(e) => {
                if let Some(mode) = e.get("mode") {
                    match mode.as_str() {
                        Some("enforce" | "shadow") => {}
                        Some(m) => errors.push(format!(
                            "spec.enforcement.mode '{m}' must be 'enforce' or 'shadow'."
                        )),
                        None => errors.push("spec.enforcement.mode must be a string.".into()),
                    }
                }
                match e.get("fail_open") {
                    Some(serde_yaml::Value::Bool(false)) | None => {}
                    Some(serde_yaml::Value::Bool(true)) => errors.push(
                        "spec.enforcement.fail_open must be false — fail_open=true is \
                         non-negotiable in production (SPEC.md §3 Principle 7)."
                            .into(),
                    ),
                    Some(_) => errors.push("spec.enforcement.fail_open must be a boolean.".into()),
                }
            }
            None => errors.push("spec.enforcement must be an object.".into()),
        }
    }

    if let Some(governance) = spec.get("governance") {
        match governance.as_mapping() {
            Some(g) => {
                if let Some(max_depth) = g.get("max_depth") {
                    match max_depth.as_i64() {
                        Some(d) if (1..=10).contains(&d) => {}
                        Some(d) => errors.push(format!(
                            "spec.governance.max_depth {d} must be between 1 and 10."
                        )),
                        None => errors.push("spec.governance.max_depth must be an integer.".into()),
                    }
                }
            }
            None => errors.push("spec.governance must be an object.".into()),
        }
    }

    if let Some(restrictions) = spec.get("model_restrictions") {
        match restrictions.as_mapping() {
            Some(r) => match r.get("allowed_models").and_then(serde_yaml::Value::as_sequence) {
                Some(models) if !models.is_empty() => {
                    if !models.iter().all(|m| m.as_str().is_some()) {
                        errors.push(
                            "spec.model_restrictions.allowed_models must be an array of strings."
                                .into(),
                        );
                    }
                }
                Some(_) => errors.push(
                    "spec.model_restrictions.allowed_models must contain at least one model."
                        .into(),
                ),
                None => errors.push(
                    "spec.model_restrictions.allowed_models is required and must be an array."
                        .into(),
                ),
            },
            None => errors.push("spec.model_restrictions must be an object.".into()),
        }
    }

    if let Some(stream) = spec.get("stream") {
        if let Some(s) = stream.as_mapping() {
            if let Some(window) = s.get("sliding_window_size") {
                match window.as_i64() {
                    Some(w) if (64..=4096).contains(&w) => {}
                    Some(w) => errors.push(format!(
                        "spec.stream.sliding_window_size {w} must be between 64 and 4096."
                    )),
                    None => errors.push(
                        "spec.stream.sliding_window_size must be an integer.".into(),
                    ),
                }
            }
        } else {
            errors.push("spec.stream must be an object.".into());
        }
    }

    if let Some(webhooks) = spec.get("webhooks") {
        match webhooks.as_mapping() {
            Some(w) => {
                if let Some(events) = w.get("events").and_then(serde_yaml::Value::as_sequence) {
                    const ALLOWED: &[&str] =
                        &["block", "redact", "audit", "quota_exceeded", "kill_switch"];
                    for ev in events {
                        match ev.as_str() {
                            Some(e) if ALLOWED.contains(&e) => {}
                            Some(e) => errors.push(format!(
                                "spec.webhooks.events entry '{e}' must be one of: {}.",
                                ALLOWED.join(", ")
                            )),
                            None => errors
                                .push("spec.webhooks.events entries must be strings.".into()),
                        }
                    }
                }
                if let Some(sev) = w.get("min_severity") {
                    const ALLOWED: &[&str] = &["info", "low", "medium", "high", "critical"];
                    match sev.as_str() {
                        Some(s) if ALLOWED.contains(&s) => {}
                        Some(s) => errors.push(format!(
                            "spec.webhooks.min_severity '{s}' must be one of: {}.",
                            ALLOWED.join(", ")
                        )),
                        None => errors.push(
                            "spec.webhooks.min_severity must be a string.".into(),
                        ),
                    }
                }
            }
            None => errors.push("spec.webhooks must be an object.".into()),
        }
    }
}
