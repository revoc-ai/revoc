//! D10 — Tool manifest analysis (SPEC.md §9 D10).
//!
//! Analyzes `tools/list` responses for dangerous parameter names and suspicious
//! description patterns before the AI client receives them.

use revoc_core::Severity;

/// Parameter names that indicate sensitive or dangerous tool capabilities.
pub const DANGEROUS_PARAM_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "credentials",
    "private_key",
    "cert",
    "bearer",
    "access_token",
    "refresh_token",
    "cmd",
    "command",
    "eval",
    "exec",
    "shell",
    "script",
    "execute",
    "subprocess",
    "sql",
    "query",
    "statement",
    "raw_sql",
    "admin",
    "root",
    "sudo",
    "privilege",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
];

/// Description substrings that suggest prompt-injection or privilege escalation.
pub const SUSPICIOUS_DESC_PATTERNS: &[&str] = &[
    "ignore previous",
    "disregard",
    "override all",
    "system prompt",
    "admin access",
    "privileged",
    "bypass",
    "jailbreak",
];

/// A single risk finding from manifest analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestFinding {
    /// Name of the tool containing the risky parameter or description.
    pub tool_name: String,
    /// Name of the parameter, or `"description"` for description-level risks.
    pub parameter_name: String,
    /// The keyword or pattern that triggered the finding.
    pub matched_keyword: String,
    /// Severity of the finding.
    pub severity: Severity,
}

/// The complete result of analyzing a `tools/list` response body.
#[derive(Debug)]
pub struct ManifestAnalysisResult {
    /// All findings produced by the analysis.
    pub findings: Vec<ManifestFinding>,
    /// Number of tools whose definitions were examined.
    pub tools_analyzed: usize,
}

/// Analyze a `tools/list` response body for dangerous parameters and descriptions.
///
/// Accepts:
/// - `{"tools": [...]}` — standard MCP envelope
/// - `[...]` — bare JSON array of tool definitions
///
/// For each tool:
/// 1. Checks `inputSchema.properties` or `parameters.properties` key names
///    against [`DANGEROUS_PARAM_KEYWORDS`].
/// 2. Checks the tool's `description` text against [`SUSPICIOUS_DESC_PATTERNS`].
pub fn analyze_tools_list(body: &[u8]) -> ManifestAnalysisResult {
    let mut findings = Vec::new();

    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return ManifestAnalysisResult {
                findings,
                tools_analyzed: 0,
            }
        }
    };

    // Accept {"tools": [...]} or bare [...] arrays
    let Some(tools) = value
        .get("tools")
        .and_then(|t| t.as_array())
        .or_else(|| value.as_array())
    else {
        return ManifestAnalysisResult {
            findings,
            tools_analyzed: 0,
        };
    };

    let tools_analyzed = tools.len();

    for tool in tools {
        let tool_name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Check parameter names in inputSchema.properties or parameters.properties
        if let Some(props) = tool
            .pointer("/inputSchema/properties")
            .or_else(|| tool.pointer("/parameters/properties"))
            .and_then(|p| p.as_object())
        {
            'param: for (param_name, _) in props {
                let lower = param_name.to_lowercase();
                for &kw in DANGEROUS_PARAM_KEYWORDS {
                    if lower.contains(kw) {
                        findings.push(ManifestFinding {
                            tool_name: tool_name.clone(),
                            parameter_name: param_name.clone(),
                            matched_keyword: kw.to_string(),
                            severity: Severity::High,
                        });
                        // One finding per parameter (first matching keyword wins)
                        continue 'param;
                    }
                }
            }
        }

        // Check description text for suspicious instruction patterns
        if let Some(desc) = tool.get("description").and_then(|d| d.as_str()) {
            let lower = desc.to_lowercase();
            for &pattern in SUSPICIOUS_DESC_PATTERNS {
                if lower.contains(pattern) {
                    findings.push(ManifestFinding {
                        tool_name: tool_name.clone(),
                        parameter_name: "description".to_string(),
                        matched_keyword: pattern.to_string(),
                        severity: Severity::Critical,
                    });
                    // One finding per tool description (first match wins)
                    break;
                }
            }
        }
    }

    ManifestAnalysisResult {
        findings,
        tools_analyzed,
    }
}
