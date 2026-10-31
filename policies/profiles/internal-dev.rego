# REVOC Internal Development profile.
# Package: revoc.governance.profile.internal-dev
#
# A relaxed profile for internal engineering teams with a safety floor:
#   - PII and secrets → Audit only (do not block or redact in dev/staging).
#   - DDL mutations → Block (prevent accidental prod-like schema damage in shared DBs).
#   - Prompt injection → Block (safety floor — cannot be relaxed further).
#   - SSRF / path traversal → Block (safety floor).
#
# Intended use: internal developer tooling, sandboxes, CI pipelines.
# Do NOT use for production or any customer-facing workload.

package revoc.governance.profile.internal_dev

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── PII in dev context → Audit only ──────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PII"
	v := {
		"rule_id":  "dev_pii_audit_v1",
		"message":  sprintf("Internal-Dev: PII entity '%v' detected — audited (not blocked in dev profile)", [f.pii_entity]),
		"severity": "LOW",
		"action":   "audit",
		"tier":     "custom",
	}
}

# ── Secrets in dev context → Audit only ──────────────────────────────────────
# NOTE: This does NOT apply in production. Use the default profile for prod.

violations contains v if {
	some f in input.findings
	f.finding_type == "SECRET_EXPOSURE"
	v := {
		"rule_id":  "dev_secret_audit_v1",
		"message":  sprintf("Internal-Dev: secret '%v' detected — audited (not blocked in dev profile)", [f.pii_entity]),
		"severity": "MEDIUM",
		"action":   "audit",
		"tier":     "custom",
	}
}

# ── DDL mutations → Block (safety floor) ─────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "DDL_MUTATION"
	v := {
		"rule_id":  "dev_ddl_block_v1",
		"message":  "Internal-Dev: DDL mutations blocked even in dev (prevents accidental schema damage in shared DBs)",
		"severity": "HIGH",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Prompt injection → Block (safety floor) ──────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PROMPT_INJECTION"
	v := {
		"rule_id":  "dev_injection_block_v1",
		"message":  "Internal-Dev: prompt injection blocked (safety floor — cannot be relaxed)",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── SSRF → Block (safety floor) ──────────────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "SSRF_ATTEMPT"
	v := {
		"rule_id":  "dev_ssrf_block_v1",
		"message":  "Internal-Dev: SSRF attempt blocked (safety floor)",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}

# ── Path traversal → Block (safety floor) ────────────────────────────────────

violations contains v if {
	some f in input.findings
	f.finding_type == "PATH_TRAVERSAL"
	v := {
		"rule_id":  "dev_path_traversal_block_v1",
		"message":  "Internal-Dev: path traversal blocked (safety floor)",
		"severity": "CRITICAL",
		"action":   "block",
		"tier":     "security",
	}
}
