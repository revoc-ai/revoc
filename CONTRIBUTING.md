# Contributing to REVOC

Thank you for contributing to REVOC — Runtime Execution Validation & Observability Control.
This document covers everything you need to go from zero to a merged pull request.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [How to Add a Detection Pattern](#how-to-add-a-detection-pattern)
4. [How to Add an Upstream Provider](#how-to-add-an-upstream-provider)
5. [How to Add a Compliance Profile](#how-to-add-a-compliance-profile)
6. [PR Process & Conventional Commits](#pr-process--conventional-commits)
7. [Testing Requirements](#testing-requirements)
8. [The 15 Non-Negotiable Principles](#the-15-non-negotiable-principles)

---

## Development Setup

### Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust | 1.80.0 (pinned) | `rustup install 1.80.0` |
| cargo-nextest | latest | `cargo install cargo-nextest` |
| Python | 3.12+ | system package manager |
| Node.js | 20+ | system package manager |
| Docker | 24+ | https://docs.docker.com/get-docker/ |
| OPA | 0.68+ | https://www.openpolicyagent.org/docs/latest/#running-opa |
| just / make | any | pre-installed on most systems |

### Clone and bootstrap

```bash
git clone https://github.com/revoc-ai/revoc.git
cd revoc

# Rust toolchain is pinned — rustup picks it up automatically
rustup show

# Build everything
cargo build --workspace

# Run all tests
cargo nextest run --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

### Run in development mode (mock upstream, no external deps)

```bash
cp .env.example .env
# Edit .env — no API keys needed in mock mode

cargo run --bin revoc-proxy -- serve --config configs/revoc.dev.toml
# Proxy: http://localhost:8080
# Dashboard: http://localhost:3000
# Internal admin: http://localhost:8081
```

### Run with Docker Compose (Tier 2 — Postgres + Redis)

```bash
make up
# or
docker compose -f docker/docker-compose.yml up -d

make logs   # tail logs
make down   # stop
```

### Admin API (Python/FastAPI)

```bash
cd admin-api
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8090
```

### Node SDK

```bash
cd sdk/node
npm install
npm run build
npm test
```

---

## Project Structure

See SPEC.md Section 6 for the full directory tree. Key locations:

```
crates/revoc-detector/src/patterns/   ← Add new detection patterns here
crates/revoc-detector/src/tests/      ← Pattern unit tests
crates/revoc-policy/src/              ← Policy engine and conflict resolution
policies/default/                     ← Rego policy files
policies/profiles/                    ← Compliance profile Rego files
configs/                              ← TOML configuration files
```

---

## How to Add a Detection Pattern

Follow these steps exactly. All steps are required for a pattern PR to be accepted.

### Step 1 — Choose the right patterns file

| Pattern type | File |
|---|---|
| PII (SSN, email, phone, credit card, etc.) | `crates/revoc-detector/src/patterns/pii.rs` |
| Secrets (API keys, tokens, passwords) | `crates/revoc-detector/src/patterns/secrets.rs` |
| Security threats (injection, SSRF, DDL) | `crates/revoc-detector/src/patterns/security.rs` |
| Financial (IBAN, SWIFT, routing numbers) | `crates/revoc-detector/src/patterns/financial.rs` |

### Step 2 — Add the entity type

In `crates/revoc-core/src/types/finding.rs`, add a variant to the appropriate enum:

```rust
// For PII:
pub enum PiiEntityType {
    // ... existing variants ...
    YourNewEntity,
}

// Also implement Display for it:
Self::YourNewEntity => "YOUR_NEW_ENTITY",
```

For non-PII types, add to `FindingType` if it is a new category.

### Step 3 — Write the regex

In the appropriate patterns file, add a compiled `Regex` or `fancy_regex::Regex`:

```rust
// In patterns/pii.rs (example — US NPI number)
pub static NPI_NUMBER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:npi|national\s+provider)\s*[:#]?\s*(\d{10})\b")
        .expect("NPI_NUMBER regex must compile")
});
```

Rules:
- Use `once_cell::sync::Lazy` for all compiled regexes
- Use `fancy_regex` only when lookbehind/lookahead is required (performance cost)
- Add the entity to `DANGEROUS_PARAM_KEYWORDS` in `manifest_analyzer.rs` if it
  can appear as an MCP tool parameter name

### Step 4 — Add a validator (if applicable)

Validators go in `patterns/pii.rs` alongside the regex. Required for:
- Credit cards → `luhn_check()`
- IBANs → `iban_checksum_valid()`
- ABA routing numbers → `aba_routing_check()`

```rust
pub fn your_checksum(s: &str) -> bool {
    // validate and return true/false
}
```

### Step 5 — Wire up in `regex_detector.rs`

In `crates/revoc-detector/src/regex_detector.rs`, add the pattern to the scan loop:

```rust
for m in patterns::pii::NPI_NUMBER.find_iter(&normalized.text) {
    findings.push(
        Finding::new(
            FindingType::Pii,
            Severity::High,
            DetectionTier::Regex,
        )
        .with_span(TextSpan { start: m.start(), end: m.end(), field: field.to_string(), value: None })
        .with_pii(PiiEntityType::NpiNumber)
        .with_confidence(0.95),
    );
    // Set was_normalized if the normalized text differed from the raw text
}
```

### Step 6 — Add a default rule

In `crates/revoc-policy/src/defaults.rs`, add a rule entry:

```rust
PolicyRule {
    id: "pii_npi_v1",
    entity: EntityMatch::Pii(PiiEntityType::NpiNumber),
    action: Action::Redact,
    tier: PolicyRuleTier::Profile,
    severity: Severity::High,
},
```

### Step 7 — Write tests

In `crates/revoc-detector/src/tests/pii_tests.rs` (or the appropriate test file):

```rust
#[test]
fn test_npi_number_detected() {
    let engine = build_test_engine();
    let input = make_input("NPI: 1234567890");
    let findings = engine.detect_sync(&input);
    assert!(findings.iter().any(|f| f.pii_entity == Some(PiiEntityType::NpiNumber)));
}

#[test]
fn test_npi_number_normalized_evasion() {
    // Must also detect through Unicode evasion (D8 requirement)
    let engine = build_test_engine();
    let input = make_input("ＮＰＩ: 1234567890");  // fullwidth chars
    let findings = engine.detect_sync(&input);
    assert!(findings.iter().any(|f| f.was_normalized));
}

#[test]
fn test_npi_number_false_positive_rate() {
    // Test at least 5 strings that look similar but should NOT match
    let engine = build_test_engine();
    for non_npi in &["123456789", "12345678901", "NPI: abc1234567"] {
        let findings = engine.detect_sync(&make_input(non_npi));
        assert!(findings.iter().all(|f| f.pii_entity != Some(PiiEntityType::NpiNumber)),
            "False positive on: {non_npi}");
    }
}
```

### Step 8 — Update SPEC.md Section 8

Add your pattern to the appropriate table in Section 8 of `SPEC.md`.

### Step 9 — Add a CHANGELOG entry

Under `## [Unreleased]` add a line:
```
- feat(detector): add NPI_NUMBER PII detection pattern with confidence 0.95
```

---

## How to Add an Upstream Provider

### Step 1 — Add provider config variant

In `crates/revoc-config/src/schema.rs`, add the provider format if it is new:

```rust
pub enum ProviderFormat {
    OpenAi,
    Anthropic,
    Azure,
    YourProvider,  // add here
}
```

### Step 2 — Add request/response translation

In `crates/revoc-proxy/src/upstream/router.rs`, add translation logic:

```rust
ProviderFormat::YourProvider => {
    translate_openai_to_your_provider(request)
}
```

Translation must handle:
- Request body format differences
- Authentication header differences (Bearer vs x-api-key vs custom)
- Response body normalization back to OpenAI format
- Streaming SSE format differences

### Step 3 — Add to default config

In `configs/revoc.toml`, add an example provider block under `[[upstream.providers]]`
with a comment explaining the format.

### Step 4 — Write upstream integration tests

In `tests/integration/`, add a test file that uses WireMock to stub the new
provider's API and verify:
- Request translation is correct
- Response translation is correct
- Streaming works
- 4xx/5xx errors are forwarded verbatim (SPEC.md §17)
- `X-Revoc-Dashboard` and `X-Revoc-Timing` are present on all responses

### Step 5 — Document in SPEC.md Section 13

Add the new provider format to the `[[upstream.providers]]` comment in Section 13.

---

## How to Add a Compliance Profile

Compliance profiles are Rego files in `policies/profiles/`. They operate at
`PolicyRuleTier::Profile` (tier 2) and can tighten — but never loosen —
Tier 3 Security rules.

### Step 1 — Create the Rego file

```bash
touch policies/profiles/your-profile.rego
```

The file must:
- Set `package revoc.profiles.your_profile`
- Import `data.revoc.default_rules`
- Only add rules at tier ≤ 2 (Profile)
- Never override or suppress a Security-tier rule

### Step 2 — Write OPA tests

```bash
touch policies/default/your_profile_test.rego
```

Run with:
```bash
make opa-test
# or
opa test policies/ -v --coverage
```

Coverage must be 100% for new profile rules.

### Step 3 — Add an example config bundle

```bash
cp policies/examples/hipaa-baseline.yaml policies/examples/your-profile-baseline.yaml
```

Edit to reference your profile's rule IDs.

### Step 4 — Register the profile in config schema

In `crates/revoc-config/src/schema.rs`, add the profile name to the
`KnownProfile` enum so it can be referenced in `policy_profile` fields.

### Step 5 — Add integration test

In `tests/integration/`, add a test that:
1. Loads your profile
2. Sends a request that your profile blocks but default rules allow
3. Verifies the correct `X-Revoc-Rules` header and 403 response

---

## PR Process & Conventional Commits

### Branch naming

```
feat/your-feature-name
fix/issue-description
sec/vulnerability-description
docs/what-you-documented
refactor/what-you-refactored
```

### Commit format (Conventional Commits)

```
<type>(<scope>): <short description>

[optional body]

[optional footer: Fixes #123]
```

| Type | When to use |
|---|---|
| `feat` | New feature or detection pattern |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `sec` | Security fix (use this for any security-related change) |
| `docs` | Documentation only |
| `refactor` | Refactoring without behavior change |
| `test` | Adding or fixing tests |
| `chore` | Tooling, CI, dependencies |
| `build` | Build system changes |

Examples:
```
feat(detector): add NPI_NUMBER PII detection with Luhn validation
fix(proxy): forward upstream 429 verbatim instead of wrapping in RevocError
sec(detector): normalize BIDI override chars before regex scan
perf(policy): add LRU cache for repeated identical policy inputs
```

### Pull request checklist

Before opening a PR, verify:

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes (or `cargo nextest run --workspace`)
- [ ] `cargo clippy --workspace -- -D warnings` produces no warnings
- [ ] `cargo fmt --all -- --check` passes
- [ ] All new public items have doc comments
- [ ] No `.unwrap()` or `.expect()` outside `#[cfg(test)]`
- [ ] No hardcoded secrets, URLs, or environment-specific values
- [ ] No `fail_open = true` anywhere in committed configs
- [ ] `X-Revoc-Dashboard` and `X-Revoc-Timing` present on all new response paths
- [ ] Normalization called before any new regex detection (D8)
- [ ] Kill-switch check is Step 0 in any new handler (D11)
- [ ] Depth check is Step 1 in any new handler (D9)
- [ ] New detection pattern has: regex, tests, default rule, CHANGELOG entry
- [ ] New upstream provider has: translation, verbatim error forwarding, tests
- [ ] No PII values in logs (only entity type + field + position)
- [ ] `make opa-test` passes if Rego was changed

### Review process

- **One maintainer approval** required for: bug fixes, documentation, tests,
  dependency updates
- **Two maintainer approvals** required for: new features, new detection patterns,
  config schema changes, new upstream providers
- **RFC required** (see GOVERNANCE.md) for: new default rules, compliance profiles,
  breaking config changes, new response headers

Maintainers aim to review within 5 business days. If you have not received a
review after 7 days, ping the PR with a comment.

---

## Testing Requirements

### By change type

| Change | Required tests |
|---|---|
| New detection pattern | Unit tests: true positive, false positive rate (≥5 non-matching strings), normalized evasion variant |
| New secret pattern | Same as above + test that the secret value is never logged |
| New security pattern | Same as above + test that it fires at Tier 3 (Security) |
| New handler or route | Integration test covering: allow, block, redact, kill-switch bypass, depth limit, dashboard header present |
| New policy rule | OPA unit test with 100% branch coverage |
| New compliance profile | OPA tests + integration test verifying profile-specific block |
| Config schema change | Test that invalid values are rejected at startup |
| Streaming change | Test with multi-chunk SSE fixture covering: partial match across chunk boundary, tool_call accumulation, finish_reason=tool_calls governance |
| Database schema change | Migration test (up + down) |
| Kill-switch change | Test activate, deactivate, status, Redis propagation stub |

### Performance regression guard

Any change to the detection pipeline must not regress the criterion benchmarks
beyond 10%. Run:

```bash
cargo bench --workspace
```

If a regression is intentional (e.g. adding a new pattern increases scan time),
document it in the PR description with the before/after numbers.

### Running specific test suites

```bash
# All workspace tests
cargo nextest run --workspace

# Single crate
cargo nextest run -p revoc-detector

# Single test
cargo nextest run -p revoc-detector normalization

# With output (useful for debugging)
cargo test -p revoc-detector normalization -- --nocapture

# OPA policy tests
make opa-test

# Integration tests (requires running stack)
make up && sleep 20
make integration-test
make down

# Admin API tests
cd admin-api
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## The 15 Non-Negotiable Principles

Every contribution must uphold all 15 principles from SPEC.md §3.
Violation of any principle is a bug, not a trade-off, and will block merge.

1. Zero governance code in application code
2. P95 proxy overhead < 10ms, P99 < 25ms
3. Rust-native detection — no external HTTP in hot path
4. Bidirectional governance on every direction, protocol, modality
5. Normalize before detect (NFKC + zero-width removal before every regex)
6. Max governance depth 10
7. Fail-closed (`fail_open = false` non-negotiable in production)
8. Upstream error transparency — 4xx/5xx forwarded verbatim, never wrapped
9. No PII in logs or audit values
10. Emergency kill-switch stops all traffic within 50ms
11. `X-Revoc-Dashboard` on every response
12. `X-Revoc-Timing` on every response
13. Tool manifest analysis before AI sees tools/list
14. Security rules always win (Tier 3 cannot be overridden)
15. No unsafe code (`#![forbid(unsafe_code)]` on all library crates)

---

## Getting Help

- **GitHub Discussions** — architecture questions, RFC proposals
- **GitHub Issues** — bug reports (use the bug report template)
- **[Private vulnerability report](https://github.com/revoc-ai/revoc/security/advisories/new)** — security vulnerabilities (never open a public issue)
- **SPEC.md** — the single source of truth for all design decisions

When in doubt, read SPEC.md Section 23 ("What Not To Do") before writing any code.
