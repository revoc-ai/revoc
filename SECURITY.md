# Security Policy

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues privately through GitHub's **private vulnerability reporting**:

**[Report a vulnerability](https://github.com/revoc-ai/revoc/security/advisories/new)** (or **Security → Report a vulnerability** on the repository page)

The report is visible only to you and the maintainers, and becomes a draft GitHub
Security Advisory that we use to coordinate the fix, request a CVE and credit you.

Include:
- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code if available)
- The affected version(s)
- Your assessment of impact and severity
- Whether you have a proposed fix

We will acknowledge your report within **24 hours** for Critical severity,
and confirm receipt within **48 hours** for all reports.

---

## Response SLA

| Severity | Definition | Acknowledgement | Fix & Release |
|---|---|---|---|
| **Critical** | RCE, auth bypass, data exfiltration, kill-switch bypass | 24 hours | 24–48 hours |
| **High** | Governance bypass, PII leak, SSRF, header injection | 48 hours | 72 hours |
| **Medium** | Denial of service, timing side-channel, config exposure | 72 hours | 2 weeks |
| **Low** | Informational, defense-in-depth improvement | 1 week | Next minor release |

All security fixes are released as patch versions (e.g. v1.0.1) and
described in the CHANGELOG with a `sec:` prefix commit.

---

## Coordinated Disclosure

We follow **coordinated disclosure**:

1. Reporter submits a private report via GitHub (link above).
2. We confirm receipt and begin investigation.
3. We develop and test a fix privately.
4. We notify the reporter when the fix is ready.
5. We release the fix and publish the GitHub Security Advisory simultaneously.
6. The reporter is credited in the advisory (unless they prefer anonymity).

We ask reporters to give us the SLA time above before public disclosure.
We will not take legal action against researchers acting in good faith.

---

## Safe Harbor

We consider security research conducted under the following conditions to
be authorized and will not pursue legal action:

- Testing is performed against your **own** REVOC installation, not
  against third-party infrastructure.
- Research does not access, modify, or destroy data belonging to others.
- Findings are reported to us before public disclosure.
- You do not exploit vulnerabilities beyond what is needed to demonstrate
  the issue.

---

## Known Security Properties

The following properties are non-negotiable design invariants, not
configuration options. Violation of any of these is a critical bug.

### Fail-Closed (`fail_open = false`)

REVOC fails closed by default. If the policy engine is unreachable or
REVOC itself encounters an unrecoverable error, all AI traffic is blocked.
`fail_open = true` must never appear in a committed configuration file
(SPEC.md §23 Rule 4).

### Constant-Time API Key Comparison

All API key comparisons use `subtle::ConstantTimeEq` to prevent
timing-based enumeration attacks (SPEC.md §17).

### No Telemetry

The proxy process never initiates outbound connections to revoc.io or any
telemetry endpoint. All data remains within the operator's infrastructure
(SPEC.md §23 Rule 23). This is enforced at the code level: there is no
phone-home code path.

### Unicode Normalization Before Detection

All text is NFKC-normalized and stripped of zero-width and BIDI override
characters before regex detection runs. This prevents evasion via Unicode
homoglyphs or invisible character injection (SPEC.md §9 D8, Principle 5).

### SSRF Protection

Upstream URLs are resolved exclusively from the allow-listed `[upstream.providers]`
configuration. Request headers cannot influence which upstream host receives
traffic (SPEC.md §17).

### Header Injection Prevention

All values placed in response headers are sanitized to strip `\r`, `\n`,
and `\0` characters (SPEC.md §17).

### Governance Depth Limit

Agent recursion is capped at depth 10. Requests carrying
`X-Revoc-Depth: 10` or higher are rejected with HTTP 503 before any
processing occurs (SPEC.md §9 D9, Principle 6).

### Blocked MCP Requests Never Reach Upstream

When a `tools/call` is blocked, the upstream MCP tool server never receives
the request. The block is applied entirely within the proxy (SPEC.md §11,
MCP Step 9).

### Upstream Error Transparency

HTTP 4xx/5xx responses from upstream providers are forwarded verbatim.
REVOC never wraps upstream errors in its own error format, ensuring
operators see the real upstream error without modification (SPEC.md
Principle 8, §17).

---

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ Active security support |
| Previous minor  | ✅ Security patches only |
| Older versions  | ❌ Please upgrade |

---

## Security-Related Configuration

See `configs/revoc.toml` for all security-relevant settings. Key fields:

```toml
[policy]
fail_open = false          # NEVER set to true in production

[detection]
normalize_before_scan = true   # MUST remain true — evasion defense

[governance]
max_depth = 10             # Do not increase above 10

[kill_switch]
enabled = true             # Emergency stop capability
```
