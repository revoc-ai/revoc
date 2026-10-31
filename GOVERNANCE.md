# REVOC Project Governance

## Overview

REVOC — Runtime Execution Validation & Observability Control — is an
Apache 2.0 open-source project governed by its contributors. This document
describes how decisions are made, how maintainers are selected, and how the
project is run.

---

## Privacy Commitment

> **REVOC collects zero telemetry. No data leaves your infrastructure.**

The proxy process never calls home to revoc.io or any external service
(SPEC.md §23 Rule 23). All audit data, policy decisions, and detection
findings remain entirely within the operator's own infrastructure. This is
a non-negotiable design invariant, not a configuration option.

---

## License

- **Core**: Apache License 2.0 — see [LICENSE](LICENSE)
- **Enterprise addons** (optional, not required for full functionality):
  Commercial license — ask in [GitHub Discussions](https://github.com/revoc-ai/revoc/discussions)

The Apache 2.0 core includes all proxy, detection, policy, dashboard,
redaction, and SDK functionality. No feature is paywalled in the open-source
build.

---

## Maintainers

Maintainers are individuals who have demonstrated sustained, high-quality
contribution to REVOC over time. They have write access to the repository
and responsibility for the project's direction and quality.

Current maintainers are listed in [.github/CODEOWNERS](.github/CODEOWNERS).

### Becoming a Maintainer

1. Make meaningful contributions over at least 3 months (features, bug
   fixes, documentation, reviews).
2. Demonstrate understanding of the architecture and the 15 non-negotiable
   principles in SPEC.md §3.
3. Be nominated by an existing maintainer via a GitHub Discussion.
4. Receive approval from a majority of existing maintainers within 14 days.

### Maintainer Responsibilities

- Review and merge pull requests within 5 business days.
- Uphold all 27 "What Not To Do" rules from SPEC.md §23.
- Participate in security vulnerability triage (SLAs in [SECURITY.md](SECURITY.md)).
- Attend monthly maintainer sync (async-friendly: async vote accepted).

### Stepping Down

Maintainers who are inactive for 6 months are moved to Emeritus status.
Emeritus maintainers retain historical credit but no longer have write access.

---

## RFC Process

Significant changes — new detection patterns, protocol support, breaking
config changes, compliance profiles — require a Request for Comments (RFC).

### When an RFC is Required

- Adding a new crate dependency
- Changes to the 30 default rules (SPEC.md §14)
- New response headers or changes to existing header semantics
- Changes to the database schema
- New config keys that affect security properties (fail-closed, depth limits)
- Any change to normalization behavior (SPEC.md §9 D8)
- New compliance profiles (HIPAA, PCI-DSS variants, etc.)

### RFC Lifecycle

1. **Draft**: Open a GitHub Discussion in the `RFC` category. Use the
   template in `.github/ISSUE_TEMPLATE/feature_request.yml`.
2. **Comment period**: Minimum 7 days open for community feedback.
3. **Maintainer review**: At least 2 maintainer approvals required.
4. **Implementation**: Link the RFC discussion in the PR description.
5. **Merge**: RFC is marked "Accepted" in the discussion.

### Expedited Process (Security)

Security fixes bypass the RFC process. Follow [SECURITY.md](SECURITY.md)
for responsible disclosure and the coordinated-release process.

---

## Decision Making

- **Day-to-day** (bug fixes, documentation, test improvements): One
  maintainer approval is sufficient.
- **Features and enhancements**: Two maintainer approvals required.
- **RFC-gated changes**: RFC acceptance + two maintainer approvals.
- **Governance changes** (this document): Three maintainer approvals +
  14-day comment period.
- **Breaking changes**: Require a minor or major version bump per SemVer
  and a CHANGELOG entry.

Decisions are made by lazy consensus: if no maintainer objects within the
review window, silence is approval.

---

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding
standards, and the PR process.

---

## Code of Conduct

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1). Violations may be
reported privately to the maintainers as described there. Reports are handled confidentially.

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process,
response SLAs, and safe harbor statement.

---

## Contact

- **General**: GitHub Discussions
- **Security**: [private vulnerability report](https://github.com/revoc-ai/revoc/security/advisories/new)
- **Enterprise**: GitHub Discussions
- **Website**: https://revoc.io
