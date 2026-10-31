<!--
Thanks for contributing to REVOC! Please fill out this template completely.
PRs that skip sections relevant to their change may be asked to add them before review.
-->

## Summary

<!-- What does this PR change, and why? Link related issues with "Fixes #123" / "Refs #123". -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Detection pattern / policy rule addition or change
- [ ] Performance improvement
- [ ] Documentation only
- [ ] CI/CD, build, or tooling

## Non-negotiable principles checklist (SPEC.md Section 3)

<!-- Check every box that applies to your change. If a box doesn't apply, leave it unchecked and say so below. -->

- [ ] No governance code was added to application code — the proxy remains 100% out-of-band
- [ ] No new external HTTP calls were introduced into the Tier 1/Tier 2 detection hot path
- [ ] All new text fields are normalized (`normalization::normalize()`) before any regex pass (Rule D8)
- [ ] Governance depth is still checked/propagated correctly — max depth remains 10 (Rule D9)
- [ ] `fail_open` remains `false` in every committed config
- [ ] Upstream 4xx/5xx responses are still forwarded verbatim, never wrapped in `RevocErrorResponse`
- [ ] No PII or secret values are logged, stored, or serialized — only entity type + field + position
- [ ] `X-Revoc-Dashboard` and `X-Revoc-Timing` headers are still set on every response
- [ ] Tier 3 security rules cannot be overridden by custom/profile rules (Rule D12)
- [ ] No `unsafe` code was introduced (`#![forbid(unsafe_code)]`)

## Zero-incomplete-code checklist (SPEC.md Section 23, Rule 6)

- [ ] No `TODO`, `FIXME`, `HACK`, `XXX`, "implement later", "stub", "placeholder", or "Phase N" comments were added
- [ ] No `unwrap()`/`expect()`/`panic!()`/`unimplemented!()`/`todo!()` outside `#[cfg(test)]`
- [ ] No function returns empty/synthetic/fabricated data where real computation is required
- [ ] I ran: `grep -rn "TODO\|stub\|placeholder\|simplified\|Phase [0-9]\|unimplemented\|todo!()\|panic!()" <changed paths>` and it returned nothing new

## Testing

<!-- How was this tested? Include commands run and their output/coverage where relevant. -->

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] Admin API: `ruff check . && mypy app/ --strict && pytest tests/ --cov-fail-under=85` passes (if `admin-api/` touched)
- [ ] `opa check policies/ --strict && opa test policies/ -v --coverage` passes (if `policies/` touched)
- [ ] `helm lint helm/revoc/` passes (if `helm/` touched)
- [ ] New behavior is covered by unit/integration tests (list them below)

<!-- List new/changed test files and what they cover -->

## Performance impact

<!--
If this touches the detection or proxy hot path, note the expected impact relative to the targets in
SPEC.md Section 19 (e.g. P95 proxy overhead < 10ms, regex throughput > 100K req/s). Attach `cargo bench`
output if you changed anything in revoc-detector, revoc-pipeline, revoc-policy, or revoc-proxy handlers.
-->

- [ ] No measurable impact on documented performance targets
- [ ] Benchmarked — results attached below
- [ ] N/A (docs/tooling/test-only change)

## Screenshots / dashboard traces (if applicable)

<!-- For dashboard/UI changes, include before/after screenshots. For proxy/policy changes, a redacted X-Revoc-Trace-ID/dashboard link is helpful. -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] My commits follow the project's commit message conventions
- [ ] I have updated relevant documentation (`docs/`, `README.md`, `CHANGELOG.md`) where needed
- [ ] I have not committed secrets, API keys, or real PII anywhere in this change
