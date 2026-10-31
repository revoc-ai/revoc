"""tests/test_compiler.py — 5 PolicyCompilerService unit tests."""

from __future__ import annotations

import subprocess

import pytest

from app.services.compiler_service import PolicyCompilerService

_svc = PolicyCompilerService()

# ── helpers ───────────────────────────────────────────────────────────────────

def _opa_available() -> bool:
    try:
        result = subprocess.run(
            ["opa", "version"], capture_output=True, timeout=5, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    else:
        return result.returncode == 0


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pii_pattern_generates_violations_rego() -> None:
    """A valid YAML with model_restrictions should produce violations Rego."""
    yaml_content = """\
apiVersion: revoc.io/v1
kind: PolicyManifest
metadata:
  name: pii-test
  org_id: acme
spec:
  model_restrictions:
    allowed_models:
      - gpt-4o-mini
"""
    rego, errors = await _svc.compile(yaml_content)
    assert errors == []
    assert "violations contains v" in rego
    assert "custom_model_acl_v1" in rego


@pytest.mark.asyncio
async def test_mcp_acl_generates_correct_rego() -> None:
    """A YAML with token quota should emit a quota violations block."""
    yaml_content = """\
apiVersion: revoc.io/v1
kind: PolicyManifest
metadata:
  name: quota-test
  org_id: acme
spec:
  quotas:
    default:
      tokens_per_request: 2048
"""
    rego, errors = await _svc.compile(yaml_content)
    assert errors == []
    assert "custom_quota_v1" in rego
    assert "2048" in rego


@pytest.mark.asyncio
async def test_profile_generates_import() -> None:
    """A YAML with a profile should reference the profile package in Rego."""
    yaml_content = """\
apiVersion: revoc.io/v1
kind: PolicyManifest
metadata:
  name: profile-test
  org_id: acme
spec:
  profile: hipaa
"""
    rego, errors = await _svc.compile(yaml_content)
    assert errors == []
    assert "hipaa" in rego
    assert "data.revoc.governance.profile" in rego


@pytest.mark.asyncio
async def test_invalid_yaml_returns_errors() -> None:
    """Malformed YAML should return a non-empty error list and empty Rego."""
    rego, errors = await _svc.compile("this: is: : invalid yaml :::")
    assert rego == ""
    assert len(errors) > 0
    assert any("yaml" in e.lower() or "parse" in e.lower() for e in errors)


@pytest.mark.asyncio
async def test_generated_rego_passes_opa_check_if_opa_available() -> None:
    """If OPA is installed, the generated Rego must pass `opa check`."""
    if not _opa_available():
        pytest.skip("OPA not on PATH — skipping static check")

    yaml_content = """\
apiVersion: revoc.io/v1
kind: PolicyManifest
metadata:
  name: opa-check-test
  org_id: acme
spec:
  model_restrictions:
    allowed_models:
      - gpt-4o-mini
  quotas:
    default:
      tokens_per_request: 4096
"""
    rego, errors = await _svc.compile(yaml_content)
    assert errors == [], f"OPA rejected generated Rego: {errors}"
    assert rego != ""
