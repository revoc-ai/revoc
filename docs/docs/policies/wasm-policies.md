# WASM Policies

REVOC supports evaluating Rego policies compiled to WebAssembly using Wasmtime.
This enables air-gapped deployments where an OPA sidecar process is undesirable,
while still supporting the full Rego policy language.

## When to Use WASM Policies

Use WASM when:
- Your environment cannot run an OPA sidecar (air-gapped, strict process isolation)
- You want OPA-compatible Rego policies without the sidecar operational overhead
- You need hot-reload of policies without restarting the proxy

Use the native engine when:
- Your workload is latency-sensitive (native engine: > 500K evaluations/s vs WASM: ~50K/s)
- You only need the 30 built-in rules and simple custom rules

Use the OPA sidecar when:
- Your organization already operates OPA infrastructure
- You need OPA's full feature set (data documents, external data, bundle server)

## Configuration

```toml
[policy]
engine = "wasm"
wasm_bundle_path = "/etc/revoc/policy.wasm"
```

## Building a WASM Bundle

```bash
# Install OPA CLI
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa

# Compile policies directory to WASM bundle
opa build -t wasm -e revoc/main/allow -e revoc/main/deny policies/

# Output: bundle.tar.gz containing policy.wasm
tar -xf bundle.tar.gz policy.wasm
cp policy.wasm /etc/revoc/policy.wasm
```

## Policy Structure

REVOC's Rego policies follow this structure:

```rego
package revoc.main

import rego.v1

# Allow is the default — deny rules override
default allow := true

deny contains decision if {
    input.request_type == "LLM_REQUEST"
    some finding in input.findings
    finding.finding_type == "SECRET_EXPOSURE"
    decision := {
        "action": "block",
        "reason": "Secret detected in LLM request",
        "rule_id": "secret_block_v1",
        "tier": "security",
    }
}
```

The `input` document corresponds to `PolicyInput` serialized as JSON.

## Hot Reloading

The WASM bundle is reloaded without proxy restart:

```bash
# Update the bundle file, then signal reload
curl -s -X POST http://localhost:8081/internal/policies/reload \
  -H "X-Admin-Key: $REVOC_ADMIN_KEY"
```

## Performance

| Engine | Evaluation throughput |
|---|---|
| Native | > 500K evaluations/s |
| WASM | ~50K evaluations/s |
| OPA HTTP sidecar | ~10K evaluations/s (network RTT bound) |

Decision caching (`decision_cache_ttl_secs`) applies to all three engines and
significantly reduces the performance difference at production request rates.
