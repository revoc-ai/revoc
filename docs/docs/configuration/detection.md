# Detection Configuration

The `[detection]` section controls which detection stages are active and how
they are configured. Normalization is always active regardless of settings.

## Core Settings

```toml
[detection]
normalize_before_scan = true       # Always active — cannot be disabled
regex_enabled = true               # Regex patterns for PII, secrets, security, financial
decode_base64_args = true          # Scan base64-decoded content
decode_url_encoded_args = true     # Scan URL-decoded content
```

## ONNX NER (optional)

```toml
[detection]
onnx_enabled = false
onnx_model_path = "models/bert-base-ner.onnx"
onnx_tokenizer_path = "models/bert-base-ner-tokenizer.json"
```

ONNX detection adds span-level named entity recognition (person names, locations).
See the `models/README.md` file in the repository root for download instructions.

When enabled, detection throughput drops from > 100K req/s to ~8K req/s on GPU.
Enable only when your workload requires detecting unstructured proper names.

## Presidio Enricher (optional)

```toml
[detection]
presidio_enabled = false
presidio_url = "http://presidio-analyzer:5001"
```

Routes detection through a Microsoft Presidio analyzer service. Presidio is called
after the regex stage — its findings are merged with regex findings and deduped.

Presidio adds multilingual PII detection. Requires deploying the Presidio analyzer
service separately.

## Detection Timeout

The entire detection pipeline (all stages) has an 8-second timeout enforced by
the proxy handler. If the timeout is exceeded:

- With `fail_open = false` (default): request is blocked
- `fail_open = true` is not supported in production

## Pattern Categories

All patterns are pre-compiled at startup in `revoc-detector/src/patterns/`:

| File | Patterns |
|---|---|
| `pii.rs` | 11 PII entity types — see [PII Rules](../default-rules/pii-rules.md) |
| `secrets.rs` | 10 secret types — see [Secret Rules](../default-rules/secret-rules.md) |
| `security.rs` | 8 threat patterns — see [Security Rules](../default-rules/security-rules.md) |
| `financial.rs` | SWIFT BIC, routing numbers, bank accounts |

## Tuning False Positives

If a specific regex pattern generates false positives for your workload, disable
the corresponding rule via a policy bundle rather than disabling the entire
detection stage:

```yaml
rules:
  - rule_id: pii_ip_address_v1
    enabled: false    # Disable IP masking for this org's policy bundle
```

This keeps all other patterns active while suppressing the specific false positive.
