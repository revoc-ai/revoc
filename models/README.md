# REVOC ONNX Models

This directory holds optional ONNX NER models used by the `onnx_detector` stage.
ONNX detection is disabled by default (`onnx_enabled = false` in `revoc.toml`).
The regex detector covers all 30 default rules without any model files.

Enable ONNX detection for higher recall on unstructured text that resists regex:

```toml
[detection]
onnx_enabled = true
onnx_model_path = "models/bert-base-ner.onnx"
onnx_tokenizer_path = "models/bert-base-ner-tokenizer.json"
```

## Default Model

| File | Size | Source |
|---|---|---|
| `bert-base-ner.onnx` | ~430 MB | Exported from `dslim/bert-base-NER` via Optimum |
| `bert-base-ner-tokenizer.json` | ~1 MB | HuggingFace tokenizer config |

## Download

```bash
# Requires Python 3.12+ and pip
bash models/download.sh
```

The script downloads and exports the model using `optimum-cli`. Total download: ~1.3 GB.
The `.onnx` file in this directory is not tracked by git (see `.gitignore`).

## Supported Entity Types (ONNX)

The ONNX model supplements regex detection with span-level NER for:

- `PER` — Person names (mapped to a custom PII entity in findings)
- `ORG` — Organization names
- `LOC` — Location names
- `MISC` — Miscellaneous named entities

Regex detection covers all financial, credential, and structured PII patterns.
ONNX adds coverage for unstructured name and location entities that lack fixed patterns.

## Performance Impact

| Mode | Throughput |
|---|---|
| Regex only (`onnx_enabled = false`) | > 100K req/s |
| Regex + ONNX (`onnx_enabled = true`) | ~8K req/s (GPU) / ~1.2K req/s (CPU) |

ONNX detection is recommended only when your workload contains free-text fields
where person names or locations must be detected and you have GPU capacity available.
