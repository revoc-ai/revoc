#!/usr/bin/env bash
# Download and export the BERT NER ONNX model for REVOC.
#
# Prerequisites:
#   pip install optimum[exporters] transformers torch
#
# Output:
#   models/bert-base-ner.onnx            (~430 MB)
#   models/bert-base-ner-tokenizer.json  (~1 MB)
#
# Usage:
#   bash models/download.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$SCRIPT_DIR"
MODEL_ID="dslim/bert-base-NER"
ONNX_FILE="$MODEL_DIR/bert-base-ner.onnx"
TOKENIZER_FILE="$MODEL_DIR/bert-base-ner-tokenizer.json"

echo "REVOC ONNX model downloader"
echo "Model: $MODEL_ID"
echo "Output directory: $MODEL_DIR"
echo ""

# Verify prerequisites
if ! python3 -c "import optimum" 2>/dev/null; then
    echo "ERROR: optimum not installed."
    echo "Install with: pip install 'optimum[exporters]' transformers torch"
    exit 1
fi

if [ -f "$ONNX_FILE" ] && [ -f "$TOKENIZER_FILE" ]; then
    echo "Model files already present:"
    echo "  $ONNX_FILE"
    echo "  $TOKENIZER_FILE"
    echo "Delete them to re-download."
    exit 0
fi

echo "Exporting $MODEL_ID to ONNX..."
EXPORT_DIR="$(mktemp -d)"
trap "rm -rf $EXPORT_DIR" EXIT

optimum-cli export onnx \
    --model "$MODEL_ID" \
    --task token-classification \
    --framework pt \
    "$EXPORT_DIR"

echo "Copying model files..."
cp "$EXPORT_DIR/model.onnx" "$ONNX_FILE"
cp "$EXPORT_DIR/tokenizer.json" "$TOKENIZER_FILE"

echo ""
echo "Done."
echo "  ONNX model: $ONNX_FILE ($(du -sh "$ONNX_FILE" | cut -f1))"
echo "  Tokenizer:  $TOKENIZER_FILE"
echo ""
echo "Enable in revoc.toml:"
echo "  [detection]"
echo "  onnx_enabled = true"
echo "  onnx_model_path = \"models/bert-base-ner.onnx\""
echo "  onnx_tokenizer_path = \"models/bert-base-ner-tokenizer.json\""
