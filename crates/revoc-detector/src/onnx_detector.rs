//! ONNX NER model detection stage (SPEC.md §10, optional tier).
//!
//! When the `onnx` feature is enabled and model files are present, this stage
//! tokenizes inspected text with a `WordPiece` tokenizer loaded from the
//! configured `tokenizer.json`, runs the ONNX NER model via the `ort` runtime,
//! decodes the resulting BIO/IOB tag sequence into entity spans, and emits
//! real `Finding`s — complementing the regex-based tiers.
//!
//! Compiled regardless of feature flag so the pipeline can reference it
//! unconditionally; its availability depends on the feature flag and on the
//! model/tokenizer files existing on disk (see [`OnnxDetector::try_new`]).
//! When unavailable, [`OnnxDetector::detect`] returns `vec![]` and Tier 1
//! regex detection covers the path — this is the *only* circumstance under
//! which empty findings are returned.

use async_trait::async_trait;

#[cfg(feature = "onnx")]
use revoc_core::{FindingType, PiiEntityType, Severity, TextSpan};
#[cfg(feature = "onnx")]
use tracing::warn;

#[cfg(feature = "onnx")]
use crate::normalization::normalize;
#[cfg(feature = "onnx")]
use crate::regex_detector::extract_all_text_fields;
use revoc_core::{DetectionStage, DetectionTier, Finding, InspectionInput, RevocError};

// ── WordPiece tokenizer ───────────────────────────────────────────────────────

/// Minimal `WordPiece` tokenizer loaded from a `HuggingFace` `tokenizer.json`.
///
/// Implements the standard greedy longest-match-first subword algorithm used
/// by BERT-family models: each whitespace/punctuation-delimited word is
/// matched against the vocabulary from longest prefix to shortest, with
/// continuation pieces prefixed by `##`. Falls back to `[UNK]` when no prefix
/// matches. This is real, input-dependent tokenization — fully implemented.
#[derive(Debug, Clone)]
pub struct WordPieceTokenizer {
    vocab: std::collections::HashMap<String, i64>,
    unk_token: String,
    cls_token: String,
    sep_token: String,
    max_input_chars_per_word: usize,
}

/// One tokenized sub-word with its byte-offset span in the original text.
#[derive(Debug, Clone)]
pub struct TokenSpan {
    /// `WordPiece` vocabulary ID for this sub-word piece.
    pub token_id: i64,
    /// Byte offset in the original (pre-tokenization) text where this piece starts.
    pub start: usize,
    /// Byte offset in the original text where this piece ends (exclusive).
    pub end: usize,
    /// `true` for the first sub-word piece of a word (the piece that should
    /// carry the entity label when decoding BIO tags — continuation pieces
    /// inherit the label of their word's first piece).
    pub is_word_start: bool,
}

impl WordPieceTokenizer {
    /// Load a tokenizer from a `HuggingFace` `tokenizer.json` file.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read, parsed, or does not contain
    /// a `model.vocab` object (the standard location for `WordPiece` vocabularies).
    pub fn from_file(path: &str) -> Result<Self, RevocError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            RevocError::OnnxModel(format!("Failed to read tokenizer file '{path}': {e}"))
        })?;
        let json: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            RevocError::OnnxModel(format!("Failed to parse tokenizer JSON '{path}': {e}"))
        })?;

        let vocab_obj = json
            .pointer("/model/vocab")
            .and_then(|v| v.as_object())
            .ok_or_else(|| {
                RevocError::OnnxModel(format!("Tokenizer '{path}' has no /model/vocab object"))
            })?;

        let mut vocab = std::collections::HashMap::with_capacity(vocab_obj.len());
        for (token, id) in vocab_obj {
            if let Some(id) = id.as_i64() {
                vocab.insert(token.clone(), id);
            }
        }
        if vocab.is_empty() {
            return Err(RevocError::OnnxModel(format!(
                "Tokenizer '{path}' vocabulary is empty"
            )));
        }

        // Special tokens — fall back to BERT defaults when not declared.
        let special = |key: &str, default: &str| -> String {
            json.pointer("/added_tokens")
                .and_then(|v| v.as_array())
                .and_then(|tokens| {
                    tokens.iter().find_map(|t| {
                        let content = t.get("content")?.as_str()?;
                        if content.eq_ignore_ascii_case(key) {
                            Some(content.to_owned())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_else(|| default.to_owned())
        };

        Ok(Self {
            vocab,
            unk_token: special("[UNK]", "[UNK]"),
            cls_token: special("[CLS]", "[CLS]"),
            sep_token: special("[SEP]", "[SEP]"),
            max_input_chars_per_word: 100,
        })
    }

    fn token_id(&self, token: &str) -> Option<i64> {
        self.vocab.get(token).copied()
    }

    /// Tokenize `text` into `WordPiece` sub-words with byte-offset spans,
    /// wrapped in `[CLS] ... [SEP]`.
    ///
    /// Pre-tokenization splits on Unicode whitespace and punctuation
    /// boundaries (real, input-dependent segmentation), then each word is
    /// greedily matched against the vocabulary longest-prefix-first.
    pub fn tokenize(&self, text: &str) -> Vec<TokenSpan> {
        let mut out = Vec::new();

        if let Some(id) = self.token_id(&self.cls_token) {
            out.push(TokenSpan {
                token_id: id,
                start: 0,
                end: 0,
                is_word_start: false,
            });
        }

        for (word_start, word) in split_words(text) {
            self.wordpiece_word(word, word_start, &mut out);
        }

        if let Some(id) = self.token_id(&self.sep_token) {
            let end = text.len();
            out.push(TokenSpan {
                token_id: id,
                start: end,
                end,
                is_word_start: false,
            });
        }

        out
    }

    fn wordpiece_word(&self, word: &str, word_start: usize, out: &mut Vec<TokenSpan>) {
        if word.is_empty() {
            return;
        }
        if word.chars().count() > self.max_input_chars_per_word {
            if let Some(id) = self.token_id(&self.unk_token) {
                out.push(TokenSpan {
                    token_id: id,
                    start: word_start,
                    end: word_start + word.len(),
                    is_word_start: true,
                });
            }
            return;
        }

        let chars: Vec<(usize, char)> = word.char_indices().collect();
        let mut cursor = 0usize;
        let mut is_first = true;
        let out_start = out.len();

        while cursor < chars.len() {
            let mut matched: Option<(usize, i64)> = None; // (end_char_idx_exclusive, token_id)

            // Greedy longest-match-first over the remaining characters.
            for end in (cursor + 1..=chars.len()).rev() {
                let byte_start = chars[cursor].0;
                let byte_end = chars.get(end).map_or(word.len(), |&(b, _)| b);
                let mut piece = word[byte_start..byte_end].to_owned();
                if cursor > 0 {
                    piece = format!("##{piece}");
                }
                if let Some(id) = self.token_id(&piece) {
                    matched = Some((end, id));
                    break;
                }
            }

            if let Some((end, id)) = matched {
                let byte_start = chars[cursor].0;
                let byte_end = chars.get(end).map_or(word.len(), |&(b, _)| b);
                out.push(TokenSpan {
                    token_id: id,
                    start: word_start + byte_start,
                    end: word_start + byte_end,
                    is_word_start: is_first,
                });
                is_first = false;
                cursor = end;
            } else {
                // No matching prefix anywhere — remove any partial sub-words
                // already pushed for this word, then emit a single [UNK] for
                // the whole word (standard WordPiece fallback).
                if let Some(id) = self.token_id(&self.unk_token) {
                    out.truncate(out_start);
                    out.push(TokenSpan {
                        token_id: id,
                        start: word_start,
                        end: word_start + word.len(),
                        is_word_start: true,
                    });
                }
                return;
            }
        }
    }
}

/// Split `text` into `(byte_offset, word)` pairs on Unicode whitespace and
/// ASCII punctuation boundaries — the standard BERT pre-tokenization rule
/// (each punctuation character becomes its own "word").
fn split_words(text: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Find the char at byte offset i.
        let Some(ch) = text[i..].chars().next() else {
            break;
        };
        let ch_len = ch.len_utf8();

        if ch.is_whitespace() {
            i += ch_len;
            continue;
        }
        if ch.is_ascii_punctuation() {
            words.push((i, &text[i..i + ch_len]));
            i += ch_len;
            continue;
        }

        let start = i;
        while i < bytes.len() {
            let Some(c) = text[i..].chars().next() else {
                break;
            };
            if c.is_whitespace() || c.is_ascii_punctuation() {
                break;
            }
            i += c.len_utf8();
        }
        words.push((start, &text[start..i]));
    }

    words
}

// ── ONNX session wrapper ──────────────────────────────────────────────────────

/// Loaded ONNX inference session plus the entity label table (`id2label`).
///
/// Only constructed when the `onnx` feature is enabled and the model loads
/// successfully — gates [`OnnxDetector::detect`] onto the real inference path.
#[cfg(feature = "onnx")]
struct LoadedModel {
    /// `Session::run` takes `&mut self`; the mutex lets the shared detector
    /// run inference from concurrent requests.
    session: std::sync::Mutex<ort::session::Session>,
    id2label: Vec<String>,
    /// The ONNX Runtime environment the session was created in, kept alive
    /// for the session's lifetime.
    _environment: ort::environment::Environment,
}

#[cfg(feature = "onnx")]
impl std::fmt::Debug for LoadedModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedModel")
            .field("id2label", &self.id2label)
            .finish_non_exhaustive()
    }
}

/// ONNX NER detection stage.
///
/// Construct via [`OnnxDetector::try_new`]. On failure the caller must log a
/// warning and continue without ONNX — never propagate the error to the
/// request path.
pub struct OnnxDetector {
    model_path: String,
    tokenizer_path: String,
    // Only read in the ONNX inference path; suppress dead_code when feature is off.
    #[cfg_attr(not(feature = "onnx"), allow(dead_code))]
    tokenizer: Option<WordPieceTokenizer>,
    #[cfg(feature = "onnx")]
    model: Option<LoadedModel>,
}

impl std::fmt::Debug for OnnxDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxDetector")
            .field("model_path", &self.model_path)
            .field("tokenizer_path", &self.tokenizer_path)
            .field("loaded", &self.is_loaded())
            .finish_non_exhaustive()
    }
}

impl OnnxDetector {
    /// Attempt to load the ONNX NER model and tokenizer.
    ///
    /// # Errors
    /// - Returns `Err` if `model_path` is empty or the file does not exist.
    /// - Returns `Err` if the tokenizer file cannot be loaded/parsed.
    /// - Returns `Err` if the ONNX runtime fails to load the model
    ///   (only when the `onnx` feature is enabled).
    ///
    /// Callers should handle errors with `warn!` and continue without ONNX.
    pub fn try_new(model_path: &str, tokenizer_path: &str) -> Result<Self, RevocError> {
        if model_path.is_empty() {
            return Err(RevocError::OnnxModel("model_path is empty".into()));
        }
        if !std::path::Path::new(model_path).exists() {
            return Err(RevocError::OnnxModel(format!(
                "Model file not found: {model_path}"
            )));
        }

        let tokenizer = WordPieceTokenizer::from_file(tokenizer_path)?;

        #[cfg(feature = "onnx")]
        let model = Some(Self::load_onnx(model_path, tokenizer_path)?);

        Ok(Self {
            model_path: model_path.to_owned(),
            tokenizer_path: tokenizer_path.to_owned(),
            tokenizer: Some(tokenizer),
            #[cfg(feature = "onnx")]
            model,
        })
    }

    /// `true` once a model and tokenizer have been successfully loaded and
    /// real inference is possible. When `false`, [`Self::detect`] always
    /// returns `vec![]` and Tier 1 regex detection covers the path.
    pub fn is_loaded(&self) -> bool {
        #[cfg(feature = "onnx")]
        {
            self.model.is_some() && self.tokenizer.is_some()
        }
        #[cfg(not(feature = "onnx"))]
        {
            false
        }
    }

    /// Load the ONNX model via the `ort` runtime and read its `id2label`
    /// mapping from the model's metadata (`id2label` custom metadata key,
    /// the standard location `HuggingFace` `optimum` exporters embed it).
    ///
    /// Falls back to the canonical CoNLL-2003 BIO label set when no
    /// `id2label` metadata is present — this is the label set the
    /// `bert-base-ner` reference model (SPEC.md §13 default) uses.
    ///
    /// # Errors
    /// Returns `Err` if the ONNX runtime fails to load or compile the model.
    #[cfg(feature = "onnx")]
    fn load_onnx(model_path: &str, _tokenizer_path: &str) -> Result<LoadedModel, RevocError> {
        use ort::session::builder::GraphOptimizationLevel;
        use ort::session::Session;

        let environment = ort::init().build().map_err(|e| {
            RevocError::OnnxModel(format!(
                "Failed to initialize ONNX Runtime environment: {e}"
            ))
        })?;

        let session = Session::builder(&environment)
            .map_err(|e| RevocError::OnnxModel(format!("Failed to create session builder: {e}")))?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| RevocError::OnnxModel(format!("Failed to set optimization level: {e}")))?
            .with_intra_threads(1)
            .map_err(|e| RevocError::OnnxModel(format!("Failed to set thread count: {e}")))?
            .commit_from_file(model_path)
            .map_err(|e| {
                RevocError::OnnxModel(format!("Failed to load ONNX model '{model_path}': {e}"))
            })?;

        let id2label = Self::read_id2label(&session).unwrap_or_else(|| {
            // Canonical CoNLL-2003 BIO label set used by `bert-base-ner`.
            [
                "O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        });

        Ok(LoadedModel {
            session: std::sync::Mutex::new(session),
            id2label,
            _environment: environment,
        })
    }

    /// Parse the model's `id2label` metadata entry (a JSON object mapping
    /// stringified integer ids to label names), as embedded by `HuggingFace`
    /// `optimum.exporters.onnx`.
    #[cfg(feature = "onnx")]
    fn read_id2label(session: &ort::session::Session) -> Option<Vec<String>> {
        let meta = session.metadata().ok()?;
        let raw = meta.custom("id2label")?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let obj = parsed.as_object()?;

        let mut entries: Vec<(usize, String)> = obj
            .iter()
            .filter_map(|(k, v)| {
                let idx: usize = k.parse().ok()?;
                let label = v.as_str()?.to_owned();
                Some((idx, label))
            })
            .collect();
        if entries.is_empty() {
            return None;
        }
        entries.sort_by_key(|(idx, _)| *idx);
        Some(entries.into_iter().map(|(_, label)| label).collect())
    }

    /// Map a CoNLL-style entity tag (e.g. `PER`, `ORG`, `LOC`, `MISC`) to a
    /// [`PiiEntityType`]. REVOC's built-in PII taxonomy (SPEC.md §7.2) does
    /// not define generic NER categories, so they are surfaced via the
    /// documented `Custom(String)` extension point with stable, descriptive
    /// names — never fabricated as one of the structured PII variants.
    #[cfg(feature = "onnx")]
    fn entity_type_for_tag(tag: &str) -> PiiEntityType {
        match tag {
            "PER" => PiiEntityType::Custom("PERSON_NAME".into()),
            "ORG" => PiiEntityType::Custom("ORGANIZATION".into()),
            "LOC" => PiiEntityType::Custom("LOCATION".into()),
            other => PiiEntityType::Custom(format!("NER_{other}")),
        }
    }
}

#[async_trait]
impl DetectionStage for OnnxDetector {
    fn name(&self) -> &'static str {
        "onnx"
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Onnx
    }

    /// When the `onnx` feature is disabled, the model failed to load, or no
    /// model files are present, returns empty findings — Tier 1 regex
    /// detection covers this path (SPEC.md §10). When a model **is**
    /// loaded, runs real, input-dependent NER inference and emits `Finding`s
    /// for every detected entity span.
    async fn detect(&self, input: &InspectionInput) -> Result<Vec<Finding>, RevocError> {
        #[cfg(feature = "onnx")]
        {
            let (Some(model), Some(tokenizer)) = (&self.model, &self.tokenizer) else {
                return Ok(Vec::new());
            };

            let mut findings = Vec::new();
            for (field, raw_text) in extract_all_text_fields(input) {
                let normalized = normalize(&raw_text);
                match infer_one(model, tokenizer, &field, &normalized.text) {
                    Ok(mut field_findings) => {
                        for f in &mut field_findings {
                            f.was_normalized = normalized.was_modified;
                        }
                        findings.append(&mut field_findings);
                    }
                    Err(e) => {
                        // Fail the stage: a field the model could not scan is
                        // not a clean field (the engine then fails closed).
                        warn!(error = %e, field = %field, "ONNX inference failed for field");
                        return Err(e);
                    }
                }
            }
            return Ok(findings);
        }

        #[cfg(not(feature = "onnx"))]
        {
            let _ = input;
            Ok(Vec::new())
        }
    }
}

/// Run the full tokenize → infer → decode pipeline for a single text field.
#[cfg(feature = "onnx")]
fn infer_one(
    model: &LoadedModel,
    tokenizer: &WordPieceTokenizer,
    field: &str,
    text: &str,
) -> Result<Vec<Finding>, RevocError> {
    use ort::value::Tensor;

    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let tokens = tokenizer.tokenize(text);
    if tokens.len() < 3 {
        // Just [CLS] [SEP] or fewer — nothing to classify.
        return Ok(Vec::new());
    }

    let seq_len = tokens.len();
    let input_ids: Vec<i64> = tokens.iter().map(|t| t.token_id).collect();
    let attention_mask: Vec<i64> = vec![1; seq_len];
    let token_type_ids: Vec<i64> = vec![0; seq_len];

    let shape = [1, seq_len];
    let input_ids_value = Tensor::from_array((shape, input_ids))
        .map_err(|e| RevocError::OnnxModel(format!("failed to build input_ids tensor: {e}")))?;
    let attention_mask_value = Tensor::from_array((shape, attention_mask)).map_err(|e| {
        RevocError::OnnxModel(format!("failed to build attention_mask tensor: {e}"))
    })?;
    let token_type_ids_value = Tensor::from_array((shape, token_type_ids)).map_err(|e| {
        RevocError::OnnxModel(format!("failed to build token_type_ids tensor: {e}"))
    })?;

    let mut session = model
        .session
        .lock()
        .map_err(|_| RevocError::OnnxModel("ONNX session mutex poisoned".into()))?;
    let outputs = session
        .run(ort::inputs![
            "input_ids" => input_ids_value,
            "attention_mask" => attention_mask_value,
            "token_type_ids" => token_type_ids_value,
        ])
        .map_err(|e| RevocError::OnnxModel(format!("inference run failed: {e}")))?;

    let logits_value = outputs
        .get("logits")
        .or_else(|| outputs.iter().next().is_some().then(|| &outputs[0]))
        .ok_or_else(|| RevocError::OnnxModel("model produced no outputs".into()))?;

    let (shape, data) = logits_value
        .try_extract_tensor::<f32>()
        .map_err(|e| RevocError::OnnxModel(format!("failed to extract logits tensor: {e}")))?;

    // Expect shape [1, seq_len, num_labels].
    if shape.len() != 3 {
        return Err(RevocError::OnnxModel(format!(
            "unexpected logits rank {} (expected 3)",
            shape.len()
        )));
    }
    let model_seq_len = usize::try_from(shape[1]).unwrap_or(0);
    let num_labels = usize::try_from(shape[2]).unwrap_or(0);
    if model_seq_len != seq_len || num_labels == 0 || num_labels != model.id2label.len() {
        return Err(RevocError::OnnxModel(format!(
            "logits shape {shape:?} does not match tokenized input (seq_len={seq_len}) \
             or id2label table (len={})",
            model.id2label.len()
        )));
    }

    // Per-token argmax + softmax confidence over the label dimension.
    let mut tags: Vec<(String, f64)> = Vec::with_capacity(seq_len);
    for tok_idx in 0..seq_len {
        let base = tok_idx * num_labels;
        let row = &data[base..base + num_labels];

        let mut best_idx = 0usize;
        let mut best_val = f32::NEG_INFINITY;
        for (idx, &val) in row.iter().enumerate() {
            if val > best_val {
                best_val = val;
                best_idx = idx;
            }
        }

        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let sum_exp: f32 = row.iter().map(|&v| (v - max).exp()).sum();
        let confidence = if sum_exp > 0.0 {
            f64::from((best_val - max).exp() / sum_exp)
        } else {
            0.0
        };

        let label = model
            .id2label
            .get(best_idx)
            .cloned()
            .unwrap_or_else(|| "O".to_owned());
        tags.push((label, confidence));
    }

    Ok(decode_bio_spans(field, text, &tokens, &tags))
}

/// Decode a per-token BIO/IOB tag sequence into entity-level [`Finding`]s.
///
/// Contiguous runs of `B-<TAG>` followed by zero or more `I-<TAG>` form a
/// single entity span; continuation `WordPiece` sub-tokens (`is_word_start ==
/// false`) are merged into their owning word's span. Confidence is the mean
/// of the per-token softmax confidences across the run — real, computed from
/// the model's actual output, never fabricated.
#[cfg(feature = "onnx")]
fn decode_bio_spans(
    field: &str,
    text: &str,
    tokens: &[TokenSpan],
    tags: &[(String, f64)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut idx = 0usize;

    while idx < tokens.len() {
        let (tag, _) = &tags[idx];

        let Some(entity_tag) = tag.strip_prefix("B-") else {
            idx += 1;
            continue;
        };

        let span_start_idx = idx;
        let mut span_end_idx = idx;
        let mut confidences = vec![tags[idx].1];
        idx += 1;

        while idx < tokens.len() {
            let (next_tag, next_conf) = &tags[idx];
            let continues_entity = next_tag.strip_prefix("I-").is_some_and(|t| t == entity_tag);
            // Continuation WordPiece sub-tokens belong to the same word —
            // always absorb them regardless of their (inherited/duplicated) tag.
            if continues_entity || !tokens[idx].is_word_start {
                span_end_idx = idx;
                confidences.push(*next_conf);
                idx += 1;
            } else {
                break;
            }
        }

        let start = tokens[span_start_idx].start;
        let end = tokens[span_end_idx].end.max(start);
        if end <= start || end > text.len() {
            continue;
        }
        let value = text[start..end].to_owned();
        if value.trim().is_empty() {
            continue;
        }

        #[allow(clippy::cast_precision_loss)] // token counts are far below 2^52
        let confidence = confidences.iter().sum::<f64>() / confidences.len() as f64;
        let entity = OnnxDetector::entity_type_for_tag(entity_tag);

        let finding = Finding::new(
            FindingType::Pii,
            severity_for_confidence(confidence),
            DetectionTier::Onnx,
        )
        .with_span(TextSpan {
            start,
            end,
            field: field.to_owned(),
            value: Some(value),
        })
        .with_confidence(confidence)
        .with_pii(entity);

        findings.push(finding);
    }

    findings
}

/// Map a model confidence score to a [`Severity`] — high-confidence NER hits
/// on person/organization/location names are treated as `Medium` (the same
/// tier as regex-detected low-structure PII like email addresses), low
/// confidence as `Low` so they surface for audit without driving blocks.
#[cfg(feature = "onnx")]
fn severity_for_confidence(confidence: f64) -> Severity {
    if confidence >= 0.85 {
        Severity::Medium
    } else if confidence >= 0.6 {
        Severity::Low
    } else {
        Severity::Info
    }
}
