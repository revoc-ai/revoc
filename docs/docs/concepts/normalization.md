# Unicode Normalization

REVOC applies four-step text normalization to every field before any regex pattern runs.
This is non-negotiable (Principle 5): detection without normalization can be trivially bypassed.

## Why It Is Necessary

Attackers can encode the same text in Unicode in ways that look identical on screen but
produce different byte sequences. A naive regex for `DROP TABLE` will miss `ＤＲＯＰTable`
even though they are visually the same string.

REVOC normalizes every text field to a canonical form before scanning, then sets
`finding.was_normalized = true` when the normalized form differs from the original.
This is surfaced in the audit log and dashboard so you can see exactly what evasion technique
was attempted.

## The Four Normalization Steps

All four steps are applied in sequence in `revoc-detector/src/normalization.rs`:

### Step 1 — NFKC Normalization

Converts Unicode compatibility variants to their canonical equivalents:

| Input | After NFKC |
|---|---|
| `ＤＲＯＰTable` (fullwidth ASCII) | `DROPTable` |
| `ﬁle` (fi ligature) | `file` |
| `²` (superscript 2) | `2` |
| `ℌ` (script H) | `H` |

### Step 2 — Zero-Width Character Removal

Removes seven invisible characters that can be inserted between letters to break regex matching:

| Code Point | Name |
|---|---|
| `U+200B` | Zero Width Space |
| `U+200C` | Zero Width Non-Joiner |
| `U+200D` | Zero Width Joiner |
| `U+FEFF` | Zero Width No-Break Space (BOM) |
| `U+00AD` | Soft Hyphen |
| `U+2060` | Word Joiner |
| `U+180E` | Mongolian Vowel Separator |

Example: `D​R​O​P` with zero-width spaces between every letter → `DROP` after removal.

### Step 3 — RTLO / BIDI Override Removal

Removes nine bidirectional control characters. These can reverse text display direction
on screen while keeping the original byte order, making `gpord` display as `drop`:

| Code Points |
|---|
| `U+202E` (Right-to-Left Override), `U+202D` (Left-to-Right Override) |
| `U+202A` (Left-to-Right Embedding), `U+202B` (Right-to-Left Embedding) |
| `U+202C` (Pop Directional Formatting) |
| `U+2066` `U+2067` `U+2068` `U+2069` (Directional Isolates) |

### Step 4 — Non-Printable Control Character Removal

Strips remaining control characters (C0/C1 range) while preserving the three characters
that appear legitimately in text content:

- `\n` (newline) — preserved
- `\r` (carriage return) — preserved
- `\t` (tab) — preserved

## Attack Examples

### Example 1 — Fullwidth ASCII

```
Attack input:  ＤＲＯＰTable users
After NFKC:    DROP TABLE users
Detection:     sec_ddl_mutation_v1 fires ✅
```

### Example 2 — Zero-Width Injection

```
Attack input:  D​R​O​P T​A​B​L​E users  (ZWSPs between every char)
After ZW removal: DROP TABLE users
Detection:     sec_ddl_mutation_v1 fires ✅
```

### Example 3 — RTLO Reversal

```
Attack input:  gpord elbat (with U+202E at start — displays as "drop table")
After BIDI removal + NFKC: gpord elbat (inert text, not a DDL keyword)
Result:        No false positive — the actual bytes were never DDL ✅
```

### Example 4 — Mixed Encoding Chaining

```
Attack input:  sk‌-ant‌-api...  (ZWNJs inserted in Anthropic key pattern)
After ZW removal: sk-ant-api...
Detection:     secret_anthropic_key_v1 fires ✅
```

## The `was_normalized` Flag

When `normalize(text).was_modified == true`, every `Finding` produced from that field
carries `was_normalized: true`. This field is stored in the audit log and exposed in
the dashboard trace view.

```json
{
  "finding_type": "DDL_MUTATION",
  "severity": "CRITICAL",
  "was_normalized": true,
  "was_encoded": false,
  "detection_tier": "REGEX"
}
```

The flag does not change the decision — the finding is treated identically regardless.
It is recorded so security teams can identify evasion attempts in the audit log.

## Idempotency Guarantee

`normalize(normalize(x)).text == normalize(x).text` — normalization is always idempotent.
Running it twice produces the same result as running it once. This is tested in
`revoc-detector/src/tests/normalization_tests.rs`.

## Configuration

Normalization is always enabled. It cannot be disabled:

```toml
[detection]
normalize_before_scan = true   # default: true — changing to false is not supported
```

The configuration key exists for forward compatibility. The detection engine ignores
a `false` value and normalizes regardless.
