# PII Rules

!!! note "Authoritative reference"
    The [Rule Catalog](catalog.md) is generated from the code and lists every
    pattern with the decision the engine actually makes. Where this page
    differs from it, the catalog is correct.

REVOC ships with 11 PII detection rules active by default. These rules detect
personally identifiable information in requests and responses and either mask
or remove it before it reaches the LLM or your application.

## Detection Method

PII is detected using compiled regular expressions after NFKC normalization.
For entities with fixed checksums (credit cards, IBANs, routing numbers), the
regex match is followed by a mathematical validation step to eliminate false positives.

## Rule Reference

### `pii_ssn_v1` — US Social Security Number

**Pattern:** `\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`

**Validation:** Regex exclusions eliminate invalid prefixes (000, 666, 9xx area codes).

**Action:** Remove (replaced with `[REDACTED]`)

**Example:** `My SSN is 123-45-6789` → `My SSN is [REDACTED]`

---

### `pii_credit_card_v1` — Credit Card Number

**Pattern:** Combined Visa / MasterCard / Amex / Discover patterns

**Validation:** Luhn algorithm — `luhn_check(digits)` must return `true`

**Action:** Remove (replaced with `[REDACTED]`)

**Example:** `Card: 4532015112830366` → `Card: [REDACTED]`

---

### `pii_iban_v1` — IBAN Bank Account Number

**Pattern:** `\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b`

**Validation:** Mod-97 checksum (`iban_checksum_valid()`)

**Action:** Remove

**Example:** `IBAN: GB29NWBK60161331926819` → `IBAN: [REDACTED]`

---

### `pii_bank_account_v1` — Bank Account Number

**Pattern:** Account number patterns near banking context keywords

**Validation:** None (context-based)

**Action:** Remove

---

### `pii_passport_v1` — US Passport Number

**Pattern:** `\b[A-Z]\d{8}\b`

**Validation:** None

**Action:** Remove

---

### `pii_driver_license_v1` — US Driver License

**Pattern:** State-specific patterns (50 state formats)

**Validation:** None

**Action:** Mask (replaced with `[US_DRIVER_LICENSE]`)

---

### `pii_email_v1` — Email Address

**Pattern:** `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`

**Validation:** None

**Action:** Mask (replaced with `[EMAIL_ADDRESS]`)

**Example:** `Contact alice@example.com` → `Contact [EMAIL_ADDRESS]`

---

### `pii_phone_v1` — US Phone Number

**Pattern:** US phone including +1, dashes, parentheses, dots

**Validation:** None

**Action:** Mask (replaced with `[PHONE_NUMBER]`)

---

### `pii_ip_address_v1` — IP Address (v4 and v6)

**IPv4 pattern:** `\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b`

**IPv6 pattern:** Full IPv6 including compressed forms

**Validation:** None

**Action:** Mask (replaced with `[IP_ADDRESS_V4]` or `[IP_ADDRESS_V6]`)

---

### `pii_mrn_v1` — Medical Record Number

**Pattern:** `(?i)\b(?:mrn|medical\s+record)\s*[:#]?\s*([A-Z0-9\-]{5,20})\b`

**Validation:** None

**Action:** Remove

---

### `pii_dob_v1` — Date of Birth

**Pattern:** Date formats in proximity to `dob`, `born`, `birthday`, `date of birth` context

**Validation:** None

**Action:** Mask (replaced with `[DATE_OF_BIRTH]`)

## Redaction Strategies

| Strategy | Output | Used by |
|---|---|---|
| Remove | `[REDACTED]` | SSN, credit card, IBAN, bank account, passport, MRN |
| Mask | `[ENTITY_TYPE]` | Email, phone, IP, driver license, DOB |

## Disabling a PII Rule

PII rules are Profile tier (2) and can be disabled via a policy bundle:

```yaml
rules:
  - rule_id: pii_email_v1
    enabled: false
```

This takes effect immediately when the bundle is activated. Use with caution —
consider shadow mode first to verify the impact before disabling.
